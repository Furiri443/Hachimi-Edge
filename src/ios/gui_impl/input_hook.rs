use std::os::raw::c_void;
use std::sync::atomic::{AtomicU64, Ordering};
use objc2::{msg_send, sel, Encode, Encoding};
use objc2::runtime::{AnyClass, AnyObject, Sel};
use objc2::ffi::{class_getInstanceMethod, method_setImplementation, IMP};
use crate::core::gui::INSTANCE;

static mut ORIG_SEND_EVENT: Option<IMP> = None;
static mut ORIG_PRESSES_BEGAN: Option<IMP> = None;
static LAST_MENU_TOGGLE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SCROLL_HOOKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static SEND_EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static PRESSES_EVENT_COUNT: AtomicU64 = AtomicU64::new(0);
static LAST_INPUT_LOG_AT_MS: AtomicU64 = AtomicU64::new(0);

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn should_log_input(now_ms: u64, event_count: u64) -> bool {
    if event_count <= 12 {
        return true;
    }

    let last = LAST_INPUT_LOG_AT_MS.load(Ordering::Relaxed);
    if now_ms.saturating_sub(last) < 1_500 {
        return false;
    }

    LAST_INPUT_LOG_AT_MS
        .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
        .is_ok()
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct CGPoint {
    x: f64,
    y: f64,
}

unsafe impl Encode for CGPoint {
    const ENCODING: Encoding = Encoding::Struct(
        "CGPoint",
        &[f64::ENCODING, f64::ENCODING],
    );
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct CGSize {
    width: f64,
    height: f64,
}

unsafe impl Encode for CGSize {
    const ENCODING: Encoding = Encoding::Struct(
        "CGSize",
        &[f64::ENCODING, f64::ENCODING],
    );
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct CGRect {
    origin: CGPoint,
    size: CGSize,
}

unsafe impl Encode for CGRect {
    const ENCODING: Encoding = Encoding::Struct(
        "CGRect",
        &[CGPoint::ENCODING, CGSize::ENCODING],
    );
}

extern "C" fn handle_scroll(_target: *mut AnyObject, _sel: Sel, recognizer: *mut AnyObject) {
    unsafe {
        let state: isize = msg_send![recognizer, state];

        if state == 1 || state == 2 || state == 3 {
            let view: *mut AnyObject = msg_send![recognizer, view];

            let location: CGPoint = msg_send![recognizer, locationInView: view];
            let bounds: CGRect = msg_send![view, bounds];

            let translation: CGPoint = msg_send![recognizer, translationInView: view];
            let zero = CGPoint { x: 0.0, y: 0.0 };
            let _: () = msg_send![recognizer, setTranslation: zero, inView: view];

            if bounds.size.width > 0.0 && bounds.size.height > 0.0 {
                if let Some(gui_mutex) = crate::core::gui::INSTANCE.get() {
                    if let Ok(mut gui) = gui_mutex.lock() {
                        let screen_rect = gui.context.screen_rect();

                        let pos = egui::pos2(
                            (location.x / bounds.size.width) as f32 * screen_rect.width(),
                            (location.y / bounds.size.height) as f32 * screen_rect.height()
                        );

                        if translation.x != 0.0 || translation.y != 0.0 {
                            let delta = egui::Vec2::new(translation.x as f32, translation.y as f32) * 1.5;
                            debug!(
                                "iOS GUI input: scroll state={} pos=({:.1},{:.1}) delta=({:.1},{:.1})",
                                state,
                                pos.x,
                                pos.y,
                                delta.x,
                                delta.y
                            );

                            gui.input.events.push(egui::Event::PointerMoved(pos));
                            gui.input.events.push(egui::Event::MouseWheel {
                                unit: egui::MouseWheelUnit::Point,
                                delta,
                                modifiers: egui::Modifiers::default(),
                            });
                        }
                    }
                }
            }
        }
    }
}

extern "C" fn should_recognize_simultaneously(
    _target: *mut AnyObject,
    _sel: Sel,
    _gesture: *mut AnyObject,
    _other_gesture: *mut AnyObject
) -> bool {
    true
}

extern "C" fn hooked_send_event(self_obj: *mut AnyObject, sel: Sel, event: *mut AnyObject) {
    unsafe {
        let event_count = SEND_EVENT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        let log_now = now_ms();
        let log_this_event = should_log_input(log_now, event_count);
        let render_ready = crate::ios::gui_impl::render_hook::is_render_ready_for_input();
        let legacy_passthrough = crate::ios::gui_impl::render_hook::uses_legacy_compat_mode();

        let is_window: bool = if let Some(ui_window_cls) = AnyClass::get("UIWindow") {
            msg_send![self_obj, isKindOfClass: ui_window_cls]
        } else {
            false
        };

        if !is_window {
            if log_this_event {
                debug!(
                    "iOS GUI input: sendEvent#{} non-window receiver={:p}, forwarding",
                    event_count,
                    self_obj
                );
            }
            if let Some(orig_imp) = ORIG_SEND_EVENT {
                let orig_fn: extern "C" fn(*mut AnyObject, Sel, *mut AnyObject) = std::mem::transmute(orig_imp);
                orig_fn(self_obj, sel, event);
            }
            return;
        }

        if !SCROLL_HOOKED.load(Ordering::Relaxed) {
            SCROLL_HOOKED.store(true, Ordering::Relaxed);
            if let Some(target_cls) = AnyClass::get("HachimiScrollTarget") {
                let target: *mut AnyObject = msg_send![target_cls, alloc];
                let target: *mut AnyObject = msg_send![target, init];

                if let Some(pan_cls) = AnyClass::get("UIPanGestureRecognizer") {
                    let pan: *mut AnyObject = msg_send![pan_cls, alloc];
                    let pan: *mut AnyObject = msg_send![pan, initWithTarget: target, action: sel!(handleScroll:)];

                    if let Some(ns_array_cls) = AnyClass::get("NSArray") {
                        let empty_array: *mut AnyObject = msg_send![ns_array_cls, array];
                        let _: () = msg_send![pan, setAllowedTouchTypes: empty_array];
                    }

                    let responds: bool = msg_send![pan, respondsToSelector: sel!(setAllowedScrollTypesMask:)];
                    if responds {
                        let _: () = msg_send![pan, setAllowedScrollTypesMask: 3_isize];
                    }

                    let _: () = msg_send![pan, setDelegate: target];
                    let _: () = msg_send![self_obj, addGestureRecognizer: pan];
                }
            }
        }

        let mut egui_wants_input = false;
        let mut has_native_ui_touch = false;
        let mut touch_count = 0usize;
        let mut main_view_touch_count = 0usize;
        let mut last_touch_phase = -1isize;
        let mut last_touch_pos = egui::pos2(0.0, 0.0);

        let event_type: isize = msg_send![event, type];

        if event_type == 0 {
            let all_touches: *mut AnyObject = msg_send![event, allTouches];
            let enumerator: *mut AnyObject = msg_send![all_touches, objectEnumerator];
            let mut touch: *mut AnyObject = msg_send![enumerator, nextObject];

            while !touch.is_null() {
                touch_count += 1;
                let phase: isize = msg_send![touch, phase];
                let tap_count: usize = msg_send![touch, tapCount];
                let view: *mut AnyObject = msg_send![touch, view];
                last_touch_phase = phase;

                if !view.is_null() {
                    let view_cls = object_getClass(view as *mut c_void);
                    let view_cls_name = std::ffi::CStr::from_ptr(class_getName(view_cls)).to_string_lossy();

                    let is_main_view = view_cls_name.contains("UnityView") || view_cls_name.contains("MTKView");

                    if !is_main_view {
                        has_native_ui_touch = true;
                    } else {
                        main_view_touch_count += 1;
                        let location: CGPoint = msg_send![touch, locationInView: view];
                        let bounds: CGRect = msg_send![view, bounds];

                        if bounds.size.width > 0.0 && bounds.size.height > 0.0 {
                            if let Some(gui_mutex) = crate::core::gui::INSTANCE.get() {
                                if let Ok(mut gui) = gui_mutex.lock() {
                                    let screen_rect = gui.context.screen_rect();

                                    let pos = egui::pos2(
                                        (location.x / bounds.size.width) as f32 * screen_rect.width(),
                                        (location.y / bounds.size.height) as f32 * screen_rect.height()
                                    );
                                    last_touch_pos = pos;

                                    let mut events = vec![];

                                    let touch_phase = match phase {
                                        0 => Some(egui::TouchPhase::Start),
                                        1 => Some(egui::TouchPhase::Move),
                                        3 | 4 => Some(egui::TouchPhase::End),
                                        _ => None,
                                    };

                                    if let Some(t_phase) = touch_phase {
                                        events.push(egui::Event::Touch {
                                            device_id: egui::TouchDeviceId(0),
                                            id: egui::TouchId::from(touch as u64),
                                            phase: t_phase,
                                            pos,
                                            force: None,
                                        });
                                    }

                                    match phase {
                                        0 => {
                                            events.push(egui::Event::PointerMoved(pos));
                                            events.push(egui::Event::PointerButton {
                                                pos,
                                                button: egui::PointerButton::Primary,
                                                pressed: true,
                                                modifiers: Default::default(),
                                            });
                                        }
                                        1 | 2 => {
                                            events.push(egui::Event::PointerMoved(pos));
                                        }
                                        3 | 4 => {
                                            events.push(egui::Event::PointerMoved(pos));
                                            events.push(egui::Event::PointerButton {
                                                pos,
                                                button: egui::PointerButton::Primary,
                                                pressed: false,
                                                modifiers: Default::default(),
                                            });
                                            events.push(egui::Event::PointerGone);
                                        }
                                        _ => {}
                                    }

                                    gui.inject_events(events);

                                    let corner_zone_size = screen_rect.width().min(screen_rect.height()) * 0.12;

                                    if phase == 0 && tap_count == 3 {
                                        let config = crate::core::Hachimi::instance().config.load();

                                        if !config.disable_gui && pos.x < corner_zone_size && pos.y < corner_zone_size {
                                            debug!(
                                                "iOS GUI input: triple-tap menu toggle pos=({:.1},{:.1})",
                                                pos.x,
                                                pos.y
                                            );
                                            gui.toggle_menu();
                                            egui_wants_input = true;
                                        }
                                        else if config.hide_ingame_ui_hotkey && pos.x > (screen_rect.width() - corner_zone_size) && pos.y < corner_zone_size {
                                            debug!(
                                                "iOS GUI input: triple-tap game UI toggle pos=({:.1},{:.1})",
                                                pos.x,
                                                pos.y
                                            );
                                            crate::il2cpp::symbols::Thread::main_thread().schedule(crate::core::Gui::toggle_game_ui);
                                            egui_wants_input = true;
                                        }
                                    }

                                    if render_ready && (
                                        gui.context.wants_pointer_input()
                                        || gui.context.is_pointer_over_area()
                                        || gui.is_consuming_input()
                                    ) {
                                        egui_wants_input = true;
                                    }
                                }
                            }
                        }
                    }
                }
                touch = msg_send![enumerator, nextObject];
            }
        }
        else if event_type == 1 {
            let event_subtype: isize = msg_send![event, subtype];

            if event_subtype == 1 {
                if let Some(gui_mutex) = crate::core::gui::INSTANCE.get() {
                    if let Ok(mut gui) = gui_mutex.lock() {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis() as u64;

                        let last = LAST_MENU_TOGGLE.load(std::sync::atomic::Ordering::Relaxed);

                        if now - last > 500 {
                            LAST_MENU_TOGGLE.store(now, std::sync::atomic::Ordering::Relaxed);
                            gui.toggle_menu();
                            egui_wants_input = true;
                            debug!("iOS GUI input: motion submenu event toggled menu");
                        }
                    }
                }
            }
        }

        let forward_to_app = has_native_ui_touch || !egui_wants_input || !render_ready || legacy_passthrough;
        if log_this_event {
            debug!(
                "iOS GUI input: sendEvent#{} type={} touches={} main_touches={} last_phase={} last_pos=({:.1},{:.1}) render_ready={} legacy_passthrough={} egui_wants={} native_touch={} forward={}",
                event_count,
                event_type,
                touch_count,
                main_view_touch_count,
                last_touch_phase,
                last_touch_pos.x,
                last_touch_pos.y,
                render_ready,
                legacy_passthrough,
                egui_wants_input,
                has_native_ui_touch,
                forward_to_app
            );
        }

        if forward_to_app {
            if let Some(orig_imp) = ORIG_SEND_EVENT {
                let orig_fn: extern "C" fn(*mut AnyObject, Sel, *mut AnyObject) = std::mem::transmute(orig_imp);
                orig_fn(self_obj, sel, event);
            }
        } else if log_this_event {
            debug!("iOS GUI input: sendEvent#{} consumed by egui", event_count);
        }
    }
}

extern "C" fn hooked_presses_began(self_obj: *mut AnyObject, sel: Sel, presses: *mut AnyObject, event: *mut AnyObject) {
    unsafe {
        let event_count = PRESSES_EVENT_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
        let log_now = now_ms();
        let log_this_event = should_log_input(log_now, event_count);
        let render_ready = crate::ios::gui_impl::render_hook::is_render_ready_for_input();
        let legacy_passthrough = crate::ios::gui_impl::render_hook::uses_legacy_compat_mode();
        let enumerator: *mut AnyObject = msg_send![presses, objectEnumerator];
        let mut press: *mut AnyObject = msg_send![enumerator, nextObject];

        let mut egui_wants_input = false;
        let mut press_count = 0usize;
        let mut last_key_code = -1isize;

        while !press.is_null() {
            press_count += 1;
            let phase: isize = msg_send![press, phase];
            let key: *mut AnyObject = msg_send![press, key];

            if phase == 0 && !key.is_null() {
                let chars_obj: *mut AnyObject = msg_send![key, characters];
                let is_empty_char = if chars_obj.is_null() {
                    true
                } else {
                    let length: usize = msg_send![chars_obj, length];
                    length == 0
                };

                if !is_empty_char {
                    let key_code: isize = msg_send![key, keyCode];
                    last_key_code = key_code;

                    if let Some(gui_mutex) = crate::core::gui::INSTANCE.get() {
                        if let Ok(mut gui) = gui_mutex.lock() {
                            let config = crate::core::Hachimi::instance().config.load();

                            if key_code as i32 == config.ios.menu_open_key {
                                debug!("iOS GUI input: hardware key toggled menu key_code={}", key_code);
                                gui.toggle_menu();
                                egui_wants_input = true;
                            }
                            else if config.hide_ingame_ui_hotkey && key_code as i32 == config.ios.hide_ingame_ui_hotkey_bind {
                                debug!("iOS GUI input: hardware key toggled game UI key_code={}", key_code);
                                crate::il2cpp::symbols::Thread::main_thread().schedule(crate::core::Gui::toggle_game_ui);
                                egui_wants_input = true;
                            }
                        }
                    }
                }
            }
            press = msg_send![enumerator, nextObject];
        }

        let forward_to_app = !egui_wants_input || !render_ready || legacy_passthrough;
        if log_this_event {
            debug!(
                "iOS GUI input: pressesBegan#{} presses={} last_key={} render_ready={} legacy_passthrough={} egui_wants={} forward={}",
                event_count,
                press_count,
                last_key_code,
                render_ready,
                legacy_passthrough,
                egui_wants_input,
                forward_to_app
            );
        }

        if forward_to_app {
            if let Some(orig_imp) = ORIG_PRESSES_BEGAN {
                let orig_fn: extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject) = std::mem::transmute(orig_imp);
                orig_fn(self_obj, sel, presses, event);
            }
        } else if log_this_event {
            debug!("iOS GUI input: pressesBegan#{} consumed by egui", event_count);
        }
    }
}

extern "C" {
    fn objc_getClass(name: *const u8) -> *mut c_void;
    fn objc_allocateClassPair(superclass: *mut c_void, name: *const u8, extra_bytes: usize) -> *mut c_void;
    fn class_addMethod(cls: *mut c_void, sel: *mut c_void, imp: *mut c_void, types: *const u8) -> bool;
    fn objc_registerClassPair(cls: *mut c_void);
    fn object_getClass(obj: *mut c_void) -> *mut c_void;
    fn class_getName(cls: *mut c_void) -> *const std::os::raw::c_char;
}

pub fn init() {
    unsafe {
        let superclass = objc_getClass(b"NSObject\0".as_ptr());
        let target_cls = objc_allocateClassPair(superclass, b"HachimiScrollTarget\0".as_ptr(), 0);
        if !target_cls.is_null() {
            let handle_scroll_sel = sel!(handleScroll:);
            let handle_scroll_imp: extern "C" fn(*mut AnyObject, Sel, *mut AnyObject) = handle_scroll;
            class_addMethod(
                target_cls,
                handle_scroll_sel.as_ptr() as *mut c_void,
                handle_scroll_imp as *mut c_void,
                b"v@:@\0".as_ptr()
            );

            let simultaneous_sel = sel!(gestureRecognizer:shouldRecognizeSimultaneouslyWithGestureRecognizer:);
            let simultaneous_imp: extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject) -> bool = should_recognize_simultaneously;
            class_addMethod(
                target_cls,
                simultaneous_sel.as_ptr() as *mut c_void,
                simultaneous_imp as *mut c_void,
                b"B@:@@\0".as_ptr()
            );

            objc_registerClassPair(target_cls);
        }

        let ui_window_cls = AnyClass::get("UIWindow").expect("Failed to find UIWindow");
        let send_event_sel = sel!(sendEvent:);

        let method = class_getInstanceMethod(
            ui_window_cls as *const _ as *mut _,
            send_event_sel.as_ptr() as *const _
        );

        if !method.is_null() {
            let hooked_fn_ptr = hooked_send_event as extern "C" fn(*mut AnyObject, Sel, *mut AnyObject);
            let hooked_imp: IMP = Some(std::mem::transmute(hooked_fn_ptr));

            let orig = method_setImplementation(method, hooked_imp);
            ORIG_SEND_EVENT = Some(orig);
            info!("iOS: UIWindow sendEvent: successfully swizzled with objc2 has_orig={}", orig.is_some());
        } else {
            error!("iOS: Failed to get sendEvent: method");
        }

        if let Some(unity_view_cls) = AnyClass::get("UnityView") {
            let presses_began_sel = sel!(pressesBegan:withEvent:);
            let method = class_getInstanceMethod(
                unity_view_cls as *const _ as *mut _,
                presses_began_sel.as_ptr() as *const _
            );

            if !method.is_null() {
                let hooked_fn_ptr = hooked_presses_began as extern "C" fn(*mut AnyObject, Sel, *mut AnyObject, *mut AnyObject);
                let hooked_imp: IMP = Some(std::mem::transmute(hooked_fn_ptr));

                let orig = method_setImplementation(method, hooked_imp);
                ORIG_PRESSES_BEGAN = Some(orig);
                info!("iOS: UnityView pressesBegan:withEvent: successfully swizzled has_orig={}", orig.is_some());
            } else {
                error!("iOS: Failed to get pressesBegan:withEvent: method from UnityView");
            }
        } else {
            error!("iOS: UnityView class not found");
        }
    }
}
