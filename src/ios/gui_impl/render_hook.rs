use std::os::raw::c_void;
use std::sync::{
    OnceLock,
    atomic::{AtomicPtr, AtomicBool, AtomicU64, Ordering},
};
use std::ptr;
use objc2::{msg_send, sel, Encode, Encoding};
use objc2::runtime::{AnyClass, AnyObject, Sel};
use objc2::ffi::{class_getInstanceMethod, method_setImplementation, object_getClass, IMP};

static ORIG_NEXT_DRAWABLE: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(ptr::null_mut());
static ORIG_PRESENT: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(ptr::null_mut());
static DRAWABLE_SWIZZLED: AtomicBool = AtomicBool::new(false);
static PAINTED_FRAME_AT_MS: AtomicU64 = AtomicU64::new(0);
static PRESENT_ORDER: OnceLock<PresentOrder> = OnceLock::new();

static EGUI_COMMAND_QUEUE: AtomicPtr<AnyObject> = AtomicPtr::new(ptr::null_mut());

#[derive(Copy, Clone, Eq, PartialEq)]
enum PresentOrder {
    GuiBeforePresent,
    GuiAfterPresent,
}

fn monotonic_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn ios_major_version() -> i32 {
    unsafe {
        let mut os_version = [0u8; 32];
        let mut size = std::mem::size_of_val(&os_version);
        if libc::sysctlbyname(
            b"kern.osproductversion\0".as_ptr() as *const _,
            os_version.as_mut_ptr() as *mut _,
            &mut size,
            std::ptr::null_mut(),
            0,
        ) != 0 {
            return 0;
        }

        let version = std::ffi::CStr::from_ptr(os_version.as_ptr() as *const _).to_string_lossy();
        version
            .split('.')
            .next()
            .and_then(|major| major.parse().ok())
            .unwrap_or(0)
    }
}

fn present_order() -> PresentOrder {
    *PRESENT_ORDER.get_or_init(|| {
        // iOS 15-25 can reorder the isolated GUI command buffer behind the game's
        // command buffer, making egui interactive but visually overwritten. Drawing
        // after the original present is the compatibility fallback for those builds.
        let major = ios_major_version();
        if major > 0 && major < 26 {
            PresentOrder::GuiAfterPresent
        } else {
            PresentOrder::GuiBeforePresent
        }
    })
}

pub fn is_render_ready_for_input() -> bool {
    if !DRAWABLE_SWIZZLED.load(Ordering::Acquire) {
        return false;
    }

    let painted_at = PAINTED_FRAME_AT_MS.load(Ordering::Acquire);
    painted_at != 0 && monotonic_ms().saturating_sub(painted_at) < 1_000
}

pub fn uses_legacy_compat_mode() -> bool {
    present_order() == PresentOrder::GuiAfterPresent
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct MTLClearColor {
    red: f64,
    green: f64,
    blue: f64,
    alpha: f64,
}

unsafe impl Encode for MTLClearColor {
    const ENCODING: Encoding = Encoding::Struct(
        "MTLClearColor",
        &[f64::ENCODING, f64::ENCODING, f64::ENCODING, f64::ENCODING],
    );
}

extern "C" fn hooked_next_drawable(self_layer: *mut AnyObject, sel: Sel) -> *mut AnyObject {
    unsafe {
        let mut queue = EGUI_COMMAND_QUEUE.load(Ordering::Acquire);
        if queue.is_null() {
            let device: *mut AnyObject = msg_send![self_layer, device];
            if !device.is_null() {
                queue = msg_send![device, newCommandQueue];
                EGUI_COMMAND_QUEUE.store(queue, Ordering::Release);
                info!("iOS: Created isolated Metal command queue for GUI");
            }
        }

        let orig_ptr = ORIG_NEXT_DRAWABLE.load(Ordering::Relaxed);
        let orig_fn: extern "C" fn(*mut AnyObject, Sel) -> *mut AnyObject = std::mem::transmute(orig_ptr);
        let drawable = orig_fn(self_layer, sel);

        if !drawable.is_null() && !DRAWABLE_SWIZZLED.load(Ordering::Relaxed) {
            let drawable_class = object_getClass(drawable as *mut _);
            let present_sel = sel!(present);
            let method = class_getInstanceMethod(drawable_class, present_sel.as_ptr() as *const _);

            if !method.is_null() {
                let hooked_imp: IMP = Some(std::mem::transmute(hooked_present as extern "C" fn(*mut AnyObject, Sel)));
                let orig_present = method_setImplementation(method, hooked_imp);
                if let Some(orig) = orig_present {
                    ORIG_PRESENT.store(orig as *mut _, Ordering::Relaxed);
                }
                info!("iOS: CAMetalDrawable 'present' swizzled on the fly!");
                DRAWABLE_SWIZZLED.store(true, Ordering::Relaxed);
            }
        }

        drawable
    }
}

extern "C" fn hooked_present(self_drawable: *mut AnyObject, sel: Sel) {
    unsafe {
        let render_after_present = present_order() == PresentOrder::GuiAfterPresent;

        if render_after_present {
            call_original_present(self_drawable, sel);
        }

        let queue = EGUI_COMMAND_QUEUE.load(Ordering::Acquire);
        if !queue.is_null() {
            let texture: *mut AnyObject = msg_send![self_drawable, texture];

            if !texture.is_null() {
                let device: *mut AnyObject = msg_send![texture, device];

                let gui_lock = crate::core::gui::Gui::instance_or_init("ios.menu_open_key");

                if let Ok(mut gui) = gui_lock.lock() {
                    let width: usize = msg_send![texture, width];
                    let height: usize = msg_send![texture, height];
                    gui.set_screen_size(width as i32, height as i32);

                    let full_output = gui.run();

                    let pixels_per_point = gui.context.pixels_per_point();
                    let screen_size = gui.context.screen_rect().size();

                    let primitives = gui.context.tessellate(full_output.shapes, pixels_per_point);

                    if let Some(painter) = gui.get_or_init_painter(device) {
                        let pass_class = objc2::class!(MTLRenderPassDescriptor);
                        let pass: *mut AnyObject = msg_send![pass_class, renderPassDescriptor];

                        let color_attachments: *mut AnyObject = msg_send![pass, colorAttachments];
                        let attachment: *mut AnyObject = msg_send![color_attachments, objectAtIndexedSubscript: 0_usize];

                        let _: () = msg_send![attachment, setTexture: texture];
                        let _: () = msg_send![attachment, setLoadAction: 1_usize];
                        let _: () = msg_send![attachment, setStoreAction: 1_usize];

                        let cmd_buf: *mut AnyObject = msg_send![queue, commandBuffer];
                        let encoder: *mut AnyObject = msg_send![cmd_buf, renderCommandEncoderWithDescriptor: pass];

                        if !encoder.is_null() {
                            painter.paint(
                                device,
                                encoder,
                                screen_size,
                                pixels_per_point,
                                full_output.textures_delta,
                                primitives,
                            );
                            let _: () = msg_send![encoder, endEncoding];
                            PAINTED_FRAME_AT_MS.store(monotonic_ms(), Ordering::Release);
                        }

                        let _: () = msg_send![cmd_buf, commit];
                        if render_after_present {
                            let _: () = msg_send![cmd_buf, waitUntilScheduled];
                        }
                    }
                }
            }
        }

        if !render_after_present {
            call_original_present(self_drawable, sel);
        }
    }
}

unsafe fn call_original_present(self_drawable: *mut AnyObject, sel: Sel) {
    let orig_present_ptr = ORIG_PRESENT.load(Ordering::Relaxed);
    if !orig_present_ptr.is_null() {
        let orig_fn: extern "C" fn(*mut AnyObject, Sel) = std::mem::transmute(orig_present_ptr);
        orig_fn(self_drawable, sel);
    }
}

pub fn init() {
    unsafe {
        match present_order() {
            PresentOrder::GuiBeforePresent => info!("iOS: GUI render mode = before present"),
            PresentOrder::GuiAfterPresent => info!("iOS: GUI render mode = legacy after present"),
        }

        let layer_class = AnyClass::get("CAMetalLayer").expect("Failed to find CAMetalLayer");
        let next_drawable_sel = sel!(nextDrawable);

        let method = class_getInstanceMethod(
            layer_class as *const _ as *mut _,
            next_drawable_sel.as_ptr() as *const _
        );

        if !method.is_null() {
            let hooked_fn_ptr = hooked_next_drawable as extern "C" fn(*mut AnyObject, Sel) -> *mut AnyObject;
            let hooked_imp: IMP = Some(std::mem::transmute(hooked_fn_ptr));
            let orig = method_setImplementation(method, hooked_imp);
            if let Some(orig_imp) = orig {
                ORIG_NEXT_DRAWABLE.store(orig_imp as *mut _, Ordering::Relaxed);
            }
            info!("iOS: CAMetalLayer nextDrawable swizzled");
        } else {
            error!("iOS: Failed to hook nextDrawable");
        }
    }
}
