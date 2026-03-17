use std::os::raw::c_void;

pub mod game_impl;
pub mod gui_impl;
pub mod hachimi_impl;
pub mod hook;
pub mod interceptor_impl;
pub mod log_impl;
pub mod symbols_impl;
pub mod utils;
pub mod il2cpp_resolver;
pub mod il2cpp_missing;

mod main;

#[cfg(target_os = "ios")]
#[link(name = "c++")]
extern "C" {}

// ── Raw ObjC FFI ─────────────────────────────────────────────────────────────
extern "C" {
    fn objc_getClass(name: *const u8) -> *mut c_void;
    fn sel_registerName(name: *const u8) -> *mut c_void;
    fn objc_msgSend(receiver: *mut c_void, sel: *mut c_void, ...) -> *mut c_void;
    fn class_addMethod(cls: *mut c_void, sel: *mut c_void, imp: *mut c_void, types: *const u8) -> bool;
    fn objc_allocateClassPair(superclass: *mut c_void, name: *const u8, extra_bytes: usize) -> *mut c_void;
    fn objc_registerClassPair(cls: *mut c_void);
}

// ── ObjC Helpers ─────────────────────────────────────────────────────────────

/// Show a native UIAlertController on the main thread.
pub(crate) unsafe fn show_alert(title: &str, message: &str) {
    // Register a helper class if needed
    let helper_cls = get_or_create_class(b"HachimiAlertHelper\0", |cls| {
        let sel = sel_registerName(b"showAlert:\0".as_ptr());
        class_addMethod(cls, sel, show_alert_impl as *mut c_void, b"v@:@\0".as_ptr());
    });

    let helper = msg_send_0(helper_cls, b"new\0");

    // Encode title|||message into a single NSString
    let payload = format!("{}|||{}", title, message);
    let ns_payload = nsstring_from_str(&payload);

    let sel_show = sel_registerName(b"showAlert:\0".as_ptr());
    let sel_perform = sel_registerName(b"performSelectorOnMainThread:withObject:waitUntilDone:\0".as_ptr());
    objc_msgSend(helper, sel_perform, sel_show, ns_payload, false as i8);
}

extern "C" fn show_alert_impl(_this: *mut c_void, _cmd: *mut c_void, arg: *mut c_void) {
    unsafe {
        let rust_str = nsstring_to_string(arg);
        let parts: Vec<&str> = rust_str.split("|||").collect();
        let (t, m) = if parts.len() == 2 { (parts[0], parts[1]) } else { ("Hachimi", rust_str.as_ref()) };

        let ns_title = nsstring_from_str(t);
        let ns_msg = nsstring_from_str(m);

        // UIAlertController.alertControllerWithTitle:message:preferredStyle:
        let alert_cls = objc_getClass(b"UIAlertController\0".as_ptr());
        let sel_alert = sel_registerName(b"alertControllerWithTitle:message:preferredStyle:\0".as_ptr());
        let alert = objc_msgSend(alert_cls, sel_alert, ns_title, ns_msg, 1i64);

        // UIAlertAction.actionWithTitle:style:handler:
        let action_cls = objc_getClass(b"UIAlertAction\0".as_ptr());
        let sel_action = sel_registerName(b"actionWithTitle:style:handler:\0".as_ptr());
        let ns_ok = nsstring_from_str("OK");
        let action = objc_msgSend(action_cls, sel_action, ns_ok, 0i64, std::ptr::null_mut::<c_void>());

        let sel_add = sel_registerName(b"addAction:\0".as_ptr());
        objc_msgSend(alert, sel_add, action);

        // Present from keyWindow.rootViewController
        let app = msg_send_0(objc_getClass(b"UIApplication\0".as_ptr()), b"sharedApplication\0");
        let window = msg_send_0(app, b"keyWindow\0");
        if !window.is_null() {
            let root_vc = msg_send_0(window, b"rootViewController\0");
            if !root_vc.is_null() {
                let sel_present = sel_registerName(b"presentViewController:animated:completion:\0".as_ptr());
                objc_msgSend(root_vc, sel_present, alert, true as i8, std::ptr::null_mut::<c_void>());
            }
        }
    }
}

/// Unlock FPS on main thread via ObjC performSelector.
pub(crate) unsafe fn unlock_fps_on_main_thread(target_fps: i32) {
    TARGET_FPS.store(target_fps, std::sync::atomic::Ordering::Relaxed);

    let helper_cls = get_or_create_class(b"HachimiFpsHelper\0", |cls| {
        let sel = sel_registerName(b"unlockFps\0".as_ptr());
        class_addMethod(cls, sel, unlock_fps_impl as *mut c_void, b"v@:\0".as_ptr());
    });

    let helper = msg_send_0(helper_cls, b"new\0");
    let sel_unlock = sel_registerName(b"unlockFps\0".as_ptr());
    let sel_perform = sel_registerName(b"performSelectorOnMainThread:withObject:waitUntilDone:\0".as_ptr());
    objc_msgSend(helper, sel_perform, sel_unlock, std::ptr::null_mut::<c_void>(), false as i8);
}

static TARGET_FPS: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(240);

extern "C" fn unlock_fps_impl(_this: *mut c_void, _cmd: *mut c_void) {
    let fps = TARGET_FPS.load(std::sync::atomic::Ordering::Relaxed);
    unsafe {
        let func_addr = crate::il2cpp::api::il2cpp_resolve_icall(
            c"UnityEngine.Application::set_targetFrameRate(System.Int32)".as_ptr(),
        );
        if func_addr != 0 {
            let func: extern "C" fn(i32) = std::mem::transmute(func_addr);
            func(fps);
            crate::core::Hachimi::instance()
                .target_fps
                .store(fps, std::sync::atomic::Ordering::Relaxed);
            log::info!("FPS set to {} on main thread ✅", fps);
        } else {
            log::error!("Failed to resolve set_targetFrameRate icall");
        }
    }
}

// ── Utility functions ────────────────────────────────────────────────────────

/// Simple objc_msgSend wrapper for no-arg selectors.
unsafe fn msg_send_0(receiver: *mut c_void, sel_name: &[u8]) -> *mut c_void {
    let sel = sel_registerName(sel_name.as_ptr());
    objc_msgSend(receiver, sel)
}

/// Create an NSString from a Rust &str.
unsafe fn nsstring_from_str(s: &str) -> *mut c_void {
    let cls = objc_getClass(b"NSString\0".as_ptr());
    let sel = sel_registerName(b"stringWithUTF8String:\0".as_ptr());
    let cstr = std::ffi::CString::new(s).unwrap_or_default();
    objc_msgSend(cls, sel, cstr.as_ptr())
}

/// Read an NSString into a Rust String.
unsafe fn nsstring_to_string(ns: *mut c_void) -> String {
    let sel = sel_registerName(b"UTF8String\0".as_ptr());
    let ptr = objc_msgSend(ns, sel) as *const std::os::raw::c_char;
    if ptr.is_null() { return String::new(); }
    std::ffi::CStr::from_ptr(ptr).to_string_lossy().into_owned()
}

/// Get or create a helper ObjC class.  `setup` is called once to add methods.
unsafe fn get_or_create_class(name: &[u8], setup: impl FnOnce(*mut c_void)) -> *mut c_void {
    let cls = objc_getClass(name.as_ptr());
    if !cls.is_null() { return cls; }

    let nsobject = objc_getClass(b"NSObject\0".as_ptr());
    let new_cls = objc_allocateClassPair(nsobject, name.as_ptr(), 0);
    setup(new_cls);
    objc_registerClassPair(new_cls);
    new_cls
}
