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

use objc::runtime::{Class, Object, Sel};
use objc::{msg_send, sel, sel_impl};

#[cfg(target_os = "ios")]
#[link(name = "c++")]
extern "C" {}

// ── ObjC Helpers (ported from Edge-2) ────────────────────────────────────────

/// Show a native iOS alert dialog on the main thread.
pub(crate) unsafe fn show_alert(title: &str, message: &str) {
    let superclass = Class::get("NSObject").unwrap();
    if Class::get("HachimiAlertHelper").is_none() {
        let mut decl = objc::declare::ClassDecl::new("HachimiAlertHelper", superclass).unwrap();
        decl.add_method(
            sel!(showAlert:),
            show_alert_impl as extern "C" fn(&Object, Sel, *mut Object),
        );
        decl.register();
    }

    let cls = Class::get("HachimiAlertHelper").unwrap();
    let helper: *mut Object = msg_send![cls, new];

    let code = format!("{}|||{}", title, message);
    let str_cls = Class::get("NSString").unwrap();
    let arg: *mut Object =
        msg_send![str_cls, stringWithUTF8String: std::ffi::CString::new(code).unwrap().as_ptr()];

    let _: () = msg_send![helper, performSelectorOnMainThread:sel!(showAlert:) withObject:arg waitUntilDone:false];
}

extern "C" fn show_alert_impl(_this: &Object, _cmd: Sel, arg: *mut Object) {
    unsafe {
        let arg_str: *const std::os::raw::c_char = msg_send![arg, UTF8String];
        let rust_str = std::ffi::CStr::from_ptr(arg_str).to_string_lossy();

        let parts: Vec<&str> = rust_str.split("|||").collect();
        let (t, m) = if parts.len() == 2 {
            (parts[0], parts[1])
        } else {
            ("Hachimi", rust_str.as_ref())
        };

        let title_cls = Class::get("NSString").unwrap();
        let t_obj: *mut Object =
            msg_send![title_cls, stringWithUTF8String: std::ffi::CString::new(t).unwrap().as_ptr()];
        let m_obj: *mut Object =
            msg_send![title_cls, stringWithUTF8String: std::ffi::CString::new(m).unwrap().as_ptr()];

        let alert_cls = Class::get("UIAlertController").unwrap();
        let alert: *mut Object =
            msg_send![alert_cls, alertControllerWithTitle:t_obj message:m_obj preferredStyle:1i64];

        let action_cls = Class::get("UIAlertAction").unwrap();
        let ok_str: *mut Object =
            msg_send![title_cls, stringWithUTF8String: std::ffi::CString::new("OK").unwrap().as_ptr()];
        let action: *mut Object =
            msg_send![action_cls, actionWithTitle:ok_str style:0i64 handler:std::ptr::null_mut::<c_void>()];

        let _: () = msg_send![alert, addAction:action];

        let app_cls = Class::get("UIApplication").unwrap();
        let shared_app: *mut Object = msg_send![app_cls, sharedApplication];
        let key_window: *mut Object = msg_send![shared_app, keyWindow];

        if !key_window.is_null() {
            let root_vc: *mut Object = msg_send![key_window, rootViewController];
            if !root_vc.is_null() {
                let _: () = msg_send![root_vc, presentViewController:alert animated:true completion:std::ptr::null_mut::<c_void>()];
            }
        }
    }
}

/// Unlock FPS to target value on main thread via ObjC performSelector.
pub(crate) unsafe fn unlock_fps_on_main_thread(target_fps: i32) {
    let superclass = Class::get("NSObject").unwrap();
    if Class::get("HachimiFpsHelper").is_none() {
        let mut decl = objc::declare::ClassDecl::new("HachimiFpsHelper", superclass).unwrap();
        decl.add_method(
            sel!(unlockFps),
            unlock_fps_impl as extern "C" fn(&Object, Sel),
        );
        decl.register();
    }

    // Store target FPS for the ObjC callback
    TARGET_FPS.store(target_fps, std::sync::atomic::Ordering::Relaxed);

    let cls = Class::get("HachimiFpsHelper").unwrap();
    let helper: *mut Object = msg_send![cls, new];
    let _: () = msg_send![helper, performSelectorOnMainThread:sel!(unlockFps) withObject:std::ptr::null_mut::<Object>() waitUntilDone:false];
}

static TARGET_FPS: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(240);

extern "C" fn unlock_fps_impl(_this: &Object, _cmd: Sel) {
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
                .store(fps as u64, std::sync::atomic::Ordering::Relaxed);
            log::info!("FPS set to {} on main thread ✅", fps);
        } else {
            log::error!("Failed to resolve set_targetFrameRate icall");
        }
    }
}
