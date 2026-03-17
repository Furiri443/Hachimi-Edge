use std::path::PathBuf;

use crate::core::game::Region;

// Raw ObjC FFI — avoid dependency on objc/objc2 crate API differences
extern "C" {
    fn objc_getClass(name: *const u8) -> *mut std::ffi::c_void;
    fn sel_registerName(name: *const u8) -> *mut std::ffi::c_void;
    fn objc_msgSend(receiver: *mut std::ffi::c_void, sel: *mut std::ffi::c_void, ...) -> *mut std::ffi::c_void;
}

pub fn get_package_name() -> String {
    unsafe {
        let cls = objc_getClass(b"NSBundle\0".as_ptr());
        let sel_main = sel_registerName(b"mainBundle\0".as_ptr());
        let bundle = objc_msgSend(cls, sel_main);

        if bundle.is_null() {
            return "unknown".to_string();
        }

        let sel_id = sel_registerName(b"bundleIdentifier\0".as_ptr());
        let bundle_id = objc_msgSend(bundle, sel_id);

        if bundle_id.is_null() {
            return "unknown".to_string();
        }

        let sel_utf8 = sel_registerName(b"UTF8String\0".as_ptr());
        let utf8_ptr = objc_msgSend(bundle_id, sel_utf8) as *const std::os::raw::c_char;

        if utf8_ptr.is_null() {
            return "unknown".to_string();
        }

        std::ffi::CStr::from_ptr(utf8_ptr)
            .to_string_lossy()
            .into_owned()
    }
}

pub fn get_region(package_name: &str) -> Region {
    match package_name {
        "jp.co.cygames.umamusume" | "app.papaya2933.cheetah1054" => Region::Japan,
        "com.komoe.kmumamusumegp" | "com.komoe.umamusumeofficial" => Region::Taiwan,
        "com.kakaogames.umamusume" => Region::Korea,
        "com.bilibili.umamusu" => Region::China,
        "com.cygames.umamusume" => Region::Global,
        _ => Region::Unknown,
    }
}

pub fn get_data_dir(_package_name: &str) -> PathBuf {
    get_game_documents_dir()
}

/// Returns the app's Documents directory: <AppSandbox>/Documents/hachimi/
fn get_game_documents_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/var/mobile".to_string());
    PathBuf::from(home).join("Documents").join("hachimi")
}
