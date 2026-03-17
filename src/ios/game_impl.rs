use std::path::PathBuf;

use crate::core::game::Region;

pub fn get_package_name() -> String {
    // Dynamically read bundle ID from NSBundle (works with resigned IPAs)
    unsafe {
        let cls = objc::runtime::Class::get("NSBundle").unwrap();
        let bundle: *mut objc::runtime::Object = objc::msg_send![cls, mainBundle];
        let bundle_id: *mut objc::runtime::Object = objc::msg_send![bundle, bundleIdentifier];

        if bundle_id.is_null() {
            return "unknown".to_string();
        }

        let utf8_str: *const std::os::raw::c_char = objc::msg_send![bundle_id, UTF8String];
        let bytes = std::ffi::CStr::from_ptr(utf8_str).to_bytes();
        String::from_utf8_lossy(bytes).into_owned()
    }
}

pub fn get_region(package_name: &str) -> Region {
    match package_name {
        "jp.co.cygames.umamusume" => Region::Japan,
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

/// Returns the app's Documents directory, which is sandbox-accessible and user-visible.
/// Path: <AppSandbox>/Documents/hachimi/
fn get_game_documents_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/var/mobile".to_string());
    PathBuf::from(home).join("Documents").join("hachimi")
}
