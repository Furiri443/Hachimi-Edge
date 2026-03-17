use std::sync::atomic;

use crate::{core::Hachimi, il2cpp::{api::il2cpp_resolve_icall, symbols::get_method_addr, types::*}};

type SetTargetFrameRateFn = extern "C" fn(value: i32);
pub extern "C" fn set_targetFrameRate(mut value: i32) {
    let target_fps = Hachimi::instance().target_fps.load(atomic::Ordering::Relaxed);
    if target_fps != -1 {
        value = target_fps;
    }
    get_orig_fn!(set_targetFrameRate, SetTargetFrameRateFn)(value);
}

static mut GET_PERSISTENTDATAPATH_ADDR: usize = 0;
impl_addr_wrapper_fn!(get_persistentDataPath, GET_PERSISTENTDATAPATH_ADDR, *mut Il2CppString,);

static mut OPENURL_ADDR: usize = 0;
impl_addr_wrapper_fn!(OpenURL, OPENURL_ADDR, (), url: *mut Il2CppString);

pub fn init(UnityEngine_CoreModule: *const Il2CppImage) {
    get_class_or_return!(UnityEngine_CoreModule, UnityEngine, Application);

    let mut set_targetFrameRate_addr = il2cpp_resolve_icall(
        c"UnityEngine.Application::set_targetFrameRate(System.Int32)".as_ptr()
    ) as usize;

    // On iOS il2cpp_resolve_icall is not implemented; fall back to method lookup.
    #[cfg(target_os = "ios")]
    if set_targetFrameRate_addr == 0 {
        set_targetFrameRate_addr = get_method_addr(Application, c"set_targetFrameRate", 1);
        info!("Application::set_targetFrameRate (iOS method lookup): {:#x}", set_targetFrameRate_addr);
    }

    new_hook!(set_targetFrameRate_addr, set_targetFrameRate);

    unsafe {
        GET_PERSISTENTDATAPATH_ADDR = get_method_addr(Application, c"get_persistentDataPath", 0);
        OPENURL_ADDR = get_method_addr(Application, c"OpenURL", 1);
    }
}
