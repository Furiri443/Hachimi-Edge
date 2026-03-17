use serde::{Deserialize, Serialize};
use crate::core::Hachimi;
use super::{il2cpp_resolver, il2cpp_missing, symbols_impl};

/// Returns true if the given filename is the IL2CPP library.
/// On iOS Unity games, it's bundled as UnityFramework or GameAssembly.
pub fn is_il2cpp_lib(filename: &str) -> bool {
    filename.contains("UnityFramework")
        || filename.contains("GameAssembly")
        || filename.ends_with("libil2cpp.dylib")
}

/// Called by `hook::on_image_added` when `UnityFramework` is detected.
///
/// `header_addr` is the `mach_header_64 *` (TEXT base, slide already applied).
/// `slide` is the ASLR slide reported by dyld.
pub fn on_il2cpp_loaded(header_addr: usize, slide: isize) {
    match il2cpp_resolver::resolve(header_addr, slide) {
        Err(e) => {
            error!("iOS: IL2CPP resolver failed: {}", e);
        }
        Ok(mut map) => {
            // Patch in re-implemented shims for functions absent from the binary.
            for (name, addr) in il2cpp_missing::missing_fn_table() {
                map.entry(name).or_insert(addr);
            }
            info!("iOS: IL2CPP resolver populated {} symbols", map.len());

            // Set the legacy HANDLE for any remaining dlsym() calls.
            crate::il2cpp::symbols::set_handle(header_addr);

            // Grab il2cpp_init address BEFORE storing the map, then hook it.
            // We can't call on_hooking_finished() here because il2cpp_init() hasn't
            // run yet (dyld fires this callback before the game's main() starts).
            let il2cpp_init_addr = map.get("il2cpp_init").copied().unwrap_or(0);

            symbols_impl::set_resolved(map);

            if il2cpp_init_addr != 0 {
                install_il2cpp_init_hook(il2cpp_init_addr);
            } else {
                error!("iOS: il2cpp_init not in resolver map, hooking will not fire");
            }
        }
    }
}

/// Trampoline to the original `il2cpp_init`.
static ORIG_IL2CPP_INIT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Our hook for `il2cpp_init(domain_name)`.
/// Called right after Unity finishes initialising the scripting runtime.
unsafe extern "C" fn hooked_il2cpp_init(domain_name: *const std::os::raw::c_char) -> i32 {
    let orig: extern "C" fn(*const std::os::raw::c_char) -> i32 =
        std::mem::transmute(ORIG_IL2CPP_INIT.load(std::sync::atomic::Ordering::Relaxed));
    let result = orig(domain_name);

    info!("iOS: il2cpp_init returned {}, triggering on_hooking_finished", result);
    crate::core::Hachimi::instance().on_hooking_finished();

    result
}

fn install_il2cpp_init_hook(addr: usize) {
    use crate::core::Interceptor;
    let hachimi = crate::core::Hachimi::instance();
    match hachimi.interceptor.hook(addr, hooked_il2cpp_init as usize) {
        Ok(trampoline) => {
            ORIG_IL2CPP_INIT.store(trampoline, std::sync::atomic::Ordering::Relaxed);
            info!("iOS: il2cpp_init hook installed at {:#x}", addr);
        }
        Err(e) => {
            error!("iOS: failed to hook il2cpp_init: {}", e);
        }
    }
}

/// Returns true if the given filename is the CRI Ware middleware library.
pub fn is_criware_lib(filename: &str) -> bool {
    filename.contains("cri_ware") || filename.ends_with("libcri_ware_unity.dylib")
}

/// Called by the core after all hooks are installed.
pub fn on_hooking_finished(_hachimi: &Hachimi) {
    info!("iOS hooking finished");
}

/// iOS-specific configuration fields (none initially; expand as needed).
#[derive(Deserialize, Serialize, Clone, Default)]
pub struct Config {
    /// Position X of the floating action button (persisted across sessions)
    #[serde(default = "Config::default_fab_x")]
    pub fab_x: f32,
    /// Position Y of the floating action button
    #[serde(default = "Config::default_fab_y")]
    pub fab_y: f32,
}

impl Config {
    fn default_fab_x() -> f32 { 16.0 }
    fn default_fab_y() -> f32 { 100.0 }
}
