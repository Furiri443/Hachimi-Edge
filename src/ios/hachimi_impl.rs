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
            symbols_impl::set_resolved(map);
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
