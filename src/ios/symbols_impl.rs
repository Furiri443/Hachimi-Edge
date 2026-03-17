//! iOS symbol resolution — replaces the `dlsym` approach.
//!
//! On iOS the IL2CPP API functions are statically linked into `UnityFramework`
//! and cannot be found via `dlsym`.  When Hachimi detects the framework, it
//! calls `il2cpp_resolver::resolve()` to build an address table, then stores
//! it here for use by `il2cpp::api`.
//!
//! **This file only compiles on `target_os = "ios"`.**

use fnv::FnvHashMap;
use once_cell::sync::OnceCell;

// ── Resolved address table ────────────────────────────────────────────────────

static RESOLVED: OnceCell<FnvHashMap<&'static str, usize>> = OnceCell::new();

/// Store the resolved function address table.
/// Called once from `hachimi_impl::on_il2cpp_loaded`.
pub fn set_resolved(map: FnvHashMap<&'static str, usize>) {
    if RESOLVED.set(map).is_err() {
        warn!("iOS: symbols_impl::set_resolved called more than once — ignoring");
    }
}

/// Look up a function by its IL2CPP API name.
/// Returns `0` if the table hasn't been populated or the name is unknown.
///
/// # Safety
/// The returned address is only valid while `UnityFramework` remains loaded.
pub unsafe fn dlsym(_handle: *mut std::os::raw::c_void, name: &str) -> usize {
    RESOLVED
        .get()
        .and_then(|m| m.get(name).copied())
        .unwrap_or_else(|| {
            warn!("iOS: symbol not resolved: {}", name);
            0
        })
}
