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
use std::sync::Mutex;

// ── Resolved address table ────────────────────────────────────────────────────

static RESOLVED: OnceCell<FnvHashMap<&'static str, usize>> = OnceCell::new();

/// Late-patch table for symbols discovered after `set_resolved` (e.g. via scanner).
/// Key is a `&'static str`; value injected into every `dlsym` call via `PATCHES`.
static PATCHES: Mutex<Vec<(&'static str, usize)>> = Mutex::new(Vec::new());

/// Store the resolved function address table.
/// Called once from `hachimi_impl::on_il2cpp_loaded`.
pub fn set_resolved(map: FnvHashMap<&'static str, usize>) {
    if RESOLVED.set(map).is_err() {
        warn!("iOS: symbols_impl::set_resolved called more than once — ignoring");
    }
}

/// Inject/overwrite a single symbol discovered after initial resolution
/// (e.g. `il2cpp_resolve_icall` found by the BL scanner).
pub fn update_resolved(name: &'static str, addr: usize) {
    if let Ok(mut p) = PATCHES.lock() {
        // Replace existing entry if present
        if let Some(e) = p.iter_mut().find(|(k, _)| *k == name) {
            e.1 = addr;
        } else {
            p.push((name, addr));
        }
    }
    info!("iOS: symbols_impl::update_resolved {} = {:#x}", name, addr);
}

/// Look up a function by its IL2CPP API name.
/// Returns `0` if the table hasn't been populated or the name is unknown.
///
/// # Safety
/// The returned address is only valid while `UnityFramework` remains loaded.
pub unsafe fn dlsym(_handle: *mut std::os::raw::c_void, name: &str) -> usize {
    // Check late-patch table first (higher priority — scanner may override stub)
    if let Ok(patches) = PATCHES.lock() {
        if let Some(&(_, addr)) = patches.iter().find(|(k, _)| *k == name) {
            if addr != 0 { return addr; }
        }
    }
    RESOLVED
        .get()
        .and_then(|m| m.get(name).copied())
        .unwrap_or_else(|| {
            warn!("iOS: symbol not resolved: {}", name);
            0
        })
}

