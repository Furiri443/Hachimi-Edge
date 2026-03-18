//! iOS function-hooking backend.
//!
//! Priority order at runtime:
//! 1. **Ellekit / Cydia Substrate** — `MSHookFunction` found via `dlsym(RTLD_DEFAULT)`.
//!    Both frameworks export this symbol; Ellekit also accepts it.
//! 2. **Dobby** — statically linked fallback for non-jailbroken injection.
//!
//! **This file only compiles on `target_os = "ios"`.**

use crate::core::{interceptor::HookHandle, Error};
use once_cell::sync::OnceCell;
use std::os::raw::c_void;

// ── Hook backend ─────────────────────────────────────────────────────────────

/// Signature of Cydia Substrate / Ellekit: `MSHookFunction(symbol, hook, &orig)`.
type MsHookFn = unsafe extern "C" fn(*mut c_void, *mut c_void, *mut *mut c_void);

enum HookBackend {
    /// Substrate / Ellekit via `MSHookFunction`.
    Substrate { hook_fn: MsHookFn },
    /// No hook backend available (non-jailbroken).
    /// Dobby is NOT used because it corrupts __TEXT pages and triggers
    /// CODESIGNING: Invalid Page kills on non-jailbroken iOS.
    None,
}

static BACKEND: OnceCell<HookBackend> = OnceCell::new();

fn backend() -> &'static HookBackend {
    BACKEND.get_or_init(|| {
        // Try to find MSHookFunction in the already-loaded address space.
        const RTLD_DEFAULT: *mut c_void = std::ptr::null_mut::<c_void>().wrapping_sub(2)
            as *mut c_void; // -2 on Darwin
        const HOOK_SYM: &[u8] = b"MSHookFunction\0";

        unsafe {
            // 1. Check if already loaded (e.g. Ellekit / Substrate injected early)
            let sym = libc::dlsym(RTLD_DEFAULT, HOOK_SYM.as_ptr() as *const _);
            if !sym.is_null() {
                info!("iOS: using Substrate/Ellekit (MSHookFunction from RTLD_DEFAULT)");
                return HookBackend::Substrate {
                    hook_fn: std::mem::transmute(sym),
                };
            }

            // 2. Try explicit library paths
            const PATHS: &[&[u8]] = &[
                b"/var/jb/usr/lib/libellekit.dylib\0",   // rootless Ellekit
                b"/usr/lib/libsubstrate.dylib\0",         // rootful Substrate
                b"/usr/lib/libhooker.dylib\0",            // Libhooker alt
            ];
            for &path in PATHS {
                let handle = libc::dlopen(path.as_ptr() as *const _, libc::RTLD_LAZY | libc::RTLD_GLOBAL);
                if handle.is_null() { continue; }
                let sym = libc::dlsym(handle, HOOK_SYM.as_ptr() as *const _);
                if !sym.is_null() {
                    info!("iOS: using Substrate/Ellekit from {}", std::str::from_utf8(path).unwrap_or("?"));
                    return HookBackend::Substrate {
                        hook_fn: std::mem::transmute(sym),
                    };
                }
                libc::dlclose(handle);
            }

            // 3. No hook backend — Dobby is NOT safe on iOS (corrupts code pages)
            warn!("iOS: no hook backend (MSHookFunction not found, Dobby skipped to avoid CODESIGNING kill)");
            HookBackend::None
        }
    })
}

// ── Public hooking API ────────────────────────────────────────────────────────

/// Hook a function at `orig_addr`, redirecting it to `hook_addr`.
/// Returns the trampoline address (original bytes + branch back).
///
/// # Safety
/// `orig_addr` and `hook_addr` must be valid function pointers.
pub unsafe fn hook(orig_addr: usize, hook_addr: usize) -> Result<usize, Error> {
    match backend() {
        HookBackend::Substrate { hook_fn } => {
            let mut trampoline: *mut c_void = std::ptr::null_mut();
            hook_fn(orig_addr as *mut c_void, hook_addr as *mut c_void, &mut trampoline);
            if trampoline.is_null() {
                Err(Error::HookingError("MSHookFunction returned null trampoline".into()))
            } else {
                Ok(trampoline as usize)
            }
        }
        HookBackend::None => {
            Err(Error::HookingError(
                "No hook backend available (non-jailbroken, Dobby skipped)".into()
            ))
        }
    }
}

/// Unhook a previously installed hook.
pub unsafe fn unhook(hook: &HookHandle) -> Result<(), Error> {
    match backend() {
        HookBackend::Substrate { .. } => {
            // Substrate / Ellekit don't provide an unhook API.
            Ok(())
        }
        HookBackend::None => Ok(()),
    }
}

/// Resolve a symbol by name from a loaded dylib/framework.
pub unsafe fn find_symbol_by_name(module: &str, symbol: &str) -> Result<usize, Error> {
    // Use dlopen + dlsym directly (works for exported symbols)
    let mod_cs = std::ffi::CString::new(module).map_err(|_| Error::SymbolNotFound(module.to_owned(), symbol.to_owned()))?;
    let sym_cs = std::ffi::CString::new(symbol).map_err(|_| Error::SymbolNotFound(module.to_owned(), symbol.to_owned()))?;
    let handle = libc::dlopen(mod_cs.as_ptr(), libc::RTLD_LAZY | libc::RTLD_NOLOAD);
    if !handle.is_null() {
        let addr = libc::dlsym(handle, sym_cs.as_ptr());
        libc::dlclose(handle);
        if !addr.is_null() {
            return Ok(addr as usize);
        }
    }
    Err(Error::SymbolNotFound(module.to_owned(), symbol.to_owned()))
}

// Vtable hooking is not used on iOS.
pub unsafe fn get_vtable_from_instance(_instance_addr: usize) -> *mut usize {
    unimplemented!("vtable hooking not used on iOS")
}
pub unsafe fn hook_vtable(
    _vtable: *mut usize,
    _vtable_index: usize,
    _hook_addr: usize,
) -> Result<HookHandle, Error> {
    unimplemented!("vtable hooking not used on iOS")
}
pub unsafe fn unhook_vtable(_hook: &HookHandle) -> Result<(), Error> {
    unimplemented!("vtable hooking not used on iOS")
}
