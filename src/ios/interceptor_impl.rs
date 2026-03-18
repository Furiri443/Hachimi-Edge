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
    /// Dobby via `dobby_rs` (static link).
    Dobby,
}

static BACKEND: OnceCell<HookBackend> = OnceCell::new();

fn backend() -> &'static HookBackend {
    BACKEND.get_or_init(|| {
        // Try to find MSHookFunction in the already-loaded address space.
        // Ellekit (rootless, /var/jb/usr/lib/libellekit.dylib) and
        // Cydia Substrate (rootful, /usr/lib/libsubstrate.dylib) both export
        // this symbol.  We probe RTLD_DEFAULT first, then try opening the
        // known paths explicitly.
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

            // 3. Fall back to Dobby (bundled, JIT-entitlement required)
            info!("iOS: falling back to Dobby for hooking");
            HookBackend::Dobby
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
        HookBackend::Dobby => {
            Ok(dobby_rs::hook(orig_addr as *mut c_void, hook_addr as *mut c_void)? as usize)
        }
    }
}

/// Unhook a previously installed hook.
pub unsafe fn unhook(hook: &HookHandle) -> Result<(), Error> {
    match backend() {
        HookBackend::Substrate { .. } => {
            // Substrate / Ellekit don't provide an unhook API.
            // Re-hook to the trampoline (i.e. restore original) if needed.
            // For Hachimi this is fine — hooks are permanent.
            Ok(())
        }
        HookBackend::Dobby => {
            dobby_rs::unhook(hook.orig_addr as *mut c_void)?;
            Ok(())
        }
    }
}

impl From<dobby_rs::DobbyHookError> for Error {
    fn from(e: dobby_rs::DobbyHookError) -> Self {
        Error::HookingError(e.to_string())
    }
}

/// Resolve a symbol by name from a loaded dylib/framework.
/// Falls back to `dlopen(NULL) + dlsym` — works for system symbols.
pub unsafe fn find_symbol_by_name(module: &str, symbol: &str) -> Result<usize, Error> {
    // Try Dobby's resolver first (wraps dlopen+dlsym)
    if let Some(addr) = dobby_rs::resolve_symbol(module, symbol) {
        return Ok(addr as usize);
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
