use serde::{Deserialize, Serialize};
use crate::core::Hachimi;
use super::{il2cpp_resolver, il2cpp_missing, resolve_icall_scanner, symbols_impl};

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
    // ═══ STAGE 3 is logged inside il2cpp_resolver::resolve() ═══

    match il2cpp_resolver::resolve(header_addr, slide) {
        Err(e) => {
            error!("═══ STAGE 3: FAILED ═══");
            error!("IL2CPP resolver error: {}", e);
            // Still try fallback — show error alert
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(5));
                unsafe {
                    super::show_alert("Hachimi Error", &format!("IL2CPP resolver failed:\n{}", e));
                }
            });
        }
        Ok(mut map) => {
            // Patch in re-implemented shims for functions absent from the binary.
            let shim_count = il2cpp_missing::missing_fn_table().len();
            for (name, addr) in il2cpp_missing::missing_fn_table() {
                map.entry(name).or_insert(addr);
            }
            info!("═══ STAGE 3: DONE ({} symbols + {} shims = {} total) ═══",
                map.len() - shim_count, shim_count, map.len());

            // Set the legacy HANDLE for any remaining dlsym() calls.
            crate::il2cpp::symbols::set_handle(header_addr);

            // Grab il2cpp_init address BEFORE storing the map, then hook it.
            let il2cpp_init_addr = map.get("il2cpp_init").copied().unwrap_or(0);

            // Log first few resolved symbols for verification
            let mut sample: Vec<_> = map.iter().take(5).collect();
            sample.sort_by_key(|(k, _)| *k);
            for (name, addr) in &sample {
                info!("  {} = {:#x}", name, addr);
            }

            symbols_impl::set_resolved(map);

            // ═══ STAGE 4: IL2CPP_INIT HOOK ═══
            info!("═══ STAGE 4: IL2CPP_INIT HOOK ═══");
            if il2cpp_init_addr != 0 {
                info!("il2cpp_init found at {:#x}", il2cpp_init_addr);
                install_il2cpp_init_hook(il2cpp_init_addr);
            } else {
                error!("il2cpp_init NOT in resolver map — hooking will not fire");
                error!("═══ STAGE 4: FAILED ═══");
            }

            // ═══ STAGE 4.5: DETECT ALREADY-INITIALIZED ═══
            // On iOS, il2cpp_init may have been called before our dyld callback.
            // Spawn a thread to poll il2cpp_domain_get — if it returns non-null,
            // the runtime is already up and we run post-init logic directly.
            std::thread::spawn(|| {
                for attempt in 1..=10 {
                    std::thread::sleep(std::time::Duration::from_secs(1));

                    // Check if our hook already fired (Stage 5 completed)
                    if ORIG_IL2CPP_INIT.load(std::sync::atomic::Ordering::Relaxed) != 0 {
                        // Try to see if domain is available
                        let domain = crate::il2cpp::api::il2cpp_domain_get();
                        if !domain.is_null() && !STAGE5_DONE.load(std::sync::atomic::Ordering::Relaxed) {
                            info!("═══ STAGE 4.5: il2cpp_init already ran (domain={:?})! Running post-init... ═══", domain);
                            STAGE5_DONE.store(true, std::sync::atomic::Ordering::Relaxed);
                            run_post_il2cpp_init();
                            return;
                        }
                    }
                    // If Stage 5 already completed via hook, we're done
                    if STAGE5_DONE.load(std::sync::atomic::Ordering::Relaxed) {
                        info!("Stage 5 already completed via hook — poll thread exiting");
                        return;
                    }
                    info!("Polling for il2cpp domain... attempt {}/10", attempt);
                }
                error!("═══ STAGE 4.5: Timed out waiting for il2cpp domain ═══");
            });
        }
    }
}

/// Trampoline to the original `il2cpp_init`.
static ORIG_IL2CPP_INIT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Whether Stage 5 logic has been executed (by hook or by poll thread).
static STAGE5_DONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Our hook for `il2cpp_init(domain_name)`.
/// Called right after Unity finishes initialising the scripting runtime.
unsafe extern "C" fn hooked_il2cpp_init(domain_name: *const std::os::raw::c_char) -> i32 {
    info!("═══ STAGE 5: IL2CPP_INIT FIRED (via hook) ═══");

    let name_str = if !domain_name.is_null() {
        std::ffi::CStr::from_ptr(domain_name).to_string_lossy().to_string()
    } else {
        "(null)".to_string()
    };
    info!("il2cpp_init called with domain: {}", name_str);

    let orig: extern "C" fn(*const std::os::raw::c_char) -> i32 =
        std::mem::transmute(ORIG_IL2CPP_INIT.load(std::sync::atomic::Ordering::Relaxed));
    let result = orig(domain_name);

    info!("Original il2cpp_init returned: {}", result);

    // Mark done and run post-init
    if !STAGE5_DONE.swap(true, std::sync::atomic::Ordering::Relaxed) {
        run_post_il2cpp_init();
    } else {
        info!("Stage 5 already completed by poll thread — skipping");
    }

    result
}

/// Shared post-init logic for Stages 5, 5.5, 6.
/// Called either from the hook (if it fires) or from the polling thread (if
/// il2cpp_init already ran before our hook was installed).
unsafe fn run_post_il2cpp_init() {
    info!("═══ STAGE 5: POST-INIT ═══");
    crate::il2cpp::symbols::init();
    crate::core::Hachimi::instance().on_hooking_finished();
    info!("═══ STAGE 5: DONE ═══");

    // ═══ STAGE 5.5: FIND il2cpp_resolve_icall VIA BL-SCAN ═══
    info!("═══ STAGE 5.5: RESOLVE_ICALL SCANNER ═══");
    match resolve_icall_scanner::resolve() {
        Some(addr) => {
            super::symbols_impl::update_resolved("il2cpp_resolve_icall", addr);
            info!("il2cpp_resolve_icall patched ✅ {:#x}", addr);
            info!("═══ STAGE 5.5: DONE ═══");
        }
        None => {
            error!("il2cpp_resolve_icall NOT FOUND — icall APIs will return null");
            error!("═══ STAGE 5.5: FAILED ═══");
        }
    }

    // ═══ STAGE 6: FPS UNLOCK TEST ═══
    std::thread::spawn(|| {
        info!("═══ STAGE 6: FPS UNLOCK TEST ═══");
        info!("Waiting 5s for Unity to initialize...");
        std::thread::sleep(std::time::Duration::from_secs(5));

        info!("Resolving set_targetFrameRate...");
        let func_addr = crate::il2cpp::api::il2cpp_resolve_icall(
            c"UnityEngine.Application::set_targetFrameRate(System.Int32)".as_ptr(),
        );

        if func_addr != 0 {
            info!("set_targetFrameRate resolved at {:#x}", func_addr);
            info!("Calling unlock_fps_on_main_thread(240)...");
            super::unlock_fps_on_main_thread(240);

            std::thread::sleep(std::time::Duration::from_secs(1));
            let pkg = super::game_impl::get_package_name();
            let region = super::game_impl::get_region(&pkg);
            super::show_alert("Hachimi Edge",
                &format!("Injection OK!\nFPS → 240\nPkg: {}\nRegion: {}", pkg, region));
            info!("═══ STAGE 6: DONE ═══");
        } else {
            error!("set_targetFrameRate resolved to 0 — icall not found");
            super::show_alert("Hachimi Error", "set_targetFrameRate resolved to 0");
            error!("═══ STAGE 6: FAILED ═══");
        }
    });
}

fn install_il2cpp_init_hook(addr: usize) {
    let hachimi = crate::core::Hachimi::instance();
    info!("Installing il2cpp_init hook: target={:#x} hook={:#x}",
        addr, hooked_il2cpp_init as usize);

    // Dump first 4 instructions BEFORE hook (for comparison)
    unsafe {
        let pre_bytes = std::slice::from_raw_parts(addr as *const u32, 4);
        info!("PRE-HOOK  bytes @ {:#x}: {:08x} {:08x} {:08x} {:08x}",
            addr, pre_bytes[0], pre_bytes[1], pre_bytes[2], pre_bytes[3]);
    }

    match hachimi.interceptor.hook(addr, hooked_il2cpp_init as usize) {
        Ok(trampoline) => {
            ORIG_IL2CPP_INIT.store(trampoline, std::sync::atomic::Ordering::Relaxed);
            info!("Trampoline at {:#x}", trampoline);

            // Dump first 4 instructions AFTER hook — should be a branch now
            unsafe {
                let post_bytes = std::slice::from_raw_parts(addr as *const u32, 4);
                info!("POST-HOOK bytes @ {:#x}: {:08x} {:08x} {:08x} {:08x}",
                    addr, post_bytes[0], post_bytes[1], post_bytes[2], post_bytes[3]);
            }

            info!("═══ STAGE 4: DONE — waiting for il2cpp_init() call ═══");
        }
        Err(e) => {
            error!("Failed to hook il2cpp_init: {}", e);
            error!("═══ STAGE 4: FAILED ═══");
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

/// iOS-specific configuration fields.
#[derive(Deserialize, Serialize, Clone, Default)]
pub struct Config {
    #[serde(default = "Config::default_fab_x")]
    pub fab_x: f32,
    #[serde(default = "Config::default_fab_y")]
    pub fab_y: f32,
}

impl Config {
    fn default_fab_x() -> f32 { 16.0 }
    fn default_fab_y() -> f32 { 100.0 }
}
