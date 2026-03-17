use crate::core::Hachimi;
use super::hook;

/// iOS entry point via the `#[ctor]` constructor attribute.
///
/// This function is called by dyld **before** the app's `main()` runs,
/// giving Hachimi a chance to install its hooks early.
#[ctor::ctor]
fn hachimi_ios_init() {
    // ═══ STAGE 1: CONSTRUCTOR ═══
    // Note: logger is not yet initialized here, so we use syslog directly for
    // the very first message.
    unsafe {
        libc::syslog(
            libc::LOG_NOTICE,
            b"[Hachimi] %s\0".as_ptr() as *const _,
            b"=== STAGE 1: CONSTRUCTOR ===\0".as_ptr(),
        );
    }

    if !Hachimi::init() {
        unsafe {
            libc::syslog(
                libc::LOG_NOTICE,
                b"[Hachimi] %s\0".as_ptr() as *const _,
                b"Hachimi::init() FAILED\0".as_ptr(),
            );
        }
        return;
    }

    // Logger is now initialized by Hachimi::init()
    let pkg = super::game_impl::get_package_name();
    let region = super::game_impl::get_region(&pkg);
    let data_dir = super::game_impl::get_data_dir(&pkg);
    info!("═══ STAGE 1: CONSTRUCTOR ═══");
    info!("Hachimi::init() OK");
    info!("Bundle ID: {}", pkg);
    info!("Region: {}", region);
    info!("Data dir: {:?}", data_dir);

    hook::init();
    info!("hook::init() — dyld callback registered");
    info!("═══ STAGE 1: DONE ═══");
}
