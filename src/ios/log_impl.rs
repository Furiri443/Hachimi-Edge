//! iOS dual logger: syslog (3uTools visible) + file log.
//!
//! **syslog** — `libc::syslog(LOG_NOTICE, "[Hachimi] ...")` — realtime on 3uTools.
//! **file** — `$HOME/Documents/hachimi/hachimi.log` — detailed with timestamps.

use log::{Level, LevelFilter, Log, Metadata, Record};
use std::io::Write;
use std::sync::Mutex;

struct DualLogger {
    file: Option<Mutex<std::fs::File>>,
}

impl Log for DualLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        // 1. syslog — always, visible in 3uTools
        let msg = format!("[Hachimi] {}", record.args());
        if let Ok(cmsg) = std::ffi::CString::new(msg.clone()) {
            unsafe {
                // Use %s format to avoid format string injection
                libc::syslog(libc::LOG_NOTICE, b"%s\0".as_ptr() as *const _, cmsg.as_ptr());
            }
        }

        // 2. file log — with timestamp and level
        if let Some(ref file_mutex) = self.file {
            if let Ok(mut f) = file_mutex.lock() {
                // Simple timestamp: seconds since init (avoid pulling in chrono)
                let _ = writeln!(f, "[{}] {}", record.level(), record.args());
                let _ = f.flush();
            }
        }
    }

    fn flush(&self) {
        if let Some(ref file_mutex) = self.file {
            if let Ok(mut f) = file_mutex.lock() {
                let _ = f.flush();
            }
        }
    }
}

static mut LOGGER: Option<DualLogger> = None;

pub fn init(filter_level: LevelFilter, _file_logging: bool) {
    let log_path = crate::ios::utils::get_log_path();

    // Ensure the parent directory exists
    if let Some(parent) = log_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .ok();

    unsafe {
        LOGGER = Some(DualLogger {
            file: file.map(Mutex::new),
        });

        if let Some(ref logger) = LOGGER {
            log::set_logger(logger as &'static dyn Log)
                .map(|()| log::set_max_level(filter_level))
                .unwrap_or_else(|e| {
                    // If logger init fails, at least try syslog directly
                    let msg = format!("[Hachimi] Failed to set logger: {}\0", e);
                    libc::syslog(libc::LOG_ERR, b"%s\0".as_ptr() as *const _,
                        msg.as_ptr() as *const _);
                });
        }
    }
}
