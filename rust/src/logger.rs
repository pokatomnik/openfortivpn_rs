use std::ffi::CString;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use nix::libc;

const LOG_MUTE: u8 = 0;
const LOG_ERROR: u8 = 1;
const LOG_WARN: u8 = 2;
const LOG_INFO: u8 = 3;
const LOG_DEBUG: u8 = 4;
const LOG_DEBUG_ALL: u8 = 6;

static LOG_LEVEL: AtomicU8 = AtomicU8::new(LOG_INFO);
static USE_SYSLOG: AtomicBool = AtomicBool::new(false);

pub fn init(use_syslog: bool, verbosity: u8) {
    LOG_LEVEL.store(verbosity.min(LOG_DEBUG_ALL), Ordering::Relaxed);
    if use_syslog {
        USE_SYSLOG.store(true, Ordering::Relaxed);
        if let Ok(ident) = CString::new("openfortivpn") {
            unsafe {
                libc::openlog(ident.as_ptr(), libc::LOG_PID, libc::LOG_DAEMON);
            }
            std::mem::forget(ident);
        }
    }
}

pub fn error(message: &str) {
    log(LOG_ERROR, "ERROR:  ", libc::LOG_ERR, message);
}

pub fn warn(message: &str) {
    log(LOG_WARN, "WARN:   ", libc::LOG_WARNING, message);
}

pub fn info(message: &str) {
    log(LOG_INFO, "INFO:   ", libc::LOG_INFO, message);
}

pub fn debug(message: &str) {
    log(LOG_DEBUG, "DEBUG:  ", libc::LOG_DEBUG, message);
}

pub fn enabled(level: u8) -> bool {
    level <= LOG_LEVEL.load(Ordering::Relaxed) && level != LOG_MUTE
}

fn log(level: u8, prefix: &str, syslog_priority: libc::c_int, message: &str) {
    if !enabled(level) {
        return;
    }

    if USE_SYSLOG.load(Ordering::Relaxed) {
        syslog(syslog_priority, message);
    } else {
        let mut stdout = io::stdout().lock();
        let _ = writeln!(stdout, "{prefix}{message}");
        let _ = stdout.flush();
    }
}

fn syslog(priority: libc::c_int, message: &str) {
    let Ok(format) = CString::new("%s") else {
        return;
    };
    let sanitized = message.replace('\0', "\\0");
    let Ok(message) = CString::new(sanitized) else {
        return;
    };
    unsafe {
        libc::syslog(priority, format.as_ptr(), message.as_ptr());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verbosity_gates_messages() {
        init(false, LOG_WARN);
        assert!(enabled(LOG_ERROR));
        assert!(enabled(LOG_WARN));
        assert!(!enabled(LOG_INFO));
    }
}
