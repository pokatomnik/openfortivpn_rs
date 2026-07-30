#[cfg(unix)]
use std::ffi::CString;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

#[cfg(unix)]
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
    USE_SYSLOG.store(use_syslog && cfg!(unix), Ordering::Relaxed);
    init_syslog();
}

pub fn error(message: &str) {
    log(LOG_ERROR, "ERROR:  ", SyslogPriority::Error, message);
}

pub fn warn(message: &str) {
    log(LOG_WARN, "WARN:   ", SyslogPriority::Warning, message);
}

pub fn info(message: &str) {
    log(LOG_INFO, "INFO:   ", SyslogPriority::Info, message);
}

pub fn debug(message: &str) {
    log(LOG_DEBUG, "DEBUG:  ", SyslogPriority::Debug, message);
}

pub fn enabled(level: u8) -> bool {
    level <= LOG_LEVEL.load(Ordering::Relaxed) && level != LOG_MUTE
}

#[derive(Debug, Clone, Copy)]
enum SyslogPriority {
    Error,
    Warning,
    Info,
    Debug,
}

fn log(level: u8, prefix: &str, syslog_priority: SyslogPriority, message: &str) {
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

#[cfg(unix)]
fn init_syslog() {
    if USE_SYSLOG.load(Ordering::Relaxed) {
        if let Ok(ident) = CString::new("openfortivpn") {
            unsafe {
                libc::openlog(ident.as_ptr(), libc::LOG_PID, libc::LOG_DAEMON);
            }
            std::mem::forget(ident);
        }
    }
}

#[cfg(not(unix))]
fn init_syslog() {}

#[cfg(unix)]
fn syslog(priority: SyslogPriority, message: &str) {
    let Ok(format) = CString::new("%s") else {
        return;
    };
    let sanitized = message.replace('\0', "\\0");
    let Ok(message) = CString::new(sanitized) else {
        return;
    };
    unsafe {
        libc::syslog(
            to_libc_priority(priority),
            format.as_ptr(),
            message.as_ptr(),
        );
    }
}

#[cfg(unix)]
fn to_libc_priority(priority: SyslogPriority) -> libc::c_int {
    match priority {
        SyslogPriority::Error => libc::LOG_ERR,
        SyslogPriority::Warning => libc::LOG_WARNING,
        SyslogPriority::Info => libc::LOG_INFO,
        SyslogPriority::Debug => libc::LOG_DEBUG,
    }
}

#[cfg(not(unix))]
fn syslog(_priority: SyslogPriority, message: &str) {
    let mut stdout = io::stdout().lock();
    let _ = writeln!(stdout, "{message}");
    let _ = stdout.flush();
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
