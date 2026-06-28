//! Routable logging facade.
//!
//! The library must not write to stderr on its own: host applications need to
//! route or silence girth's status output. All status/error text goes through
//! this facade, which is silent by default and only prints when a host installs
//! one. The CLI installs [`init_stderr_logger`].

use std::sync::OnceLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Level {
    Error,
    Warn,
    Info,
}

impl Level {
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
        }
    }
}

type LogFn = dyn Fn(Level, &str) + Send + Sync + 'static;

static LOGGER: OnceLock<Box<LogFn>> = OnceLock::new();

/// Installs the process-wide logger. Returns `false` if one was already set
/// (the first installation wins, mirroring `log::set_logger`).
pub fn set_logger<F>(f: F) -> bool
where
    F: Fn(Level, &str) + Send + Sync + 'static,
{
    LOGGER.set(Box::new(f)).is_ok()
}

/// Emits a message, or drops it if no logger is installed.
#[inline]
pub fn log(level: Level, msg: &str) {
    if let Some(l) = LOGGER.get() {
        l(level, msg);
    }
}

#[inline]
pub fn error(msg: &str) {
    log(Level::Error, msg);
}
#[inline]
pub fn warn(msg: &str) {
    log(Level::Warn, msg);
}
#[inline]
pub fn info(msg: &str) {
    log(Level::Info, msg);
}

/// CLI helper: route all girth log output to stderr (best-effort; ignored if a
/// logger is already installed).
pub fn init_stderr_logger() {
    let _ = set_logger(|level, msg| {
        eprintln!("girth [{}] {}", level.as_str(), msg);
    });
}
