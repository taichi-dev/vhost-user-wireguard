// SPDX-License-Identifier: MIT OR Apache-2.0

//! systemd integration: sd_notify and watchdog support.

use std::time::Duration;

/// Notify systemd that the daemon is ready.
///
/// This is best-effort: if not running under systemd (NOTIFY_SOCKET not set),
/// sd_notify returns Ok(false) which we treat as success.
pub fn notify_ready() -> Result<(), crate::error::Error> {
    match sd_notify::notify(false, &[sd_notify::NotifyState::Ready]) {
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::warn!("sd_notify ready failed (non-fatal): {}", e);
            Ok(())
        }
    }
}

/// Notify systemd that the daemon is stopping.
///
/// Best-effort: errors are logged but not propagated.
pub fn notify_stopping() -> Result<(), crate::error::Error> {
    match sd_notify::notify(false, &[sd_notify::NotifyState::Stopping]) {
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::warn!("sd_notify stopping failed (non-fatal): {}", e);
            Ok(())
        }
    }
}

/// Ping the systemd watchdog.
///
/// Best-effort: errors are logged but not propagated.
pub fn notify_watchdog() -> Result<(), crate::error::Error> {
    match sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]) {
        Ok(_) => Ok(()),
        Err(e) => {
            tracing::warn!("sd_notify watchdog failed (non-fatal): {}", e);
            Ok(())
        }
    }
}

/// Return the interval at which the watchdog ping should be sent.
///
/// Reads `WATCHDOG_USEC` from the environment (set by systemd when watchdog is
/// enabled). Returns half the configured interval so pings arrive well before
/// the deadline. Returns `None` if the variable is absent or unparseable.
pub fn watchdog_interval() -> Option<Duration> {
    let usec: u64 = std::env::var("WATCHDOG_USEC")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_micros(usec / 2))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_watchdog_interval_not_set() {
        unsafe { std::env::remove_var("WATCHDOG_USEC") };
        assert_eq!(watchdog_interval(), None);
    }

    #[test]
    fn test_watchdog_interval_set() {
        unsafe { std::env::set_var("WATCHDOG_USEC", "30000000") };
        let interval = watchdog_interval().expect("should return Some");
        assert_eq!(interval, Duration::from_secs(15));
        unsafe { std::env::remove_var("WATCHDOG_USEC") };
    }

    #[test]
    fn test_notify_ready_no_panic() {
        let result = notify_ready();
        let _ = result;
    }

    #[test]
    fn test_notify_stopping_no_panic() {
        let _ = notify_stopping();
    }

    #[test]
    fn test_notify_watchdog_no_panic() {
        let _ = notify_watchdog();
    }

    #[test]
    fn test_watchdog_interval_invalid_value() {
        unsafe { std::env::set_var("WATCHDOG_USEC", "not_a_number") };
        assert_eq!(watchdog_interval(), None);
        unsafe { std::env::remove_var("WATCHDOG_USEC") };
    }
}
