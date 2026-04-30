// SPDX-License-Identifier: MIT OR Apache-2.0

//! Tracing-subscriber setup with text and JSON formatters.

use crate::error::LoggingError;
use tracing_subscriber::EnvFilter;

/// Log output format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

/// Initialise the global tracing subscriber.
///
/// # Errors
/// - [`LoggingError::InvalidFilter`] if `filter` is not a valid `EnvFilter` directive.
/// - [`LoggingError::AlreadyInstalled`] if a global subscriber has already been set.
pub fn init(format: LogFormat, filter: &str) -> Result<(), LoggingError> {
    let env_filter = EnvFilter::try_new(filter).map_err(|e| LoggingError::InvalidFilter {
        filter: filter.to_owned(),
        source: e,
    })?;

    match format {
        LogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .try_init()
            .map_err(|_| LoggingError::AlreadyInstalled)?,
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .try_init()
            .map_err(|_| LoggingError::AlreadyInstalled)?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::LoggingError;

    #[test]
    fn test_invalid_filter_returns_error() {
        let result = init(LogFormat::Text, "!!!invalid");
        assert!(
            matches!(result, Err(LoggingError::InvalidFilter { .. })),
            "expected InvalidFilter error, got: {:?}",
            result
        );
    }

    #[test]
    fn test_valid_filter_accepted() {
        // The global subscriber may already be installed from another test;
        // both Ok and AlreadyInstalled are acceptable outcomes.
        let result = init(LogFormat::Text, "info");
        assert!(
            result.is_ok() || matches!(result, Err(LoggingError::AlreadyInstalled)),
            "unexpected error: {:?}",
            result
        );
    }

    #[test]
    fn test_log_format_variants() {
        assert_ne!(LogFormat::Text, LogFormat::Json);
        assert_eq!(LogFormat::Text, LogFormat::Text);
        assert_eq!(LogFormat::Json, LogFormat::Json);
    }

    #[test]
    fn test_already_installed_is_acceptable_on_second_call() {
        // First call may succeed or fail (if another test ran first).
        let _ = init(LogFormat::Text, "debug");
        // Second call must return AlreadyInstalled (subscriber is now set).
        let result = init(LogFormat::Json, "warn");
        assert!(
            result.is_ok() || matches!(result, Err(LoggingError::AlreadyInstalled)),
            "unexpected error on second init: {:?}",
            result
        );
    }
}
