//! Application-level error types.

use thiserror::Error;

use crate::{config, proxy};

/// Top-level application errors.
///
/// Wraps errors from various subsystems (proxy, config) into a unified
/// error type for the main application.
#[derive(Debug, Error)]
pub enum AppError {
    /// An error occurred in the proxy service.
    #[error("failed to create service: {0}")]
    MakeService(#[from] proxy::ProxyError),
    /// An error occurred while loading or parsing configuration.
    #[error("failed to parse config: {0}")]
    Config(#[from] config::ConfigError),
}

/// A specialized [`Result`] type for application operations.
pub type Result<T> = std::result::Result<T, AppError>;
