//! Configuration module for the proxy server.
//!
//! Provides types for loading and validating configuration from TOML files.

use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

use crate::upstream::UpstreamError;

/// Errors that can occur when loading or validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ReadConfig(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    ParseConfig(#[from] toml::de::Error),
    #[error("failed to create request client: {0}")]
    RequestClient(#[from] reqwest::Error),
    #[error("failed to parse upstream url: {0}")]
    InvalidUrl(String),
    #[error("failed to convert tokens: {0}")]
    InvalidToken(String),
    #[error("failed to create upstream client: {0}")]
    UpstreamClient(#[from] UpstreamError),
    #[error("rate limit must be greater than zero")]
    InvalidRateLimit,
}

/// A specialized [`Result`] type for configuration operations.
pub type Result<T> = std::result::Result<T, ConfigError>;

/// Root configuration structure for the proxy server.
///
/// Loaded from a TOML file and contains all settings needed to run the proxy.
#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    /// Server binding configuration.
    pub server: ServerConfig,
    /// Upstream server configuration.
    pub upstream: UpstreamConfig,
    /// Authentication and token mapping configuration.
    pub auth: AuthConfig,
    /// Rate limiting configuration.
    pub rate_limit: RateLimitConfig,
}

/// Server binding configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    /// The address to bind the server to (e.g., "127.0.0.1:8080").
    pub address: String,
}

/// Upstream server configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    /// The base URL of the upstream server.
    pub url: String,
}

/// Authentication configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    /// List of client-to-upstream token mappings.
    pub tokens: Vec<TokenMapping>,
}

/// Mapping between a client token and its corresponding upstream token.
///
/// When a client authenticates with the `client` token, requests will be
/// forwarded to the upstream server using the `upstream` token.
#[derive(Debug, Deserialize, Clone)]
pub struct TokenMapping {
    /// The token presented by the client.
    pub client: String,
    /// The token used to authenticate with the upstream server.
    pub upstream: String,
}

/// Rate limiting configuration.
#[derive(Debug, Deserialize, Clone)]
pub struct RateLimitConfig {
    /// Maximum number of requests allowed per minute per client token.
    pub requests_per_minute: u32,
}

impl Config {
    /// Loads configuration from a TOML file at the specified path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or parsed as valid TOML.
    pub async fn from(config_path: impl AsRef<Path>) -> Result<Self> {
        let config_str = tokio::fs::read_to_string(config_path).await?;
        let config = toml::from_str(&config_str)?;
        Ok(config)
    }
}
