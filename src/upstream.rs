//! Upstream client module for communicating with the upstream server.

use std::time::Duration;

use thiserror::Error;

/// Errors that can occur when creating or using the upstream client.
#[derive(Debug, Error)]
pub enum UpstreamError {
    /// Failed to create the HTTP client.
    #[error("failed to create upstream client: {0}")]
    Client(#[from] reqwest::Error),
}

/// A specialized [`Result`] type for upstream operations.
pub type Result<T> = std::result::Result<T, UpstreamError>;

/// HTTP client configured for communicating with the upstream server.
///
/// Wraps a [`reqwest::Client`] with appropriate timeout settings for
/// proxying requests.
#[derive(Debug, Clone)]
pub struct UpstreamClient {
    /// The underlying HTTP client.
    pub client: reqwest::Client,
}

impl UpstreamClient {
    /// Creates a new upstream client with default timeout settings.
    ///
    /// Configures the client with:
    /// - 30 second request timeout
    /// - 5 second connection timeout
    /// - Proxy bypass enabled
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client cannot be built.
    pub fn new() -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(30))
                .connect_timeout(Duration::from_secs(5))
                .build()?,
        })
    }
}
