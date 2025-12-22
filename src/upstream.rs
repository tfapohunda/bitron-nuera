use std::time::Duration;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum UpstreamError {
    #[error("failed to create upstream client: {0}")]
    Client(#[from] reqwest::Error),
}

pub type Result<T> = std::result::Result<T, UpstreamError>;

#[derive(Debug, Clone)]
pub struct UpstreamClient {
    pub client: reqwest::Client,
}

impl UpstreamClient {
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
