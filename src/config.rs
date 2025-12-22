use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

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
}

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub auth: AuthConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub address: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct UpstreamConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    pub tokens: Vec<TokenMapping>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TokenMapping {
    pub client: String,
    pub upstream: String,
}

impl Config {
    pub async fn from(config_path: impl AsRef<Path>) -> Result<Self> {
        let config_str = tokio::fs::read_to_string(config_path).await?;
        let config = toml::from_str(&config_str)?;
        Ok(config)
    }
}
