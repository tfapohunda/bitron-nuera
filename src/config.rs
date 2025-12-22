use serde::Deserialize;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    ConfigIO(#[from] std::io::Error),
    #[error("failed to parse config: {0}")]
    Config(#[from] toml::de::Error),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    #[expect(dead_code)]
    pub address: String,
}

impl Config {
    pub async fn from(config_path: impl AsRef<Path>) -> Result<Self> {
        let config_str = tokio::fs::read_to_string(config_path).await?;
        let config = toml::from_str(&config_str)?;
        Ok(config)
    }
}
