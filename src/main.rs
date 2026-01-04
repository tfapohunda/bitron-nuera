mod config;
mod error;
mod proxy;
mod upstream;

use std::path::PathBuf;

use clap::Parser;
use proxy::ProxyServer;
use tracing_subscriber::EnvFilter;

use crate::{config::Config, error::Result};

/// Command-line arguments for the proxy server.
#[derive(Parser, Debug)]
struct Args {
    /// Path to the configuration file.
    #[arg(short, long, default_value = "config.toml")]
    config_path: PathBuf,
}

/// Entry point for the proxy server.
///
/// Initializes logging, parses command-line arguments, loads the configuration,
/// and starts the proxy server.
#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::new("info,reqwest=error,hyper=error,hyper_util=error");
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    let args = Args::parse();
    let config = Config::from(&args.config_path)
        .await
        .inspect_err(|err| tracing::error!(%err, "Failed to load config"))?;

    let proxy_server = ProxyServer::new(config);
    proxy_server
        .start()
        .await
        .inspect_err(|err| tracing::error!(%err, "Failed to start proxy server"))?;
    Ok(())
}
