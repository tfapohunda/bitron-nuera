mod config;
mod error;
mod proxy;

use std::path::PathBuf;

use clap::Parser;
use proxy::ProxyServer;
use tracing_subscriber::EnvFilter;

use crate::{config::Config, error::Result};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config_path: PathBuf,
}

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
