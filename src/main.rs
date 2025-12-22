mod app_state;
mod config;
mod error;
mod proxy;
mod request_id;

use std::path::PathBuf;

use clap::Parser;
use proxy::Proxy;
use tracing_subscriber::EnvFilter;

use crate::{config::Config, error::Result};

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let filter = EnvFilter::new("debug,reqwest=error,hyper=error,hyper_util=error");
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let args = Args::parse();
    let config = Config::from(&args.config_path).await?;

    let proxy_server = Proxy::new(config);
    proxy_server.start().await?;
    Ok(())
}
