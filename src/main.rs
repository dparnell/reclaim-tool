mod reclaim;
mod cli;
mod certs;
mod tls;
mod mqtt_sub;
mod util;

use anyhow::Result;
use cli::{Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::parse();
    cli::init_logging(&cli.log_level);
    match &cli.command {
        Commands::FetchCerts => certs::fetch_and_save_certs(&cli).await,
        Commands::Subscribe { unique_id } => mqtt_sub::subscribe(&cli, unique_id).await,
    }
}
