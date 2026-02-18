mod analysis;
mod cli;
mod mcp;
mod profile;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Mcp { profile_path } => {
            mcp::run_server(&profile_path).await?;
        }
    }

    Ok(())
}
