mod analysis;
mod cli;
mod mcp;
mod profile;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands};

#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Mcp => {
            mcp::run_server().await?;
        }
    }

    Ok(())
}
