use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "samply-mcp")]
#[command(about = "MCP server for analyzing samply profiler output")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run as MCP server for a given profile
    Mcp {
        /// Path to profile.json or profile.json.gz
        profile_path: PathBuf,
    },
}
