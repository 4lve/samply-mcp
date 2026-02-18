use clap::{Parser, Subcommand};

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
    /// Run as MCP server (profiles loaded on-demand via path parameter)
    Mcp,
}
