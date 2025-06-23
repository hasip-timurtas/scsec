use anyhow::Result;
use clap::Parser;
use env_logger::Env;
use log::info;

mod analyzer;
mod cli;
mod fuzz;
mod plugin;
mod report;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logger with colored output
    env_logger::Builder::from_env(Env::default().default_filter_or("info"))
        .write_style(env_logger::WriteStyle::Auto)
        .init();

    let cli = Cli::parse();

    info!(
        "Starting Solana Smart Contract Security Toolkit (solsec) v{}",
        env!("CARGO_PKG_VERSION")
    );

    match cli.command {
        Commands::Scan {
            path,
            config,
            output,
            format,
            json_only,
            html_only,
            no_open,
            fail_on_critical,
        } => {
            let scan_config = cli::ScanConfig {
                path,
                config,
                output,
                formats: format,
                json_only,
                html_only,
                no_open,
                fail_on_critical,
            };
            cli::handle_scan_command(scan_config).await
        }
        Commands::Fuzz {
            path,
            timeout,
            jobs,
            output,
        } => cli::handle_fuzz_command(path, timeout, jobs, output).await,

        Commands::Plugin { action, path } => cli::handle_plugin_command(action, path).await,
    }
}
