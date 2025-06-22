use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use std::path::PathBuf;

use crate::analyzer::StaticAnalyzer;
use crate::fuzz::FuzzEngine;
use crate::plugin::{PluginAction, PluginManager};
use crate::report::{ReportFormat, ReportGenerator};

#[derive(Parser)]
#[command(name = "scsec")]
#[command(about = "Solana Smart Contract Security Toolkit")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(author = "Hasip Timurtas")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run static analysis on Solana smart contracts
    Scan {
        /// Path to the program directory or IDL file
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Configuration file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output directory for results
        #[arg(short, long, default_value = "./scsec-results")]
        output: PathBuf,

        /// Output format
        #[arg(short, long, default_value = "json")]
        format: ReportFormat,

        /// Fail with non-zero exit code on critical issues
        #[arg(long, default_value = "true")]
        fail_on_critical: bool,
    },

    /// Run fuzz testing on smart contracts
    Fuzz {
        /// Path to the program directory
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Timeout in seconds for fuzzing
        #[arg(short, long, default_value = "300")]
        timeout: u64,

        /// Number of parallel fuzzing jobs
        #[arg(short, long, default_value = "1")]
        jobs: usize,

        /// Output directory for fuzz results
        #[arg(short, long, default_value = "./fuzz-results")]
        output: PathBuf,
    },

    /// Generate reports from analysis results
    Report {
        /// Path to results directory
        #[arg(value_name = "RESULTS")]
        results: PathBuf,

        /// Output path for generated report
        #[arg(short, long, default_value = "./report.html")]
        output: PathBuf,

        /// Report format
        #[arg(short, long, default_value = "html")]
        format: ReportFormat,
    },

    /// Manage security rule plugins
    Plugin {
        /// Plugin action
        #[arg(value_enum)]
        action: PluginAction,

        /// Path to plugin file or directory
        path: Option<PathBuf>,
    },
}

pub async fn handle_scan_command(
    path: PathBuf,
    config: Option<PathBuf>,
    output: PathBuf,
    format: ReportFormat,
    fail_on_critical: bool,
) -> Result<()> {
    info!("Starting static analysis scan on: {}", path.display());

    let mut analyzer = StaticAnalyzer::new(config)?;
    let results = analyzer.analyze_path(&path).await?;

    // Generate report
    let report_gen = ReportGenerator::new();
    report_gen
        .generate_report(&results, &output, format)
        .await?;

    let critical_count = results.iter().filter(|r| r.severity == "critical").count();
    let high_count = results.iter().filter(|r| r.severity == "high").count();

    info!(
        "Scan completed. Found {} critical and {} high severity issues",
        critical_count, high_count
    );

    if fail_on_critical && critical_count > 0 {
        error!("Critical issues found. Failing as requested.");
        std::process::exit(1);
    }

    Ok(())
}

pub async fn handle_fuzz_command(
    path: PathBuf,
    timeout: u64,
    jobs: usize,
    output: PathBuf,
) -> Result<()> {
    info!("Starting fuzz testing on: {}", path.display());

    let fuzz_engine = FuzzEngine::new(path, output)?;
    let results = fuzz_engine.run_fuzzing(timeout, jobs).await?;

    info!("Fuzzing completed. Found {} crashes", results.crashes.len());

    if !results.crashes.is_empty() {
        warn!("Crashes detected during fuzzing!");
        for crash in &results.crashes {
            warn!("Crash: {}", crash.description);
        }
    }

    Ok(())
}

pub async fn handle_report_command(
    results: PathBuf,
    output: PathBuf,
    format: ReportFormat,
) -> Result<()> {
    info!("Generating report from: {}", results.display());

    let report_gen = ReportGenerator::new();
    report_gen
        .generate_from_directory(&results, &output, format)
        .await?;

    info!("Report generated: {}", output.display());

    Ok(())
}

pub async fn handle_plugin_command(action: PluginAction, path: Option<PathBuf>) -> Result<()> {
    let mut plugin_manager = PluginManager::new()?;

    match action {
        PluginAction::List => {
            let plugins = plugin_manager.list_plugins()?;
            info!("Available plugins:");
            for plugin in plugins {
                info!("  - {} ({})", plugin.name, plugin.version);
            }
        }
        PluginAction::Load => {
            if let Some(plugin_path) = path {
                plugin_manager.load_plugin(&plugin_path)?;
                info!("Plugin loaded: {}", plugin_path.display());
            } else {
                error!("Plugin path required for load action");
                std::process::exit(1);
            }
        }
        PluginAction::Unload => {
            if let Some(plugin_path) = path {
                plugin_manager.unload_plugin(&plugin_path)?;
                info!("Plugin unloaded: {}", plugin_path.display());
            } else {
                error!("Plugin path required for unload action");
                std::process::exit(1);
            }
        }
    }

    Ok(())
}
