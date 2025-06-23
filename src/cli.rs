use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use std::path::PathBuf;

use crate::analyzer::StaticAnalyzer;
use crate::fuzz::FuzzEngine;
use crate::plugin::{PluginAction, PluginManager};
use crate::report::{ReportFormat, ReportGenerator};

#[derive(Parser)]
#[command(name = "solsec")]
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
        /// Path to the program directory or file(s). Defaults to current directory.
        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,

        /// Configuration file path
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Output directory for results
        #[arg(short, long, default_value = "./solsec-results")]
        output: PathBuf,

        /// Output format(s) - can specify multiple: json,html,markdown,csv
        #[arg(short, long, default_value = "json,html", value_delimiter = ',')]
        format: Vec<ReportFormat>,

        /// Only generate JSON output (for CI/CD integration)
        #[arg(long, conflicts_with = "format")]
        json_only: bool,

        /// Only generate HTML output (for human review)
        #[arg(long, conflicts_with = "format")]
        html_only: bool,

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
        #[arg(short, long, default_value = "./solsec-fuzz")]
        output: PathBuf,
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
    formats: Vec<ReportFormat>,
    json_only: bool,
    html_only: bool,
    fail_on_critical: bool,
) -> Result<()> {
    info!("Starting static analysis scan on: {}", path.display());

    let mut analyzer = StaticAnalyzer::new(config)?;
    let results = analyzer.analyze_path(&path).await?;

    // Determine which formats to generate
    let formats_to_generate = if json_only {
        vec![ReportFormat::Json]
    } else if html_only {
        vec![ReportFormat::Html]
    } else {
        formats
    };

    // Generate reports in all requested formats
    let report_gen = ReportGenerator::new();
    for format in formats_to_generate {
        let extension = match format {
            ReportFormat::Json => "json",
            ReportFormat::Html => "html",
            ReportFormat::Markdown => "md",
            ReportFormat::Csv => "csv",
        };

        let output_file = if output.extension().is_some() {
            // If user provided a specific filename, respect it for the first format
            output.clone()
        } else {
            // Generate appropriate filename based on format
            output.join(format!("security-report.{}", extension))
        };

        report_gen
            .generate_report(&results, &output_file, format.clone())
            .await?;
    }

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
