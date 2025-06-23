use anyhow::Result;
use clap::{Parser, Subcommand};
use log::{error, info, warn};
use std::path::PathBuf;

use crate::analyzer::StaticAnalyzer;
use crate::fuzz::FuzzEngine;
use crate::plugin::{PluginAction, PluginManager};
use crate::report::{ReportFormat, ReportGenerator};

#[derive(Debug)]
pub struct ScanConfig {
    pub path: PathBuf,
    pub config: Option<PathBuf>,
    pub output: PathBuf,
    pub formats: Vec<ReportFormat>,
    pub json_only: bool,
    pub html_only: bool,
    pub no_open: bool,
    pub fail_on_critical: bool,
}

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

        /// Don't automatically open HTML report in browser (opens by default in interactive mode)
        #[arg(long)]
        no_open: bool,

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

pub async fn handle_scan_command(config: ScanConfig) -> Result<()> {
    info!(
        "Starting static analysis scan on: {}",
        config.path.display()
    );

    let mut analyzer = StaticAnalyzer::new(config.config)?;
    let results = analyzer.analyze_path(&config.path).await?;

    // Determine which formats to generate
    let formats_to_generate = if config.json_only {
        vec![ReportFormat::Json]
    } else if config.html_only {
        vec![ReportFormat::Html]
    } else {
        config.formats
    };

    // Check if we should open HTML before generating reports
    let should_open = should_open_html(&formats_to_generate, config.no_open);
    let mut html_file_path: Option<PathBuf> = None;

    // Generate reports in all requested formats
    let report_gen = ReportGenerator::new();
    for format in formats_to_generate {
        let extension = match format {
            ReportFormat::Json => "json",
            ReportFormat::Html => "html",
            ReportFormat::Markdown => "md",
            ReportFormat::Csv => "csv",
        };

        let output_file = if config.output.extension().is_some() {
            // If user provided a specific filename, respect it for the first format
            config.output.clone()
        } else {
            // Generate appropriate filename based on format
            config.output.join(format!("security-report.{}", extension))
        };

        // Track HTML file path for opening later
        if matches!(format, ReportFormat::Html) {
            html_file_path = Some(output_file.clone());
        }

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

    if config.fail_on_critical && critical_count > 0 {
        error!("Critical issues found. Failing as requested.");
        std::process::exit(1);
    }

    // Open HTML report in browser if appropriate
    if should_open {
        if let Some(html_path) = html_file_path {
            open_html_file(&html_path)?;
        }
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

/// Detects if we're running in a CI environment
fn is_ci_environment() -> bool {
    // Check common CI environment variables
    std::env::var("CI").is_ok()
        || std::env::var("GITHUB_ACTIONS").is_ok()
        || std::env::var("GITLAB_CI").is_ok()
        || std::env::var("JENKINS_URL").is_ok()
        || std::env::var("TRAVIS").is_ok()
        || std::env::var("CIRCLECI").is_ok()
        || std::env::var("BUILDKITE").is_ok()
        || std::env::var("TF_BUILD").is_ok() // Azure DevOps
}

/// Detects if we're in an interactive terminal session
fn is_interactive() -> bool {
    // Check if stdout is a terminal and not redirected
    use std::io::IsTerminal;
    std::io::stdout().is_terminal()
}

/// Determines if we should automatically open the HTML report
fn should_open_html(formats: &[ReportFormat], no_open: bool) -> bool {
    // Don't open if user explicitly disabled it
    if no_open {
        return false;
    }

    // Don't open in CI environments
    if is_ci_environment() {
        return false;
    }

    // Don't open if not in interactive terminal
    if !is_interactive() {
        return false;
    }

    // Only open if HTML is being generated
    formats.contains(&ReportFormat::Html)
}

/// Opens the HTML file in the default browser
fn open_html_file(file_path: &PathBuf) -> Result<()> {
    match opener::open(file_path) {
        Ok(()) => {
            info!(
                "📖 Opening security report in browser: {}",
                file_path.display()
            );
            Ok(())
        }
        Err(e) => {
            warn!(
                "Could not open HTML report in browser: {}. You can manually open: {}",
                e,
                file_path.display()
            );
            Ok(()) // Don't fail the entire command if browser opening fails
        }
    }
}
