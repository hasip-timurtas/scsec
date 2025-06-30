//! # solsec - Solana Smart Contract Security Toolkit
//!
//! A comprehensive security analysis toolkit for Solana smart contracts.
//!
//! ## Features
//!
//! - **Static Analysis**: Built-in security rules for common vulnerabilities
//! - **Fuzzing**: Automated fuzz testing with IDL integration  
//! - **Reporting**: Multiple output formats (JSON, HTML, Markdown, CSV)
//! - **Plugin System**: Extensible security rules via dynamic loading
//!
//! ## Example
//!
//! ```rust
//! use solsec::analyzer::StaticAnalyzer;
//! use std::path::Path;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let mut analyzer = StaticAnalyzer::new(None)?;
//!     let results = analyzer.analyze_path(Path::new("src/")).await?;
//!     
//!     println!("Found {} security issues", results.len());
//!     Ok(())
//! }
//! ```

// Re-export core modules for library usage
pub mod analyzer;
pub mod fuzz;
pub mod plugin;
pub mod report;

// CLI module is typically not exposed in library API
// but can be made public if needed for programmatic CLI usage
pub mod cli;

// Re-export commonly used types for convenience
pub use analyzer::{AnalysisResult, AnalyzerConfig, StaticAnalyzer};
pub use fuzz::FuzzEngine;
pub use plugin::{PluginManager, Rule};
pub use report::{ReportFormat, ReportGenerator};
