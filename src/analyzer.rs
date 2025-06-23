use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::plugin::{PluginManager, Rule, RuleResult, Severity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub rule_name: String,
    pub severity: String,
    pub message: String,
    pub file_path: String,
    pub line_number: Option<usize>,
    pub column: Option<usize>,
    pub code_snippet: Option<String>,
    pub suggestion: Option<String>,
}

#[derive(Debug)]
pub struct StaticAnalyzer {
    rules: Vec<Box<dyn Rule>>,
    config: AnalyzerConfig,
    plugin_manager: Option<PluginManager>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AnalyzerConfig {
    pub enabled_rules: Vec<String>,
    pub disabled_rules: Vec<String>,
    pub rule_settings: HashMap<String, serde_json::Value>,
}

impl Default for AnalyzerConfig {
    fn default() -> Self {
        Self {
            enabled_rules: vec![
                "integer_overflow".to_string(),
                "missing_signer_check".to_string(),
                "unchecked_account".to_string(),
                "reentrancy".to_string(),
            ],
            disabled_rules: vec![],
            rule_settings: HashMap::new(),
        }
    }
}

impl StaticAnalyzer {
    pub fn new(config_path: Option<PathBuf>) -> Result<Self> {
        let config = if let Some(path) = config_path {
            let config_content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read config file: {}", path.display()))?;
            toml::from_str(&config_content).with_context(|| "Failed to parse config file")?
        } else {
            AnalyzerConfig::default()
        };

        let mut analyzer = Self {
            rules: Vec::new(),
            config,
            plugin_manager: PluginManager::new().ok(),
        };

        // Register built-in rules
        analyzer.register_builtin_rules()?;

        // Load plugin rules if plugin manager is available
        if let Some(plugin_manager) = &analyzer.plugin_manager {
            let plugin_rules = plugin_manager.get_all_rules();
            info!("Loaded {} plugin rules", plugin_rules.len());

            // Log rule descriptions (demonstrates usage of trait methods)
            for rule in &analyzer.rules {
                debug!("Rule '{}': {}", rule.name(), rule.description());
                if let Some(_schema) = rule.config_schema() {
                    debug!("Rule '{}' has configuration schema", rule.name());
                }
            }
        }

        Ok(analyzer)
    }

    fn register_builtin_rules(&mut self) -> Result<()> {
        self.rules.push(Box::new(IntegerOverflowRule::new()));
        self.rules.push(Box::new(MissingSignerCheckRule::new()));
        self.rules.push(Box::new(UncheckedAccountRule::new()));
        self.rules.push(Box::new(ReentrancyRule::new()));
        Ok(())
    }

    pub async fn analyze_path(&mut self, path: &Path) -> Result<Vec<AnalysisResult>> {
        let mut results = Vec::new();

        // Check if path exists first
        if !path.exists() {
            error!("Path does not exist: {}", path.display());
            anyhow::bail!("Path does not exist: {}", path.display());
        }

        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "rs" {
                    results.extend(self.analyze_file(path).await?);
                } else {
                    warn!("File is not a Rust source file (.rs): {}", path.display());
                }
            } else {
                warn!("File has no extension: {}", path.display());
            }
        } else if path.is_dir() {
            let mut rust_files_found = 0;
            let walker = WalkDir::new(path).into_iter();
            let filtered_walker = walker.filter_entry(|e| {
                let is_target = e.file_name() == "target";
                let is_git = e.file_name() == ".git";
                !is_target && !is_git
            });

            for entry in filtered_walker.filter_map(|e| e.ok()) {
                let entry_path = entry.path();
                if entry_path.extension().is_some_and(|ext| ext == "rs") {
                    rust_files_found += 1;
                    results.extend(self.analyze_file(entry_path).await?);
                }
            }
            if rust_files_found == 0 {
                warn!(
                    "No Rust source files (.rs) found in directory: {}",
                    path.display()
                );
            } else {
                info!("Analyzed {} Rust files", rust_files_found);
            }
        } else {
            error!("Path is neither a file nor a directory: {}", path.display());
            anyhow::bail!("Path is neither a file nor a directory: {}", path.display());
        }

        info!("Static analysis completed. Found {} issues", results.len());
        Ok(results)
    }

    async fn analyze_file(&mut self, file_path: &Path) -> Result<Vec<AnalysisResult>> {
        debug!("Analyzing file: {}", file_path.display());

        let content = fs::read_to_string(file_path)
            .with_context(|| format!("Failed to read file: {}", file_path.display()))?;

        let mut results = Vec::new();

        for rule in &self.rules {
            if self.is_rule_enabled(rule.name()) {
                // Pass rule-specific settings if available
                let _rule_config = self.config.rule_settings.get(rule.name());
                match rule.check(&content, file_path) {
                    Ok(rule_results) => {
                        for rule_result in rule_results {
                            results.push(AnalysisResult {
                                rule_name: rule.name().to_string(),
                                severity: format!("{:?}", rule_result.severity).to_lowercase(),
                                message: rule_result.message,
                                file_path: file_path.to_string_lossy().to_string(),
                                line_number: rule_result.line_number,
                                column: rule_result.column,
                                code_snippet: rule_result.code_snippet,
                                suggestion: rule_result.suggestion,
                            });
                        }
                    }
                    Err(e) => {
                        warn!(
                            "Rule '{}' failed on file {}: {}",
                            rule.name(),
                            file_path.display(),
                            e
                        );
                    }
                }
            }
        }

        Ok(results)
    }

    fn is_rule_enabled(&self, rule_name: &str) -> bool {
        if self.config.disabled_rules.contains(&rule_name.to_string()) {
            return false;
        }

        self.config.enabled_rules.is_empty()
            || self.config.enabled_rules.contains(&rule_name.to_string())
    }
}

// Built-in security rules

#[derive(Debug)]
pub struct IntegerOverflowRule {
    overflow_patterns: Vec<Regex>,
}

impl IntegerOverflowRule {
    pub fn new() -> Self {
        let patterns = vec![
            Regex::new(r"\.checked_add\(").expect("Invalid regex for checked_add"),
            Regex::new(r"\.checked_sub\(").expect("Invalid regex for checked_sub"),
            Regex::new(r"\.checked_mul\(").expect("Invalid regex for checked_mul"),
            Regex::new(r"\.checked_div\(").expect("Invalid regex for checked_div"),
            Regex::new(r"\+\s*=").expect("Invalid regex for add assignment"),
            Regex::new(r"-\s*=").expect("Invalid regex for sub assignment"),
            Regex::new(r"\*\s*=").expect("Invalid regex for mul assignment"),
        ];

        Self {
            overflow_patterns: patterns,
        }
    }
}

impl Rule for IntegerOverflowRule {
    fn name(&self) -> &str {
        "integer_overflow"
    }

    fn description(&self) -> &str {
        "Detects potential integer overflow vulnerabilities"
    }

    fn check(&self, content: &str, _file_path: &Path) -> Result<Vec<RuleResult>> {
        let mut results = Vec::new();
        let lines: Vec<&str> = content.lines().collect();
        let arithmetic_regex = Regex::new(r"\b\w+\s*[+\-*]\s*\w+")?;

        for (line_num, line) in lines.iter().enumerate() {
            // Look for arithmetic operations without checked variants
            if line.contains('+') || line.contains('-') || line.contains('*') {
                // Skip if already using checked operations - check using our patterns
                if self
                    .overflow_patterns
                    .iter()
                    .any(|pattern| pattern.is_match(line))
                {
                    continue;
                }

                // Look for potential integer operations
                if arithmetic_regex.is_match(line) {
                    results.push(RuleResult {
                        severity: Severity::Medium,
                        message: "Potential integer overflow. Consider using checked arithmetic operations.".to_string(),
                        line_number: Some(line_num + 1),
                        column: None,
                        code_snippet: Some(line.trim().to_string()),
                        suggestion: Some("Use checked_add(), checked_sub(), or checked_mul()".to_string()),
                    });
                }
            }
        }

        Ok(results)
    }
}

#[derive(Debug)]
pub struct MissingSignerCheckRule;

impl MissingSignerCheckRule {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for MissingSignerCheckRule {
    fn name(&self) -> &str {
        "missing_signer_check"
    }

    fn description(&self) -> &str {
        "Detects missing signer validation in instruction handlers"
    }

    fn check(&self, content: &str, _file_path: &Path) -> Result<Vec<RuleResult>> {
        let mut results = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if line.contains("pub fn") && (line.contains("instruction") || line.contains("handler"))
            {
                // Look for the next few lines to see if there's a signer check
                let mut has_signer_check = false;
                for check_line in lines.iter().skip(line_num).take(10) {
                    if check_line.contains("is_signer") || check_line.contains("Signer") {
                        has_signer_check = true;
                        break;
                    }
                }

                if !has_signer_check {
                    results.push(RuleResult {
                        severity: Severity::High,
                        message: "Instruction handler may be missing signer validation".to_string(),
                        line_number: Some(line_num + 1),
                        column: None,
                        code_snippet: Some(line.trim().to_string()),
                        suggestion: Some(
                            "Add signer validation to prevent unauthorized access".to_string(),
                        ),
                    });
                }
            }
        }

        Ok(results)
    }
}

#[derive(Debug)]
pub struct UncheckedAccountRule;

impl UncheckedAccountRule {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for UncheckedAccountRule {
    fn name(&self) -> &str {
        "unchecked_account"
    }

    fn description(&self) -> &str {
        "Detects potentially unchecked account validations"
    }

    fn check(&self, content: &str, _file_path: &Path) -> Result<Vec<RuleResult>> {
        let mut results = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            if line.contains("AccountInfo") && !line.contains("check") {
                // Look for account usage without proper validation
                if line.contains("unchecked") || line.contains("unsafe") {
                    results.push(RuleResult {
                        severity: Severity::Critical,
                        message: "Account used without proper validation checks".to_string(),
                        line_number: Some(line_num + 1),
                        column: None,
                        code_snippet: Some(line.trim().to_string()),
                        suggestion: Some("Add proper account validation before usage".to_string()),
                    });
                }
            }
        }

        Ok(results)
    }
}

#[derive(Debug)]
pub struct ReentrancyRule;

impl ReentrancyRule {
    pub fn new() -> Self {
        Self
    }
}

impl Rule for ReentrancyRule {
    fn name(&self) -> &str {
        "reentrancy"
    }

    fn description(&self) -> &str {
        "Detects potential reentrancy vulnerabilities"
    }

    fn check(&self, content: &str, _file_path: &Path) -> Result<Vec<RuleResult>> {
        let mut results = Vec::new();
        let lines: Vec<&str> = content.lines().collect();

        for (line_num, line) in lines.iter().enumerate() {
            // Look for cross-program invocations
            if line.contains("invoke") || line.contains("invoke_signed") {
                // Check if state changes happen after the invoke
                for check_line in lines.iter().skip(line_num + 1).take(5) {
                    if check_line.contains("=") && !check_line.contains("let") {
                        results.push(RuleResult {
                            severity: Severity::High,
                            message: "Potential reentrancy: state changes after external call"
                                .to_string(),
                            line_number: Some(line_num + 1),
                            column: None,
                            code_snippet: Some(line.trim().to_string()),
                            suggestion: Some(
                                "Move state changes before external calls or use reentrancy guards"
                                    .to_string(),
                            ),
                        });
                        break;
                    }
                }
            }
        }

        Ok(results)
    }
}
