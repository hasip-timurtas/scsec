use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use handlebars::Handlebars;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::analyzer::AnalysisResult;
use crate::fuzz::FuzzResult;

#[derive(Debug, Clone, ValueEnum, Serialize, Deserialize)]
pub enum ReportFormat {
    Json,
    Html,
    Markdown,
    Csv,
}

impl std::fmt::Display for ReportFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportFormat::Json => write!(f, "json"),
            ReportFormat::Html => write!(f, "html"),
            ReportFormat::Markdown => write!(f, "markdown"),
            ReportFormat::Csv => write!(f, "csv"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub metadata: ReportMetadata,
    pub summary: ReportSummary,
    pub analysis_results: Vec<AnalysisResult>,
    pub fuzz_results: Option<FuzzResult>,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub generated_at: DateTime<Utc>,
    pub solsec_version: String,
    pub scan_target: String,
    pub total_files_scanned: usize,
    pub scan_duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportSummary {
    pub total_issues: usize,
    pub critical_issues: usize,
    pub high_issues: usize,
    pub medium_issues: usize,
    pub low_issues: usize,
    pub issues_by_rule: HashMap<String, usize>,
    pub files_with_issues: Vec<String>,
}

pub struct ReportGenerator {
    handlebars: Handlebars<'static>,
}

impl ReportGenerator {
    pub fn new() -> Self {
        let mut handlebars = Handlebars::new();

        // Register HTML template
        if let Err(e) = handlebars.register_template_string("html_report", HTML_TEMPLATE) {
            panic!("Failed to register HTML template: {}", e);
        }

        // Register Markdown template
        if let Err(e) = handlebars.register_template_string("markdown_report", MARKDOWN_TEMPLATE) {
            panic!("Failed to register Markdown template: {}", e);
        }

        Self { handlebars }
    }

    pub async fn generate_report(
        &self,
        analysis_results: &[AnalysisResult],
        output_path: &Path,
        format: ReportFormat,
    ) -> Result<()> {
        let report = self.build_report(analysis_results, None).await?;
        self.write_report(&report, output_path, format).await
    }

    pub async fn generate_from_directory(
        &self,
        results_dir: &Path,
        output_path: &Path,
        format: ReportFormat,
    ) -> Result<()> {
        info!(
            "Generating report from directory: {}",
            results_dir.display()
        );

        // Load analysis results
        let mut analysis_results = Vec::new();
        let mut fuzz_results = None;

        if results_dir.exists() {
            for entry in fs::read_dir(results_dir)? {
                let entry = entry?;
                let path = entry.path();

                if path.extension().is_some_and(|ext| ext == "json") {
                    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

                    if filename.contains("analysis") || filename.contains("scan") {
                        let content = fs::read_to_string(&path)?;

                        // Try to parse as SecurityReport first (from scan command)
                        if let Ok(security_report) =
                            serde_json::from_str::<SecurityReport>(&content)
                        {
                            analysis_results.extend(security_report.analysis_results);
                        } else {
                            // Fallback to parsing as Vec<AnalysisResult> (legacy format)
                            let results: Vec<AnalysisResult> = serde_json::from_str(&content)
                                .with_context(|| {
                                    format!(
                                        "Failed to parse analysis results from: {}",
                                        path.display()
                                    )
                                })?;
                            analysis_results.extend(results);
                        }
                    } else if filename.contains("fuzz") {
                        let content = fs::read_to_string(&path)?;
                        fuzz_results = Some(serde_json::from_str(&content).with_context(|| {
                            format!("Failed to parse fuzz results from: {}", path.display())
                        })?);
                    }
                }
            }
        }

        let report = self.build_report(&analysis_results, fuzz_results).await?;
        self.write_report(&report, output_path, format).await
    }

    async fn build_report(
        &self,
        analysis_results: &[AnalysisResult],
        fuzz_results: Option<FuzzResult>,
    ) -> Result<SecurityReport> {
        let metadata = ReportMetadata {
            generated_at: Utc::now(),
            solsec_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_target: "N/A".to_string(), // This would be filled from context
            total_files_scanned: self.count_unique_files(analysis_results),
            scan_duration_ms: 0, // This would be tracked during scanning
        };

        let summary = self.build_summary(analysis_results);
        let recommendations = self.generate_recommendations(analysis_results);

        Ok(SecurityReport {
            metadata,
            summary,
            analysis_results: analysis_results.to_vec(),
            fuzz_results,
            recommendations,
        })
    }

    fn count_unique_files(&self, results: &[AnalysisResult]) -> usize {
        use std::collections::HashSet;
        let mut files = HashSet::new();
        for result in results {
            files.insert(&result.file_path);
        }
        files.len()
    }

    fn build_summary(&self, results: &[AnalysisResult]) -> ReportSummary {
        let mut issues_by_rule = HashMap::new();
        let mut files_with_issues = std::collections::HashSet::new();

        let mut critical_count = 0;
        let mut high_count = 0;
        let mut medium_count = 0;
        let mut low_count = 0;

        for result in results {
            // Count by severity
            match result.severity.as_str() {
                "critical" => critical_count += 1,
                "high" => high_count += 1,
                "medium" => medium_count += 1,
                "low" => low_count += 1,
                _ => {}
            }

            // Count by rule
            *issues_by_rule.entry(result.rule_name.clone()).or_insert(0) += 1;

            // Track files with issues
            files_with_issues.insert(result.file_path.clone());
        }

        ReportSummary {
            total_issues: results.len(),
            critical_issues: critical_count,
            high_issues: high_count,
            medium_issues: medium_count,
            low_issues: low_count,
            issues_by_rule,
            files_with_issues: files_with_issues.into_iter().collect(),
        }
    }

    fn generate_recommendations(&self, results: &[AnalysisResult]) -> Vec<String> {
        let mut recommendations = Vec::new();

        if results.is_empty() {
            recommendations
                .push("Great! No security issues found in the static analysis.".to_string());
            recommendations
                .push("Consider running fuzz testing for more thorough coverage.".to_string());
            return recommendations;
        }

        // Count issues by severity
        let critical_count = results.iter().filter(|r| r.severity == "critical").count();
        let high_count = results.iter().filter(|r| r.severity == "high").count();

        if critical_count > 0 {
            recommendations.push(format!("🚨 URGENT: {} critical security issues found. Address these immediately before deployment.", critical_count));
        }

        if high_count > 0 {
            recommendations.push(format!(
                "⚠️  {} high-severity issues require attention.",
                high_count
            ));
        }

        // Rule-specific recommendations
        let mut rule_counts = HashMap::new();
        for result in results {
            *rule_counts.entry(&result.rule_name).or_insert(0) += 1;
        }

        for (rule, count) in rule_counts {
            match rule.as_str() {
                "integer_overflow" => {
                    recommendations.push(format!("Consider using checked arithmetic operations for {} overflow-prone locations.", count));
                }
                "missing_signer_check" => {
                    recommendations.push(format!(
                        "Add signer validation to {} instruction handlers.",
                        count
                    ));
                }
                "unchecked_account" => {
                    recommendations.push(format!(
                        "Implement proper account validation for {} locations.",
                        count
                    ));
                }
                "reentrancy" => {
                    recommendations.push(format!(
                        "Review {} potential reentrancy vulnerabilities and implement guards.",
                        count
                    ));
                }
                _ => {}
            }
        }

        if recommendations.is_empty() {
            recommendations
                .push("Review the identified issues and apply the suggested fixes.".to_string());
        }

        recommendations.push(
            "Run tests after fixing issues to ensure functionality is preserved.".to_string(),
        );
        recommendations
            .push("Consider setting up CI/CD integration to catch issues early.".to_string());

        recommendations
    }

    async fn write_report(
        &self,
        report: &SecurityReport,
        output_path: &Path,
        format: ReportFormat,
    ) -> Result<()> {
        let content = match format {
            ReportFormat::Json => self.generate_json_report(report)?,
            ReportFormat::Html => self.generate_html_report(report)?,
            ReportFormat::Markdown => self.generate_markdown_report(report)?,
            ReportFormat::Csv => self.generate_csv_report(report)?,
        };

        // Ensure output directory exists
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create output directory: {}", parent.display())
            })?;
        }

        fs::write(output_path, content)
            .with_context(|| format!("Failed to write report to: {}", output_path.display()))?;

        info!("Report generated: {}", output_path.display());
        Ok(())
    }

    fn generate_json_report(&self, report: &SecurityReport) -> Result<String> {
        serde_json::to_string_pretty(report).with_context(|| "Failed to serialize report to JSON")
    }

    fn generate_html_report(&self, report: &SecurityReport) -> Result<String> {
        self.handlebars
            .render("html_report", report)
            .with_context(|| "Failed to render HTML report")
    }

    fn generate_markdown_report(&self, report: &SecurityReport) -> Result<String> {
        self.handlebars
            .render("markdown_report", report)
            .with_context(|| "Failed to render Markdown report")
    }

    fn generate_csv_report(&self, report: &SecurityReport) -> Result<String> {
        let mut csv = String::new();
        csv.push_str("File,Rule,Severity,Line,Message,Suggestion\n");

        for result in &report.analysis_results {
            csv.push_str(&format!(
                "\"{}\",\"{}\",\"{}\",{},\"{}\",\"{}\"\n",
                result.file_path,
                result.rule_name,
                result.severity,
                result.line_number.map_or(String::new(), |n| n.to_string()),
                result.message.replace('"', "\"\""),
                result
                    .suggestion
                    .as_ref()
                    .map_or("", |s| s)
                    .replace('"', "\"\"")
            ));
        }

        Ok(csv)
    }
}

const HTML_TEMPLATE: &str = r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Solana Security Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
        .content { padding: 30px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-number { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
        .critical { color: #dc3545; }
        .high { color: #fd7e14; }
        .medium { color: #ffc107; }
        .low { color: #28a745; }
        .issue { border-left: 4px solid #dee2e6; margin: 10px 0; padding: 15px; background: #f8f9fa; border-radius: 4px; }
        .issue.critical { border-left-color: #dc3545; }
        .issue.high { border-left-color: #fd7e14; }
        .issue.medium { border-left-color: #ffc107; }
        .issue.low { border-left-color: #28a745; }
        .code { background: #f1f3f4; padding: 10px; border-radius: 4px; font-family: monospace; margin: 10px 0; }
        .recommendations { background: #e3f2fd; padding: 20px; border-radius: 8px; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Solana Security Report</h1>
            <p>Generated on {{metadata.generated_at}} by solsec v{{metadata.solsec_version}}</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <div class="stat-card">
                    <div class="stat-number">{{summary.total_issues}}</div>
                    <div>Total Issues</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number critical">{{summary.critical_issues}}</div>
                    <div>Critical</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number high">{{summary.high_issues}}</div>
                    <div>High</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number medium">{{summary.medium_issues}}</div>
                    <div>Medium</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number low">{{summary.low_issues}}</div>
                    <div>Low</div>
                </div>
            </div>

            {{#if analysis_results}}
            <h2>Security Issues</h2>
            {{#each analysis_results}}
            <div class="issue {{severity}}">
                <h3>{{rule_name}}</h3>
                <p><strong>File:</strong> {{file_path}} {{#if line_number}}(Line {{line_number}}){{/if}}</p>
                <p><strong>Severity:</strong> {{severity}}</p>
                <p>{{message}}</p>
                {{#if code_snippet}}
                <div class="code">{{code_snippet}}</div>
                {{/if}}
                {{#if suggestion}}
                <p><strong>Suggestion:</strong> {{suggestion}}</p>
                {{/if}}
            </div>
            {{/each}}
            {{/if}}

            <div class="recommendations">
                <h2>📋 Recommendations</h2>
                <ul>
                {{#each recommendations}}
                    <li>{{this}}</li>
                {{/each}}
                </ul>
            </div>
        </div>
    </div>
</body>
</html>
"#;

const MARKDOWN_TEMPLATE: &str = r#"
# 🛡️ Solana Security Report

**Generated:** {{metadata.generated_at}}  
**Tool Version:** solsec v{{metadata.solsec_version}}  
**Files Scanned:** {{metadata.total_files_scanned}}

## Summary

| Severity | Count |
|----------|-------|
| Critical | {{summary.critical_issues}} |
| High     | {{summary.high_issues}} |
| Medium   | {{summary.medium_issues}} |
| Low      | {{summary.low_issues}} |
| **Total** | **{{summary.total_issues}}** |

{{#if analysis_results}}
## Security Issues

{{#each analysis_results}}
### {{rule_name}} - {{severity}}

**File:** `{{file_path}}`{{#if line_number}} (Line {{line_number}}){{/if}}

{{message}}

{{#if code_snippet}}
```rust
{{code_snippet}}
```
{{/if}}

{{#if suggestion}}
**💡 Suggestion:** {{suggestion}}
{{/if}}

---
{{/each}}
{{/if}}

## Recommendations

{{#each recommendations}}
- {{this}}
{{/each}}

---
*Report generated by [solsec](https://github.com/hasip-timurtas/solsec)*
"#;

impl Default for ReportGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_report_generator_creation() {
        let generator = ReportGenerator::new();
        // Just test that it creates without panicking
        assert!(generator.handlebars.get_template("html_report").is_some());
    }

    #[test]
    fn test_summary_building() {
        let generator = ReportGenerator::new();
        let results = vec![AnalysisResult {
            rule_name: "test_rule".to_string(),
            severity: "critical".to_string(),
            message: "Test message".to_string(),
            file_path: "test.rs".to_string(),
            line_number: Some(10),
            column: None,
            code_snippet: None,
            suggestion: None,
        }];

        let summary = generator.build_summary(&results);
        assert_eq!(summary.total_issues, 1);
        assert_eq!(summary.critical_issues, 1);
        assert_eq!(summary.high_issues, 0);
    }
}
