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

#[derive(Debug, Clone, PartialEq, ValueEnum, Serialize, Deserialize)]
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

        // Register the 'eq' helper for string comparisons
        handlebars.register_helper(
            "eq",
            Box::new(
                |h: &handlebars::Helper,
                 _: &handlebars::Handlebars,
                 _: &handlebars::Context,
                 _: &mut handlebars::RenderContext,
                 out: &mut dyn handlebars::Output|
                 -> handlebars::HelperResult {
                    let param1 = h.param(0).and_then(|v| v.value().as_str()).unwrap_or("");
                    let param2 = h.param(1).and_then(|v| v.value().as_str()).unwrap_or("");
                    if param1 == param2 {
                        out.write("true")?;
                    }
                    Ok(())
                },
            ),
        );

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
        // Create a copy of the report with sorted analysis results
        let mut sorted_report = report.clone();

        // Sort by severity: Critical > High > Medium > Low
        sorted_report.analysis_results.sort_by(|a, b| {
            let severity_order = |s: &str| match s {
                "critical" => 0,
                "high" => 1,
                "medium" => 2,
                "low" => 3,
                _ => 4,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        self.handlebars
            .render("html_report", &sorted_report)
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
        .stat-card { 
            background: #f8f9fa; 
            padding: 20px; 
            border-radius: 8px; 
            text-align: center; 
            cursor: pointer; 
            transition: all 0.3s ease; 
            border: 2px solid transparent;
        }
        .stat-card:hover { 
            background: #e9ecef; 
            transform: translateY(-2px); 
            box-shadow: 0 4px 12px rgba(0,0,0,0.15); 
        }
        .stat-card.clickable:hover { 
            border-color: #007bff; 
        }
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
        .code { background: #f1f3f4; padding: 10px; border-radius: 4px; font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; margin: 10px 0; }
        .recommendations { background: #e3f2fd; padding: 20px; border-radius: 8px; margin-top: 30px; }
        
        /* Severity Section Styles */
        .severity-section { 
            margin: 30px 0; 
            padding: 20px; 
            border-radius: 8px; 
            background: #fafbfc; 
            border: 1px solid #e9ecef; 
        }
        .severity-header { 
            font-size: 1.4em; 
            font-weight: 600; 
            margin-bottom: 20px; 
            padding: 15px; 
            border-radius: 6px; 
            background: #ffffff; 
            border-left: 4px solid; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .severity-header.critical { 
            border-left-color: #dc3545; 
            background: linear-gradient(90deg, #fff5f5 0%, #ffffff 100%); 
        }
        .severity-header.high { 
            border-left-color: #fd7e14; 
            background: linear-gradient(90deg, #fff7ed 0%, #ffffff 100%); 
        }
        .severity-header.medium { 
            border-left-color: #ffc107; 
            background: linear-gradient(90deg, #fffbf0 0%, #ffffff 100%); 
        }
        .severity-header.low { 
            border-left-color: #28a745; 
            background: linear-gradient(90deg, #f0fff4 0%, #ffffff 100%); 
        }
        .severity-badge { 
            display: inline-block; 
            padding: 4px 8px; 
            border-radius: 4px; 
            font-size: 0.85em; 
            font-weight: 600; 
            text-transform: uppercase; 
            color: white; 
        }
        .severity-badge.critical { 
            background: #dc3545; 
        }
        .severity-badge.high { 
            background: #fd7e14; 
        }
        .severity-badge.medium { 
            background: #ffc107; 
            color: #212529; 
        }
        .severity-badge.low { 
            background: #28a745; 
        }
        
        /* Enhanced Suggestion Styling */
        .suggestion-container { 
            background: #f8f9fb; 
            border: 1px solid #e9ecef; 
            border-radius: 8px; 
            padding: 16px; 
            margin: 12px 0; 
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .suggestion-header { 
            display: flex; 
            align-items: center; 
            margin-bottom: 12px; 
            font-weight: 600; 
            color: #495057;
        }
        .suggestion-icon { 
            margin-right: 8px; 
            font-size: 1.2em; 
        }
        .suggestion-content { 
            line-height: 1.6; 
        }
        .suggestion-option { 
            background: #ffffff; 
            border: 1px solid #dee2e6; 
            border-radius: 6px; 
            padding: 12px; 
            margin: 8px 0; 
            box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        }
        .suggestion-option-title { 
            font-weight: 600; 
            color: #28a745; 
            margin-bottom: 8px; 
            display: flex;
            align-items: center;
        }
        .option-number { 
            background: #28a745; 
            color: white; 
            border-radius: 50%; 
            width: 20px; 
            height: 20px; 
            display: inline-flex; 
            align-items: center; 
            justify-content: center; 
            font-size: 0.8em; 
            margin-right: 8px; 
        }
        .before-after { 
            display: grid; 
            grid-template-columns: 1fr 1fr; 
            gap: 12px; 
            margin: 12px 0; 
        }
        .before-after-item { 
            background: #f8f9fa; 
            border-radius: 4px; 
            padding: 8px 12px; 
        }
        .before-after-label { 
            font-size: 0.85em; 
            font-weight: 600; 
            margin-bottom: 4px; 
            text-transform: uppercase; 
            letter-spacing: 0.5px; 
        }
        .before-label { 
            color: #dc3545; 
        }
        .after-label { 
            color: #28a745; 
        }
        .code-example { 
            background: #f8f9fa; 
            border: 1px solid #e9ecef; 
            border-radius: 4px; 
            padding: 8px 12px; 
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace; 
            font-size: 0.9em; 
            color: #495057; 
            overflow-x: auto;
        }
        .simple-suggestion { 
            background: #e7f3ff; 
            border-left: 4px solid #007bff; 
            padding: 12px; 
            border-radius: 4px; 
            font-style: italic; 
        }
        
        @media (max-width: 768px) { 
            .before-after { 
                grid-template-columns: 1fr; 
            } 
        }
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
                <div class="stat-card" onclick="scrollToSection('all-issues')">
                    <div class="stat-number">{{summary.total_issues}}</div>
                    <div>Total Issues</div>
                </div>
                <div class="stat-card clickable" onclick="scrollToSection('critical-issues')" {{#unless summary.critical_issues}}style="opacity: 0.5; cursor: default;"{{/unless}}>
                    <div class="stat-number critical">{{summary.critical_issues}}</div>
                    <div>Critical</div>
                </div>
                <div class="stat-card clickable" onclick="scrollToSection('high-issues')" {{#unless summary.high_issues}}style="opacity: 0.5; cursor: default;"{{/unless}}>
                    <div class="stat-number high">{{summary.high_issues}}</div>
                    <div>High</div>
                </div>
                <div class="stat-card clickable" onclick="scrollToSection('medium-issues')" {{#unless summary.medium_issues}}style="opacity: 0.5; cursor: default;"{{/unless}}>
                    <div class="stat-number medium">{{summary.medium_issues}}</div>
                    <div>Medium</div>
                </div>
                <div class="stat-card clickable" onclick="scrollToSection('low-issues')" {{#unless summary.low_issues}}style="opacity: 0.5; cursor: default;"{{/unless}}>
                    <div class="stat-number low">{{summary.low_issues}}</div>
                    <div>Low</div>
                </div>
            </div>

            {{#if analysis_results}}
            <h2 id="all-issues">🔍 Security Issues</h2>
            
            <!-- Critical Issues Section -->
            {{#if summary.critical_issues}}
            <div id="critical-issues" class="severity-section">
                <h3 class="severity-header critical">🚨 Critical Issues ({{summary.critical_issues}})</h3>
                {{#each analysis_results}}
                {{#if (eq severity "critical")}}
                <div class="issue {{severity}}">
                    <h4>{{rule_name}}</h4>
                    <p><strong>File:</strong> {{file_path}} {{#if line_number}}(Line {{line_number}}){{/if}}</p>
                    <p><strong>Severity:</strong> <span class="severity-badge critical">{{severity}}</span></p>
                    <p>{{message}}</p>
                    {{#if code_snippet}}
                    <div class="code">{{code_snippet}}</div>
                    {{/if}}
                    {{#if suggestion}}
                    <div class="suggestion-container">
                        <div class="suggestion-header">
                            <span class="suggestion-icon">💡</span>
                            <span>Suggested Fix</span>
                        </div>
                        <div class="suggestion-content">
                            <div id="suggestion-{{@index}}" class="suggestion-text">{{suggestion}}</div>
                        </div>
                    </div>
                    {{/if}}
                </div>
                {{/if}}
                {{/each}}
            </div>
            {{/if}}
            
            <!-- High Issues Section -->
            {{#if summary.high_issues}}
            <div id="high-issues" class="severity-section">
                <h3 class="severity-header high">⚠️ High Severity Issues ({{summary.high_issues}})</h3>
                {{#each analysis_results}}
                {{#if (eq severity "high")}}
                <div class="issue {{severity}}">
                    <h4>{{rule_name}}</h4>
                    <p><strong>File:</strong> {{file_path}} {{#if line_number}}(Line {{line_number}}){{/if}}</p>
                    <p><strong>Severity:</strong> <span class="severity-badge high">{{severity}}</span></p>
                    <p>{{message}}</p>
                    {{#if code_snippet}}
                    <div class="code">{{code_snippet}}</div>
                    {{/if}}
                    {{#if suggestion}}
                    <div class="suggestion-container">
                        <div class="suggestion-header">
                            <span class="suggestion-icon">💡</span>
                            <span>Suggested Fix</span>
                        </div>
                        <div class="suggestion-content">
                            <div id="suggestion-{{@index}}" class="suggestion-text">{{suggestion}}</div>
                        </div>
                    </div>
                    {{/if}}
                </div>
                {{/if}}
                {{/each}}
            </div>
            {{/if}}
            
            <!-- Medium Issues Section -->
            {{#if summary.medium_issues}}
            <div id="medium-issues" class="severity-section">
                <h3 class="severity-header medium">🔶 Medium Severity Issues ({{summary.medium_issues}})</h3>
                {{#each analysis_results}}
                {{#if (eq severity "medium")}}
                <div class="issue {{severity}}">
                    <h4>{{rule_name}}</h4>
                    <p><strong>File:</strong> {{file_path}} {{#if line_number}}(Line {{line_number}}){{/if}}</p>
                    <p><strong>Severity:</strong> <span class="severity-badge medium">{{severity}}</span></p>
                    <p>{{message}}</p>
                    {{#if code_snippet}}
                    <div class="code">{{code_snippet}}</div>
                    {{/if}}
                    {{#if suggestion}}
                    <div class="suggestion-container">
                        <div class="suggestion-header">
                            <span class="suggestion-icon">💡</span>
                            <span>Suggested Fix</span>
                        </div>
                        <div class="suggestion-content">
                            <div id="suggestion-{{@index}}" class="suggestion-text">{{suggestion}}</div>
                        </div>
                    </div>
                    {{/if}}
                </div>
                {{/if}}
                {{/each}}
            </div>
            {{/if}}
            
            <!-- Low Issues Section -->
            {{#if summary.low_issues}}
            <div id="low-issues" class="severity-section">
                <h3 class="severity-header low">🔵 Low Severity Issues ({{summary.low_issues}})</h3>
                {{#each analysis_results}}
                {{#if (eq severity "low")}}
                <div class="issue {{severity}}">
                    <h4>{{rule_name}}</h4>
                    <p><strong>File:</strong> {{file_path}} {{#if line_number}}(Line {{line_number}}){{/if}}</p>
                    <p><strong>Severity:</strong> <span class="severity-badge low">{{severity}}</span></p>
                    <p>{{message}}</p>
                    {{#if code_snippet}}
                    <div class="code">{{code_snippet}}</div>
                    {{/if}}
                    {{#if suggestion}}
                    <div class="suggestion-container">
                        <div class="suggestion-header">
                            <span class="suggestion-icon">💡</span>
                            <span>Suggested Fix</span>
                        </div>
                        <div class="suggestion-content">
                            <div id="suggestion-{{@index}}" class="suggestion-text">{{suggestion}}</div>
                        </div>
                    </div>
                    {{/if}}
                </div>
                {{/if}}
                {{/each}}
            </div>
            {{/if}}
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
    
    <script>
        // Smooth scrolling function for navigation
        function scrollToSection(sectionId) {
            const element = document.getElementById(sectionId);
            if (element) {
                element.scrollIntoView({ 
                    behavior: 'smooth', 
                    block: 'start',
                    inline: 'nearest'
                });
                // Add a subtle highlight effect
                element.style.boxShadow = '0 0 20px rgba(0,123,255,0.3)';
                setTimeout(() => {
                    element.style.boxShadow = '';
                }, 2000);
            }
        }

        // Enhanced suggestion formatting
        document.addEventListener('DOMContentLoaded', function() {
            document.querySelectorAll('.suggestion-text').forEach(function(element) {
                const text = element.textContent;
                
                // Check if it's a multi-option suggestion
                if (text.includes('Option 1') || text.includes('Before:') || text.includes('After:')) {
                    element.innerHTML = formatEnhancedSuggestion(text);
                } else {
                    // Simple suggestion
                    element.innerHTML = '<div class="simple-suggestion">' + text + '</div>';
                }
            });
        });
        
        function formatEnhancedSuggestion(text) {
            let html = '';
            
            // Handle before/after patterns
            if (text.includes('Before:') && text.includes('After:')) {
                const lines = text.split('\n');
                let beforeLine = '';
                let afterLine = '';
                
                for (let line of lines) {
                    if (line.trim().startsWith('Before:')) {
                        beforeLine = line.replace('Before:', '').trim();
                    } else if (line.trim().startsWith('After:')) {
                        afterLine = line.replace('After:', '').trim();
                    }
                }
                
                if (beforeLine && afterLine) {
                    html += '<div class="before-after">';
                    html += '<div class="before-after-item">';
                    html += '<div class="before-after-label before-label">Before</div>';
                    html += '<div class="code-example">' + escapeHtml(beforeLine) + '</div>';
                    html += '</div>';
                    html += '<div class="before-after-item">';
                    html += '<div class="before-after-label after-label">After</div>';
                    html += '<div class="code-example">' + escapeHtml(afterLine) + '</div>';
                    html += '</div>';
                    html += '</div>';
                    return html;
                }
            }
            
            // Handle multi-option patterns
            if (text.includes('Option 1') || text.includes('Option 2') || text.includes('Option 3')) {
                const sections = text.split(/Option \d+/);
                const header = sections[0].trim();
                
                if (header) {
                    html += '<p>' + escapeHtml(header) + '</p>';
                }
                
                let optionNumber = 1;
                for (let i = 1; i < sections.length; i++) {
                    const optionText = sections[i].trim();
                    if (optionText) {
                        const lines = optionText.split('\n');
                        const title = lines[0].replace(/^[\s\-]+/, '').trim();
                        const codeLines = lines.slice(1).filter(line => line.trim());
                        
                        html += '<div class="suggestion-option">';
                        html += '<div class="suggestion-option-title">';
                        html += '<span class="option-number">' + optionNumber + '</span>';
                        html += escapeHtml(title);
                        html += '</div>';
                        
                        if (codeLines.length > 0) {
                            html += '<div class="code-example">';
                            html += escapeHtml(codeLines.join('\n'));
                            html += '</div>';
                        }
                        
                        html += '</div>';
                        optionNumber++;
                    }
                }
                
                return html;
            }
            
            // Fallback for other patterns
            return '<div class="simple-suggestion">' + escapeHtml(text) + '</div>';
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
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
