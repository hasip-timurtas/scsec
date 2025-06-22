use anyhow::{Context, Result};
use clap::ValueEnum;
use libloading::{Library, Symbol};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Severity levels for security issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// Result from a security rule check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleResult {
    pub severity: Severity,
    pub message: String,
    pub line_number: Option<usize>,
    pub column: Option<usize>,
    pub code_snippet: Option<String>,
    pub suggestion: Option<String>,
}

/// Trait that all security rules must implement
pub trait Rule: Send + Sync + std::fmt::Debug {
    /// Unique name for the rule
    fn name(&self) -> &str;

    /// Human-readable description of what the rule checks
    fn description(&self) -> &str;

    /// Check the given content and return any issues found
    fn check(&self, content: &str, file_path: &Path) -> Result<Vec<RuleResult>>;

    /// Optional: rule configuration schema
    fn config_schema(&self) -> Option<serde_json::Value> {
        None
    }
}

/// Plugin actions for CLI
#[derive(Debug, Clone, ValueEnum)]
pub enum PluginAction {
    List,
    Load,
    Unload,
}

/// Plugin metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginInfo {
    pub name: String,
    pub version: String,
    pub description: String,
    pub author: String,
    pub rules: Vec<String>,
}

/// Plugin manager for loading and managing custom rules
#[derive(Debug)]
pub struct PluginManager {
    plugins: HashMap<String, PluginHandle>,
    plugin_dir: PathBuf,
}

#[derive(Debug)]
struct PluginHandle {
    #[allow(dead_code)]
    library: Library,
    info: PluginInfo,
    rules: Vec<Box<dyn Rule>>,
}

impl PluginManager {
    pub fn new() -> Result<Self> {
        let plugin_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("scsec")
            .join("plugins");

        // Create plugin directory if it doesn't exist
        if !plugin_dir.exists() {
            fs::create_dir_all(&plugin_dir).with_context(|| {
                format!(
                    "Failed to create plugin directory: {}",
                    plugin_dir.display()
                )
            })?;
        }

        Ok(Self {
            plugins: HashMap::new(),
            plugin_dir,
        })
    }

    pub fn list_plugins(&self) -> Result<Vec<PluginInfo>> {
        let mut plugins = Vec::new();

        // Add loaded plugins
        for handle in self.plugins.values() {
            plugins.push(handle.info.clone());
        }

        // Scan plugin directory for available plugins
        if self.plugin_dir.exists() {
            for entry in fs::read_dir(&self.plugin_dir)? {
                let entry = entry?;
                let path = entry.path();

                if path
                    .extension()
                    .is_some_and(|ext| ext == "so" || ext == "dll" || ext == "dylib")
                {
                    // Try to read plugin metadata without loading
                    if let Ok(info) = self.read_plugin_info(&path) {
                        // Only add if not already loaded
                        if !self.plugins.contains_key(&info.name) {
                            plugins.push(info);
                        }
                    }
                }
            }
        }

        Ok(plugins)
    }

    pub fn load_plugin(&mut self, plugin_path: &Path) -> Result<()> {
        info!("Loading plugin: {}", plugin_path.display());

        unsafe {
            let library = Library::new(plugin_path).with_context(|| {
                format!("Failed to load plugin library: {}", plugin_path.display())
            })?;

            // Get plugin info
            let get_info: Symbol<extern "C" fn() -> PluginInfo> =
                library
                    .get(b"get_plugin_info")
                    .with_context(|| "Plugin missing get_plugin_info function")?;

            let info = get_info();

            // Get plugin rules
            let create_rules: Symbol<extern "C" fn() -> Vec<Box<dyn Rule>>> = library
                .get(b"create_rules")
                .with_context(|| "Plugin missing create_rules function")?;

            let rules = create_rules();

            debug!("Loaded plugin '{}' with {} rules", info.name, rules.len());

            let handle = PluginHandle {
                library,
                info: info.clone(),
                rules,
            };

            self.plugins.insert(info.name.clone(), handle);
        }

        Ok(())
    }

    pub fn unload_plugin(&mut self, plugin_path: &Path) -> Result<()> {
        // Find plugin by path or name
        let plugin_name = if let Ok(info) = self.read_plugin_info(plugin_path) {
            info.name
        } else {
            plugin_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("unknown")
                .to_string()
        };

        if self.plugins.remove(&plugin_name).is_some() {
            info!("Unloaded plugin: {}", plugin_name);
        } else {
            warn!("Plugin not found: {}", plugin_name);
        }

        Ok(())
    }

    pub fn get_all_rules(&self) -> Vec<&dyn Rule> {
        let mut rules = Vec::new();
        for handle in self.plugins.values() {
            for rule in &handle.rules {
                rules.push(rule.as_ref());
            }
        }
        rules
    }

    fn read_plugin_info(&self, plugin_path: &Path) -> Result<PluginInfo> {
        // For now, we'll try to load the plugin temporarily to get info
        // In a real implementation, you might store metadata separately
        unsafe {
            let library = Library::new(plugin_path)?;
            let get_info: Symbol<extern "C" fn() -> PluginInfo> =
                library.get(b"get_plugin_info")?;
            Ok(get_info())
        }
    }
}

/// Example custom rule implementation
#[derive(Debug)]
pub struct ExampleCustomRule;

impl Rule for ExampleCustomRule {
    fn name(&self) -> &str {
        "example_custom_rule"
    }

    fn description(&self) -> &str {
        "An example custom security rule"
    }

    fn check(&self, content: &str, _file_path: &Path) -> Result<Vec<RuleResult>> {
        let mut results = Vec::new();

        // Example: detect usage of unsafe blocks
        for (line_num, line) in content.lines().enumerate() {
            if line.contains("unsafe") {
                results.push(RuleResult {
                    severity: Severity::Medium,
                    message: "Usage of unsafe block detected".to_string(),
                    line_number: Some(line_num + 1),
                    column: None,
                    code_snippet: Some(line.trim().to_string()),
                    suggestion: Some(
                        "Consider if unsafe block is necessary and properly documented".to_string(),
                    ),
                });
            }
        }

        Ok(results)
    }

    fn config_schema(&self) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "ignore_patterns": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Patterns to ignore when checking for unsafe blocks"
                }
            }
        }))
    }
}

// Plugin interface functions that plugins must implement
#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn get_plugin_info() -> PluginInfo {
    PluginInfo {
        name: "example_plugin".to_string(),
        version: "1.0.0".to_string(),
        description: "Example security plugin for scsec".to_string(),
        author: "Hasip Timurtas".to_string(),
        rules: vec!["example_custom_rule".to_string()],
    }
}

#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn create_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(ExampleCustomRule)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_custom_rule() {
        let rule = ExampleCustomRule;
        let content = r#"
            fn safe_function() {
                println!("This is safe");
            }
            
            fn unsafe_function() {
                unsafe {
                    // Some unsafe operation
                }
            }
        "#;

        let results = rule.check(content, Path::new("test.rs")).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].severity, Severity::Medium);
        assert!(results[0].message.contains("unsafe block"));
    }

    #[test]
    fn test_plugin_manager_creation() {
        let manager = PluginManager::new().unwrap();
        assert!(manager.plugin_dir.exists() || manager.plugin_dir.parent().is_some());
    }
}
