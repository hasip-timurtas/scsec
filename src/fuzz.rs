use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use serde::{Deserialize, Serialize};

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tokio::time::{timeout, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub target_name: String,
    pub crashes: Vec<CrashInfo>,
    pub coverage: Option<CoverageInfo>,
    pub execution_time: u64,
    pub total_executions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrashInfo {
    pub crash_type: String,
    pub description: String,
    pub input_hash: String,
    pub stack_trace: Option<String>,
    pub crash_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageInfo {
    pub lines_covered: usize,
    pub total_lines: usize,
    pub coverage_percentage: f64,
    pub uncovered_lines: Vec<usize>,
}

#[derive(Debug)]
pub struct FuzzEngine {
    program_path: PathBuf,
    output_dir: PathBuf,
    targets: Vec<FuzzTarget>,
}

#[derive(Debug, Clone)]
struct FuzzTarget {
    name: String,
    entry_point: String,
    harness_code: String,
}

impl FuzzEngine {
    pub fn new(program_path: PathBuf, output_dir: PathBuf) -> Result<Self> {
        // Create output directory
        if !output_dir.exists() {
            fs::create_dir_all(&output_dir).with_context(|| {
                format!(
                    "Failed to create output directory: {}",
                    output_dir.display()
                )
            })?;
        }

        let mut engine = Self {
            program_path,
            output_dir,
            targets: Vec::new(),
        };

        // Auto-discover fuzz targets
        engine.discover_targets()?;

        Ok(engine)
    }

    pub async fn run_fuzzing(&self, timeout_secs: u64, jobs: usize) -> Result<FuzzResult> {
        info!(
            "Starting fuzzing with {} jobs for {} seconds",
            jobs, timeout_secs
        );

        let mut all_crashes = Vec::new();
        let mut total_executions = 0u64;

        // Install cargo-fuzz if not present
        self.ensure_cargo_fuzz_installed().await?;

        // Initialize fuzz targets
        self.init_fuzz_targets().await?;

        for target in &self.targets {
            info!("Fuzzing target: {}", target.name);

            let target_result = timeout(
                Duration::from_secs(timeout_secs),
                self.run_single_target(target, jobs),
            )
            .await;

            match target_result {
                Ok(Ok(result)) => {
                    all_crashes.extend(result.crashes);
                    total_executions += result.total_executions;
                }
                Ok(Err(e)) => {
                    error!("Error fuzzing target {}: {}", target.name, e);
                }
                Err(_) => {
                    warn!("Fuzzing target {} timed out", target.name);
                }
            }
        }

        let result = FuzzResult {
            target_name: "all".to_string(),
            crashes: all_crashes,
            coverage: self.collect_coverage().await.ok(),
            execution_time: timeout_secs,
            total_executions,
        };

        // Save results
        self.save_results(&result).await?;

        Ok(result)
    }

    fn discover_targets(&mut self) -> Result<()> {
        info!(
            "Discovering fuzz targets in: {}",
            self.program_path.display()
        );

        // Look for IDL files to generate targets from
        if let Ok(idl_content) = self.find_and_read_idl() {
            self.generate_targets_from_idl(&idl_content)?;
        }

        // Look for existing fuzz targets
        let fuzz_dir = self.program_path.join("fuzz");
        if fuzz_dir.exists() {
            self.discover_existing_targets(&fuzz_dir)?;
        }

        // If no targets found, create a basic one
        if self.targets.is_empty() {
            warn!("No fuzz targets found, creating basic target");
            self.create_basic_target()?;
        }

        info!("Discovered {} fuzz targets", self.targets.len());
        Ok(())
    }

    fn find_and_read_idl(&self) -> Result<String> {
        // Look for IDL files in common locations
        let possible_locations = vec![
            self.program_path.join("target").join("idl"),
            self.program_path.join("idl"),
            self.program_path.clone(),
        ];

        for location in possible_locations {
            if let Ok(entries) = fs::read_dir(&location) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().is_some_and(|ext| ext == "json") {
                        if let Ok(content) = fs::read_to_string(&path) {
                            // Basic check if it looks like an IDL
                            if content.contains("instructions") && content.contains("accounts") {
                                debug!("Found IDL file: {}", path.display());
                                return Ok(content);
                            }
                        }
                    }
                }
            }
        }

        Err(anyhow::anyhow!("No IDL file found"))
    }

    fn generate_targets_from_idl(&mut self, idl_content: &str) -> Result<()> {
        // Parse IDL (simplified JSON parsing)
        let idl: serde_json::Value =
            serde_json::from_str(idl_content).with_context(|| "Failed to parse IDL JSON")?;

        if let Some(instructions) = idl.get("instructions").and_then(|i| i.as_array()) {
            for instruction in instructions.iter() {
                if let Some(name) = instruction.get("name").and_then(|n| n.as_str()) {
                    let entry_point = name.to_string();
                    let target = FuzzTarget {
                        name: format!("fuzz_instruction_{}", name),
                        entry_point: entry_point.clone(),
                        harness_code: self
                            .generate_instruction_harness(&entry_point, instruction)?,
                    };
                    self.targets.push(target);
                }
            }
        }

        Ok(())
    }

    fn generate_instruction_harness(
        &self,
        instruction_name: &str,
        _instruction: &serde_json::Value,
    ) -> Result<String> {
        // Generate a basic fuzzing harness for the instruction
        let harness = format!(
            r#"
#![no_main]
use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;

#[derive(Arbitrary, Debug)]
struct FuzzData {{
    // Add instruction-specific fields here
    data: Vec<u8>,
}}

fuzz_target!(|data: FuzzData| {{
    // Initialize program context
    // Call the {} instruction with fuzzed data
    // Handle any panics or errors gracefully
    
    // This is a template - you'll need to implement the actual instruction calls
    let _ = fuzz_instruction_call(&data.data);
}});

fn fuzz_instruction_call(_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {{
    // TODO: Implement actual instruction fuzzing for: {}
    // This would involve:
    // 1. Setting up program context
    // 2. Creating accounts with fuzzed data  
    // 3. Calling the {} instruction
    // 4. Checking for panics/errors
    Ok(())
}}
"#,
            instruction_name, instruction_name, instruction_name
        );

        Ok(harness)
    }

    fn discover_existing_targets(&mut self, fuzz_dir: &Path) -> Result<()> {
        let fuzz_targets_dir = fuzz_dir.join("fuzz_targets");
        if !fuzz_targets_dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(&fuzz_targets_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().is_some_and(|ext| ext == "rs") {
                if let Some(name) = path.file_stem().and_then(|n| n.to_str()) {
                    let content = fs::read_to_string(&path)?;
                    let target = FuzzTarget {
                        name: name.to_string(),
                        entry_point: name.to_string(),
                        harness_code: content,
                    };
                    self.targets.push(target);
                }
            }
        }

        Ok(())
    }

    fn create_basic_target(&mut self) -> Result<()> {
        let basic_harness = r#"
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Basic fuzzing target - customize for your program
    if data.len() < 4 {
        return;
    }
    
    // Add your program-specific fuzzing logic here
    let _ = basic_fuzz_function(data);
});

fn basic_fuzz_function(_data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: Implement basic fuzzing logic
    Ok(())
}
"#;

        let target = FuzzTarget {
            name: "basic_fuzz".to_string(),
            entry_point: "basic_fuzz".to_string(),
            harness_code: basic_harness.to_string(),
        };

        self.targets.push(target);
        Ok(())
    }

    async fn ensure_cargo_fuzz_installed(&self) -> Result<()> {
        debug!("Checking if cargo-fuzz is installed");

        let output = Command::new("cargo").args(["fuzz", "--version"]).output();

        match output {
            Ok(output) if output.status.success() => {
                debug!("cargo-fuzz is already installed");
                Ok(())
            }
            _ => {
                info!("Installing cargo-fuzz...");
                let status = Command::new("cargo")
                    .args(["install", "cargo-fuzz"])
                    .status()
                    .with_context(|| "Failed to run cargo install")?;

                if !status.success() {
                    return Err(anyhow::anyhow!("Failed to install cargo-fuzz"));
                }

                info!("cargo-fuzz installed successfully");
                Ok(())
            }
        }
    }

    async fn init_fuzz_targets(&self) -> Result<()> {
        let fuzz_dir = self.program_path.join("fuzz");

        if !fuzz_dir.exists() {
            info!("Initializing fuzz directory");
            let status = Command::new("cargo")
                .args(["fuzz", "init"])
                .current_dir(&self.program_path)
                .status()
                .with_context(|| "Failed to initialize cargo-fuzz")?;

            if !status.success() {
                return Err(anyhow::anyhow!("Failed to initialize fuzz directory"));
            }
        }

        // Create/update target files
        let targets_dir = fuzz_dir.join("fuzz_targets");
        for target in &self.targets {
            let target_file = targets_dir.join(format!("{}.rs", target.name));
            if !target_file.exists() {
                fs::write(&target_file, &target.harness_code).with_context(|| {
                    format!("Failed to write target file: {}", target_file.display())
                })?;
                debug!("Created fuzz target: {}", target_file.display());
            }
        }

        Ok(())
    }

    async fn run_single_target(&self, target: &FuzzTarget, jobs: usize) -> Result<FuzzResult> {
        info!(
            "Running fuzz target: {} (entry point: {})",
            target.name, target.entry_point
        );

        let output = Command::new("cargo")
            .args([
                "fuzz",
                "run",
                &target.name,
                "--jobs",
                &jobs.to_string(),
                "--",
                "-max_total_time=10", // Run for 10 seconds per target
            ])
            .current_dir(&self.program_path)
            .output()
            .with_context(|| format!("Failed to run fuzz target: {}", target.name))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        debug!("Fuzz output for {}: {}", target.name, stdout);
        if !stderr.is_empty() {
            debug!("Fuzz stderr for {}: {}", target.name, stderr);
        }

        // Parse output for crashes and statistics
        let crashes = self.parse_crashes(&stdout, &stderr)?;
        let executions = self.parse_execution_count(&stdout);

        Ok(FuzzResult {
            target_name: target.name.clone(),
            crashes,
            coverage: None,
            execution_time: 10, // We ran for 10 seconds
            total_executions: executions,
        })
    }

    fn parse_crashes(&self, stdout: &str, stderr: &str) -> Result<Vec<CrashInfo>> {
        let mut crashes = Vec::new();

        // Look for crash indicators in the output
        for line in stdout.lines().chain(stderr.lines()) {
            if line.contains("CRASH") || line.contains("ERROR") || line.contains("ASAN") {
                crashes.push(CrashInfo {
                    crash_type: "Unknown".to_string(),
                    description: line.to_string(),
                    input_hash: "unknown".to_string(),
                    stack_trace: None,
                    crash_file: None,
                });
            }
        }

        Ok(crashes)
    }

    fn parse_execution_count(&self, output: &str) -> u64 {
        // Look for execution count in output
        for line in output.lines() {
            if line.contains("exec/s") {
                // Try to parse execution count (this is simplified)
                return 1000; // Default placeholder
            }
        }
        0
    }

    async fn collect_coverage(&self) -> Result<CoverageInfo> {
        // This would integrate with coverage tools
        // For now, return a placeholder
        Ok(CoverageInfo {
            lines_covered: 0,
            total_lines: 0,
            coverage_percentage: 0.0,
            uncovered_lines: Vec::new(),
        })
    }

    async fn save_results(&self, results: &FuzzResult) -> Result<()> {
        let results_file = self.output_dir.join("fuzz_results.json");
        let json = serde_json::to_string_pretty(results)
            .with_context(|| "Failed to serialize fuzz results")?;

        fs::write(&results_file, json)
            .with_context(|| format!("Failed to write results to: {}", results_file.display()))?;

        info!("Fuzz results saved to: {}", results_file.display());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_fuzz_engine_creation() {
        let temp_dir = tempdir().unwrap();
        let program_path = temp_dir.path().to_path_buf();
        let output_dir = temp_dir.path().join("output");

        let engine = FuzzEngine::new(program_path, output_dir);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_basic_target_generation() {
        let temp_dir = tempdir().unwrap();
        let program_path = temp_dir.path().to_path_buf();
        let output_dir = temp_dir.path().join("output");

        let mut engine = FuzzEngine::new(program_path, output_dir).unwrap();
        engine.create_basic_target().unwrap();

        assert_eq!(engine.targets.len(), 1);
        assert_eq!(engine.targets[0].name, "basic_fuzz");
    }
}
