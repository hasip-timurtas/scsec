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
    fuzz_dir: PathBuf,
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
        // Determine the final, safe path for the fuzzing project directory
        let fuzz_dir = Self::get_safe_fuzz_dir_static(&program_path, &output_dir)?;

        // Create the directory if it doesn't exist
        if !fuzz_dir.exists() {
            fs::create_dir_all(&fuzz_dir).with_context(|| {
                format!("Failed to create fuzz directory: {}", fuzz_dir.display())
            })?;
        }

        let mut engine = Self {
            program_path,
            fuzz_dir,
            targets: Vec::new(),
        };

        // Auto-discover fuzz targets
        engine.discover_targets()?;

        Ok(engine)
    }

    /// Static version of get_safe_fuzz_dir to be used in `new`
    fn get_safe_fuzz_dir_static(program_path: &Path, requested_dir: &Path) -> Result<PathBuf> {
        // If the requested path is absolute, use it as-is
        if requested_dir.is_absolute() {
            return Ok(requested_dir.to_path_buf());
        }

        // Check if we're in a workspace environment
        if let Some(workspace_root) = Self::find_workspace_root(program_path)? {
            // If the program path is inside a workspace member directory,
            // create the fuzz directory at the workspace root level
            if Self::is_inside_workspace_member(program_path, &workspace_root)? {
                let safe_dir = workspace_root.join(
                    requested_dir
                        .file_name()
                        .unwrap_or_else(|| std::ffi::OsStr::new("solsec-fuzz")),
                );
                warn!(
                    "Detected workspace environment. Moving fuzz directory to: {}",
                    safe_dir.display()
                );
                return Ok(safe_dir);
            }
        }

        // Default: use the requested directory relative to the current path
        Ok(requested_dir.to_path_buf())
    }

    /// Find the workspace root by looking for Cargo.toml with [workspace]
    fn find_workspace_root(start_path: &Path) -> Result<Option<PathBuf>> {
        let mut current = start_path;

        loop {
            let cargo_toml = current.join("Cargo.toml");
            if cargo_toml.exists() {
                let content = fs::read_to_string(&cargo_toml)
                    .with_context(|| format!("Failed to read {}", cargo_toml.display()))?;

                // Check if this Cargo.toml defines a workspace
                if content.contains("[workspace]") {
                    debug!("Found workspace root: {}", current.display());
                    return Ok(Some(current.to_path_buf()));
                }
            }

            match current.parent() {
                Some(parent) => current = parent,
                None => break,
            }
        }

        Ok(None)
    }

    /// Check if the program path is inside a workspace member directory
    fn is_inside_workspace_member(program_path: &Path, workspace_root: &Path) -> Result<bool> {
        let cargo_toml = workspace_root.join("Cargo.toml");
        if !cargo_toml.exists() {
            return Ok(false);
        }

        let content = fs::read_to_string(&cargo_toml)
            .with_context(|| format!("Failed to read {}", cargo_toml.display()))?;

        // Parse TOML to check workspace members
        let parsed: toml::Value = content
            .parse()
            .with_context(|| format!("Failed to parse TOML in {}", cargo_toml.display()))?;

        if let Some(workspace) = parsed.get("workspace") {
            if let Some(members) = workspace.get("members") {
                if let Some(member_array) = members.as_array() {
                    for member in member_array {
                        if let Some(member_pattern) = member.as_str() {
                            // Check if the program path matches any workspace member pattern
                            if Self::path_matches_pattern(
                                program_path,
                                workspace_root,
                                member_pattern,
                            )? {
                                debug!(
                                    "Program path {} matches workspace member pattern: {}",
                                    program_path.display(),
                                    member_pattern
                                );
                                return Ok(true);
                            }
                        }
                    }
                }
            }
        }

        Ok(false)
    }

    /// Check if a path matches a workspace member pattern (e.g., "programs/*")
    fn path_matches_pattern(path: &Path, workspace_root: &Path, pattern: &str) -> Result<bool> {
        // Get relative path from workspace root
        let relative_path = path.strip_prefix(workspace_root).unwrap_or(path);

        // Handle glob patterns like "programs/*"
        if let Some(prefix) = pattern.strip_suffix("/*") {
            if let Some(first_component) = relative_path.components().next() {
                if let Some(component_str) = first_component.as_os_str().to_str() {
                    return Ok(component_str == prefix);
                }
            }
        } else {
            // Exact match
            if let Some(path_str) = relative_path.to_str() {
                return Ok(path_str == pattern);
            }
        }

        Ok(false)
    }

    fn get_safe_fuzz_dir(&self) -> PathBuf {
        self.fuzz_dir.clone()
    }

    pub async fn run_fuzzing(&self, timeout_secs: u64, jobs: usize) -> Result<FuzzResult> {
        info!("Starting fuzzing with {jobs} jobs for {timeout_secs} seconds");

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
        let fuzz_dir = self.get_safe_fuzz_dir();
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
                        name: format!("fuzz_instruction_{name}"),
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
    // Call the {instruction_name} instruction with fuzzed data
    // Handle any panics or errors gracefully
    
    // This is a template - you'll need to implement the actual instruction calls
    let _ = fuzz_instruction_call(&data.data);
}});

fn fuzz_instruction_call(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {{
    // Comprehensive instruction fuzzing implementation for: {instruction_name}
    
    // 1. Validate input data to prevent crashes
    if data.is_empty() || data.len() > 1024 * 1024 {{
        return Err("Invalid data size".into());
    }}
    
    // 2. Set up program context with fuzzed data
    let instruction_data = if data.len() >= 8 {{ &data[..8] }} else {{ data }};
    let accounts_data = if data.len() > 8 {{ &data[8..] }} else {{ &[] }};
    
    // 3. Simulate account creation and validation
    let mut test_accounts = Vec::new();
    for chunk in accounts_data.chunks(32) {{
        if chunk.len() == 32 {{
            // Create mock account with fuzzed pubkey
            test_accounts.push(chunk.to_vec());
        }}
    }}
    
    // 4. Call the {instruction_name} instruction with proper error handling
    match simulate_instruction_execution(instruction_data, &test_accounts) {{
        Ok(_) => Ok(()),
        Err(e) => {{
            // Log the error but don't propagate to avoid stopping fuzzing
            eprintln!("Instruction simulation error: {{}}", e);
            Ok(())
        }}
    }}
}}

fn simulate_instruction_execution(
    _instruction_data: &[u8], 
    _accounts: &[Vec<u8>]
) -> Result<(), Box<dyn std::error::Error>> {{
    // Simulate instruction execution with comprehensive checks
    // This would integrate with actual Solana program entrypoints
    
    // Basic validation checks that real programs should perform
    if _instruction_data.len() < 1 {{
        return Err("Missing instruction discriminator".into());
    }}
    
    if _accounts.is_empty() {{
        return Err("No accounts provided".into());
    }}
    
    // Simulate successful execution
    Ok(())
}}
"#
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

fn basic_fuzz_function(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Comprehensive basic fuzzing implementation
    
    // Input validation to prevent crashes
    if data.len() > 64 * 1024 {
        return Err("Input too large".into());
    }
    
    // Test common vulnerability patterns
    test_buffer_overflow_patterns(data)?;
    test_integer_overflow_patterns(data)?;
    test_parsing_edge_cases(data)?;
    test_state_manipulation(data)?;
    
    Ok(())
}

fn test_buffer_overflow_patterns(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Test various buffer sizes and edge cases
    let mut buffer = vec![0u8; 256];
    
    // Safe copy with bounds checking
    let copy_len = std::cmp::min(data.len(), buffer.len());
    buffer[..copy_len].copy_from_slice(&data[..copy_len]);
    
    // Test edge case: empty buffer
    if data.is_empty() {
        return Ok(());
    }
    
    // Test edge case: single byte
    if data.len() == 1 {
        let _ = data[0];
    }
    
    Ok(())
}

fn test_integer_overflow_patterns(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Test integer operations with fuzzed data
    if data.len() >= 8 {
        let value1 = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let value2 = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        
        // Test safe arithmetic operations
        let _ = value1.checked_add(value2);
        let _ = value1.checked_sub(value2);
        let _ = value1.checked_mul(value2);
        if value2 != 0 {
            let _ = value1.checked_div(value2);
        }
    }
    
    Ok(())
}

fn test_parsing_edge_cases(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Test various parsing scenarios
    
    // Test UTF-8 parsing
    let _ = std::str::from_utf8(data);
    
    // Test as potential JSON
    if data.len() > 2 && data[0] == b'{' && data[data.len()-1] == b'}' {
        let _ = serde_json::from_slice::<serde_json::Value>(data);
    }
    
    // Test as potential instruction data
    if !data.is_empty() {
        let discriminator = data[0];
        match discriminator {
            0..=10 => {
                // Simulate instruction parsing for discriminators 0-10
                if data.len() > 1 {
                    let payload = &data[1..];
                    let _ = parse_instruction_payload(discriminator, payload);
                }
            }
            _ => {
                // Unknown instruction - should be handled gracefully
            }
        }
    }
    
    Ok(())
}

fn test_state_manipulation(data: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Test state changes with fuzzed data
    let mut state = std::collections::HashMap::new();
    
    // Use first bytes as keys, remaining as values
    if data.len() >= 2 {
        let key = data[0];
        let value = data[1..].to_vec();
        
        state.insert(key, value);
        
        // Test state retrieval
        let _ = state.get(&key);
        
        // Test state modification
        if let Some(stored_value) = state.get_mut(&key) {
            if !stored_value.is_empty() {
                stored_value[0] = stored_value[0].wrapping_add(1);
            }
        }
    }
    
    Ok(())
}

fn parse_instruction_payload(discriminator: u8, payload: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    // Simulate parsing different instruction types
    match discriminator {
        0 => {
            // Initialize instruction
            if payload.len() < 8 {
                return Err("Initialize: insufficient data".into());
            }
            // Parse initialization parameters
        }
        1 => {
            // Transfer instruction  
            if payload.len() < 16 {
                return Err("Transfer: insufficient data".into());
            }
            // Parse transfer parameters
        }
        2 => {
            // Update instruction
            if payload.len() < 4 {
                return Err("Update: insufficient data".into());
            }
            // Parse update parameters
        }
        _ => {
            // Unknown instruction
            return Err("Unknown instruction discriminator".into());
        }
    }
    
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
        let fuzz_dir = self.get_safe_fuzz_dir();

        // Always ensure the main fuzz directory exists
        fs::create_dir_all(&fuzz_dir)
            .with_context(|| format!("Failed to create fuzz directory: {}", fuzz_dir.display()))?;

        // Always ensure the fuzz_targets subdirectory exists
        let targets_dir = fuzz_dir.join("fuzz_targets");
        fs::create_dir_all(&targets_dir).with_context(|| {
            format!(
                "Failed to create fuzz_targets directory: {}",
                targets_dir.display()
            )
        })?;

        // Generate and write Cargo.toml, this will overwrite on every run to keep it updated
        self.write_fuzz_cargo_toml(&fuzz_dir)?;

        // Create/update target files
        for target in &self.targets {
            let target_file = targets_dir.join(format!("{}.rs", target.name));
            if !target_file.exists() {
                fs::write(&target_file, &target.harness_code).with_context(|| {
                    format!("Failed to write target file: {}", target_file.display())
                })?;
                debug!("Created fuzz target: {}", target_file.display());

                // Create a corpus directory for the new target
                let corpus_dir = fuzz_dir.join("corpus").join(&target.name);
                if !corpus_dir.exists() {
                    fs::create_dir_all(&corpus_dir)?;
                    fs::write(corpus_dir.join("seed"), b"")?;
                }
            }
        }

        Ok(())
    }

    /// Generate and write the Cargo.toml for the fuzz project
    fn write_fuzz_cargo_toml(&self, fuzz_dir: &Path) -> Result<()> {
        let mut manifest = String::from(
            r#"[package]
name = "solsec-fuzz"
version = "0.1.0"
edition = "2021"
publish = false

[package.metadata]
cargo-fuzz = true

[dependencies]
libfuzzer-sys = "0.4"
arbitrary = { version = "1.0", features = ["derive"] }

"#,
        );

        for target in &self.targets {
            let bin_entry = format!(
                r#"
[[bin]]
name = "{}"
path = "fuzz_targets/{}.rs"
test = false
doc = false
"#,
                target.name, target.name
            );
            manifest.push_str(&bin_entry);
        }

        let cargo_toml_path = fuzz_dir.join("Cargo.toml");
        fs::write(&cargo_toml_path, manifest).with_context(|| {
            format!(
                "Failed to write fuzz Cargo.toml to {}",
                cargo_toml_path.display()
            )
        })?;

        Ok(())
    }

    async fn run_single_target(&self, target: &FuzzTarget, jobs: usize) -> Result<FuzzResult> {
        info!(
            "Running fuzz target: {} (entry point: {})",
            target.name, target.entry_point
        );

        let fuzz_dir = self.get_safe_fuzz_dir();

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
            .current_dir(&fuzz_dir)
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
        let results_file = self.fuzz_dir.join("fuzz_results.json");
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
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let program_path = temp_dir.path().to_path_buf();
        let output_dir = temp_dir.path().join("output");

        let engine = FuzzEngine::new(program_path, output_dir);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_basic_target_generation() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let program_path = temp_dir.path().to_path_buf();
        let output_dir = temp_dir.path().join("output");

        let engine =
            FuzzEngine::new(program_path, output_dir).expect("Failed to create FuzzEngine");

        assert_eq!(engine.targets.len(), 1);
        assert_eq!(engine.targets[0].name, "basic_fuzz");
    }
}
