# 🛡️ Solana Smart Contract Security Toolkit (solsec)

[![Crates.io](https://img.shields.io/crates/v/solsec.svg)](https://crates.io/crates/solsec)
[![Downloads](https://img.shields.io/crates/d/solsec.svg)](https://crates.io/crates/solsec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://www.rust-lang.org)

A comprehensive security analysis tool for Solana smart contracts that helps developers identify vulnerabilities before deployment through static analysis and fuzz testing.

## ✨ Features

- **Static Analysis**: Detect common vulnerabilities in Anchor and native Rust programs
- **Fuzz Testing**: Auto-generate fuzzing harnesses from IDL files
- **Multiple Report Formats**: JSON, HTML, Markdown, and CSV outputs
- **Plugin System**: Extensible architecture for custom security rules
- **CI/CD Integration**: GitHub Actions support with automated security checks
- **Professional Reports**: Beautiful HTML reports with severity rankings and actionable recommendations
- **Smart Error Handling**: Clear, colored error messages with proper path validation
- **Comprehensive Examples**: 8 educational examples demonstrating vulnerabilities and secure patterns

## 🚀 Quick Start

### Installation

#### From Crates.io (Recommended)
```bash
cargo install solsec
```

#### From Source
```bash
git clone https://github.com/hasip-timurtas/solsec.git
cd solsec
cargo install --path .
```

### Basic Usage

```bash
# Scan the current project and generates both JSON and HTML
solsec scan

# Scan a specific Solana program and set an output directory
solsec scan ./my-solana-program --output ./results

# Generate only JSON
solsec scan ./my-program --json-only --output results.json

# Generate only HTML
solsec scan ./my-program --html-only --output results.html

# Generate multiple formats at once
solsec scan ./my-program --format json,html,markdown,csv

# Don't open browser automatically (useful for CI/automation)
solsec scan ./my-program --no-open

# Run fuzz testing
solsec fuzz ./my-solana-program --timeout 300
```

## 📖 Commands

### `solsec scan`

Run static analysis on your Solana smart contracts. Generates both JSON and HTML If no path is provided, it recursively scans the current directory for all `.rs` files, automatically ignoring `target/` and `.git/` folders.

HTML reports automatically open in your default browser when running interactively, but remain closed in CI/automation environments.

```bash
solsec scan [PATH] [OPTIONS]

OPTIONS:
    -c, --config <FILE>          Configuration file path
    -o, --output <DIR>           Output directory [default: ./solsec-results]
    -f, --format <FORMATS>       Output formats (comma-separated) [default: json,html] [possible values: json, html, markdown, csv]
        --json-only              Only generate JSON (perfect for CI/CD)
        --html-only              Only generate HTML (perfect for humans)
        --no-open                Don't automatically open HTML report in browser
        --fail-on-critical       Exit with non-zero code on critical issues [default: true]

EXAMPLES:
    # Scan the entire project (generates both JSON and HTML, opens in browser!)
    solsec scan

    # Scan a specific directory with default formats
    solsec scan ./programs/my-program
    
    # Generate only JSON for CI/CD integration (no browser opening)
    solsec scan ./programs --json-only --output results.json

    # Generate only HTML for manual review (opens in browser)
    solsec scan ./programs --html-only --output results.html

    # Generate HTML but don't open browser (useful for automation)
    solsec scan ./programs --html-only --no-open --output results.html

    # Generate all available formats
    solsec scan ./programs --format json,html,markdown,csv

    # Scan with configuration file
    solsec scan ./programs --config solsec.toml --output ./security-results
```

### `solsec fuzz`

Run fuzz testing on smart contracts.

```bash
solsec fuzz <PATH> [OPTIONS]

OPTIONS:
    -t, --timeout <SECONDS>      Timeout in seconds [default: 300]
    -j, --jobs <NUMBER>          Number of parallel fuzzing jobs [default: 1]
    -o, --output <DIR>           Output directory [default: ./fuzz-results]

EXAMPLES:
    solsec fuzz ./programs/my-program --timeout 600 --jobs 4
    solsec fuzz ./programs --output ./custom-fuzz-results
```



### `solsec plugin`

Manage security rule plugins.

```bash
solsec plugin <ACTION> [PATH]

ACTIONS:
    list      List available plugins
    load      Load a plugin
    unload    Unload a plugin

EXAMPLES:
    solsec plugin list
    solsec plugin load ./my-custom-rule.so
    solsec plugin unload my-custom-rule
```

## 🔧 Configuration

Create a `solsec.toml` configuration file:

```toml
# Enable/disable specific rules
enabled_rules = [
    "integer_overflow",
    "missing_signer_check", 
    "unchecked_account",
    "reentrancy"
]

disabled_rules = []

# Rule-specific settings
[rule_settings]
[rule_settings.integer_overflow]
ignore_patterns = ["test_*", "mock_*"]

[rule_settings.missing_signer_check]
required_for_instructions = ["transfer", "withdraw"]
```

## 🔍 Built-in Security Rules

| Rule | Severity | Description |
|------|----------|-------------|
| `integer_overflow` | Medium | Detects potential integer overflow vulnerabilities |
| `missing_signer_check` | High | Identifies missing signer validation in instruction handlers |
| `unchecked_account` | Critical | Finds accounts used without proper validation |
| `reentrancy` | High | Detects potential reentrancy vulnerabilities |

## 🔌 Plugin Development

Create custom security rules by implementing the `Rule` trait:

```rust
use solsec::plugin::{Rule, RuleResult, Severity};
use std::path::Path;
use anyhow::Result;

#[derive(Debug)]
pub struct MyCustomRule;

impl Rule for MyCustomRule {
    fn name(&self) -> &str {
        "my_custom_rule"
    }

    fn description(&self) -> &str {
        "Detects my specific vulnerability pattern"
    }

    fn check(&self, content: &str, file_path: &Path) -> Result<Vec<RuleResult>> {
        let mut results = Vec::new();
        
        // Your analysis logic here
        for (line_num, line) in content.lines().enumerate() {
            if line.contains("dangerous_pattern") {
                results.push(RuleResult {
                    severity: Severity::High,
                    message: "Dangerous pattern detected".to_string(),
                    line_number: Some(line_num + 1),
                    column: None,
                    code_snippet: Some(line.trim().to_string()),
                    suggestion: Some("Use safe alternative".to_string()),
                });
            }
        }
        
        Ok(results)
    }
}

// Plugin interface
#[no_mangle]
pub extern "C" fn get_plugin_info() -> PluginInfo {
    PluginInfo {
        name: "my_plugin".to_string(),
        version: "1.0.0".to_string(),
        description: "My custom security plugin".to_string(),
        author: "Your Name".to_string(),
        rules: vec!["my_custom_rule".to_string()],
    }
}

#[no_mangle]
pub extern "C" fn create_rules() -> Vec<Box<dyn Rule>> {
    vec![Box::new(MyCustomRule)]
}
```

Build your plugin as a dynamic library:

```bash
cargo build --lib --crate-type=cdylib --release
```

## 🤖 CI/CD Integration

### GitHub Actions

Add the following to your `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Install solsec
      run: |
        curl -L https://github.com/hasip-timurtas/solsec/releases/latest/download/solsec-linux-x86_64.tar.gz | tar xz
        sudo mv solsec /usr/local/bin/
    
    - name: Run security scan
      run: |
        solsec scan ./programs --output ./security-results
    
    - name: Upload security report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: ./security-results/
    
    - name: Fail on critical issues
      run: |
        if [ -f ./security-results/*.json ]; then
          critical_count=$(jq '[.[] | select(.severity == "critical")] | length' ./security-results/*.json)
          if [ "$critical_count" -gt 0 ]; then
            echo "❌ Critical security issues found!"
            exit 1
          fi
        fi
```

### Pre-commit Hook

```bash
#!/bin/sh
# .git/hooks/pre-commit

echo "🛡️ Running security scan..."
solsec scan ./programs --format json --output ./tmp-security-results

if [ -f ./tmp-security-results/*.json ]; then
    critical_count=$(jq '[.[] | select(.severity == "critical")] | length' ./tmp-security-results/*.json 2>/dev/null || echo "0")
    if [ "$critical_count" -gt 0 ]; then
        echo "❌ Critical security issues found! Commit blocked."
        echo "Run 'solsec scan ./programs' to see details."
        rm -rf ./tmp-security-results
        exit 1
    fi
fi

rm -rf ./tmp-security-results
echo "✅ Security scan passed!"
```

## 🌐 Smart Browser Opening

**Automatic browser opening** when generating HTML reports makes reviewing security findings effortless:

**✅ Opens automatically when:**
- Running in an interactive terminal (not redirected)
- Generating HTML reports (`--html-only` or default formats)
- Not in CI/automation environments

**❌ Stays closed when:**
- Running in CI environments (GitHub Actions, GitLab CI, etc.)
- Output is redirected or piped
- Using `--no-open` flag
- Only generating non-visual formats (JSON, CSV)

This gives you the best of both worlds: **great UX for developers** and **automation-friendly behavior** for CI/CD.

## 📊 Report Examples

### HTML Report
Beautiful, interactive HTML reports with:
- Executive summary with issue counts by severity
- Detailed findings with code snippets
- Actionable recommendations
- Responsive design for all devices
- **Auto-opens in your browser for immediate review!**

### JSON Report
Machine-readable format perfect for:
- CI/CD pipeline integration
- Custom tooling and analysis
- Data processing and metrics

### Markdown Report
Developer-friendly format for:
- README documentation
- Pull request comments
- Documentation sites

## 🛠️ Development

### Building from Source

```bash
git clone https://github.com/hasip-timurtas/solsec.git
cd solsec
cargo build --release
```

### Running Tests

```bash
cargo test
```

### Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📚 Examples

The [`examples/`](./examples/) directory contains comprehensive security vulnerability demonstrations:

### 🚨 Vulnerability Examples
Each category includes both **vulnerable** and **secure** implementations for educational purposes:

| Vulnerability Type | Severity | Vulnerable Examples | Secure Examples |
|-------------------|----------|-------------------|-----------------|
| **Integer Overflow** | Medium | `examples/integer_overflow/vulnerable.rs` | `examples/integer_overflow/secure.rs` |
| **Missing Signer Check** | High | `examples/missing_signer_check/vulnerable.rs` | `examples/missing_signer_check/secure.rs` |
| **Unchecked Account** | Critical | `examples/unchecked_account/vulnerable.rs` | `examples/unchecked_account/secure.rs` |
| **Reentrancy** | High | `examples/reentrancy/vulnerable.rs` | `examples/reentrancy/secure.rs` |

### 🧪 Testing the Examples

```bash
# Test vulnerable examples (should find many issues)
solsec scan examples/integer_overflow/vulnerable.rs     # 5 issues found
solsec scan examples/missing_signer_check/vulnerable.rs # 5 issues found
solsec scan examples/unchecked_account/vulnerable.rs    # 6 issues found
solsec scan examples/reentrancy/vulnerable.rs           # 2 issues found

# Test secure examples (should find 0 issues)
solsec scan examples/*/secure.rs                        # All pass!

# Comprehensive analysis
solsec scan examples/                                    # 26 total issues across all vulnerable examples
```

### 📖 Learning Resources
- **Side-by-side Comparisons**: See exactly how to fix each vulnerability
- **Real-world Patterns**: Actual Solana/Anchor code patterns
- **Educational Comments**: Clear explanations of security issues
- **Test Suite**: Validate that solsec detection works correctly

See the detailed [`examples/README.md`](./examples/README.md) for complete documentation.

## 🤝 Community

- **Issues**: [GitHub Issues](https://github.com/hasip-timurtas/solsec/issues)
- **Discussions**: [GitHub Discussions](https://github.com/hasip-timurtas/solsec/discussions)
- **Discord**: [Solana Security Community](https://discord.gg/solana-security)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- The Solana Foundation for supporting security tooling
- The Rust security community for best practices
- Contributors and early adopters

---

**⚠️ Important**: This tool helps identify potential security issues but does not guarantee complete security. Always conduct thorough testing and consider professional security audits for production applications.

*Built with ❤️ by Hasip Timurtas*