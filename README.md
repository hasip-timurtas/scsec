# 🛡️ Solana Smart Contract Security Toolkit (scsec)

A comprehensive security analysis tool for Solana smart contracts that helps developers identify vulnerabilities before deployment through static analysis and fuzz testing.

## ✨ Features

- **Static Analysis**: Detect common vulnerabilities in Anchor and native Rust programs
- **Fuzz Testing**: Auto-generate fuzzing harnesses from IDL files
- **Multiple Report Formats**: JSON, HTML, Markdown, and CSV outputs
- **Plugin System**: Extensible architecture for custom security rules
- **CI/CD Integration**: GitHub Actions support with automated security checks
- **Professional Reports**: Beautiful HTML reports with severity rankings and actionable recommendations

## 🚀 Quick Start

### Installation

#### From Crates.io (Recommended)
```bash
cargo install scsec
```

#### From Source
```bash
git clone https://github.com/hasip-timurtas/scsec.git
cd scsec
cargo install --path .
```

### Basic Usage

```bash
# Scan a Solana program for security issues
scsec scan ./my-solana-program --output ./results

# Run fuzz testing
scsec fuzz ./my-solana-program --timeout 300

# Generate an HTML report
scsec report ./results --output report.html --format html
```

## 📖 Commands

### `scsec scan`

Run static analysis on your Solana smart contracts.

```bash
scsec scan <PATH> [OPTIONS]

OPTIONS:
    -c, --config <FILE>          Configuration file path
    -o, --output <DIR>           Output directory [default: ./scsec-results]
    -f, --format <FORMAT>        Output format [default: json] [possible values: json, html, markdown, csv]
        --fail-on-critical       Exit with non-zero code on critical issues [default: true]

EXAMPLES:
    scsec scan ./programs/my-program
    scsec scan ./programs --config scsec.toml --output ./security-results
    scsec scan ./target/idl/my_program.json --format html
```

### `scsec fuzz`

Run fuzz testing on smart contracts.

```bash
scsec fuzz <PATH> [OPTIONS]

OPTIONS:
    -t, --timeout <SECONDS>      Timeout in seconds [default: 300]
    -j, --jobs <NUMBER>          Number of parallel fuzzing jobs [default: 1]
    -o, --output <DIR>           Output directory [default: ./fuzz-results]

EXAMPLES:
    scsec fuzz ./programs/my-program --timeout 600 --jobs 4
    scsec fuzz ./programs --output ./custom-fuzz-results
```

### `scsec report`

Generate human-readable reports from analysis results.

```bash
scsec report <RESULTS> [OPTIONS]

OPTIONS:
    -o, --output <FILE>          Output file path [default: ./report.html]
    -f, --format <FORMAT>        Report format [default: html] [possible values: json, html, markdown, csv]

EXAMPLES:
    scsec report ./scsec-results
    scsec report ./results --output security-report.md --format markdown
    scsec report ./results --format csv > issues.csv
```

### `scsec plugin`

Manage security rule plugins.

```bash
scsec plugin <ACTION> [PATH]

ACTIONS:
    list      List available plugins
    load      Load a plugin
    unload    Unload a plugin

EXAMPLES:
    scsec plugin list
    scsec plugin load ./my-custom-rule.so
    scsec plugin unload my-custom-rule
```

## 🔧 Configuration

Create a `scsec.toml` configuration file:

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
use scsec::plugin::{Rule, RuleResult, Severity};
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
    
    - name: Install scsec
      run: |
        curl -L https://github.com/hasip-timurtas/scsec/releases/latest/download/scsec-linux-x86_64.tar.gz | tar xz
        sudo mv scsec /usr/local/bin/
    
    - name: Run security scan
      run: |
        scsec scan ./programs --output ./security-results --format json
        scsec report ./security-results --output ./security-report.html
    
    - name: Upload security report
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: |
          ./security-results/
          ./security-report.html
    
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
scsec scan ./programs --format json --output ./tmp-security-results

if [ -f ./tmp-security-results/*.json ]; then
    critical_count=$(jq '[.[] | select(.severity == "critical")] | length' ./tmp-security-results/*.json 2>/dev/null || echo "0")
    if [ "$critical_count" -gt 0 ]; then
        echo "❌ Critical security issues found! Commit blocked."
        echo "Run 'scsec scan ./programs' to see details."
        rm -rf ./tmp-security-results
        exit 1
    fi
fi

rm -rf ./tmp-security-results
echo "✅ Security scan passed!"
```

## 📊 Report Examples

### HTML Report
Beautiful, interactive HTML reports with:
- Executive summary with issue counts by severity
- Detailed findings with code snippets
- Actionable recommendations
- Responsive design for all devices

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
git clone https://github.com/hasip-timurtas/scsec.git
cd scsec
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

Check out the [`examples/`](./examples/) directory for:
- Sample Solana programs with vulnerabilities
- Custom plugin implementations
- CI/CD configuration templates
- Integration with various development workflows

## 🤝 Community

- **Issues**: [GitHub Issues](https://github.com/hasip-timurtas/scsec/issues)
- **Discussions**: [GitHub Discussions](https://github.com/hasip-timurtas/scsec/discussions)
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