# Scripts Directory

This directory contains automation scripts for **solsec** development and version management.

## Available Scripts

### 🧪 `run-tests.sh`
**Purpose**: Comprehensive testing script that runs all project quality checks required by CI.

**Features**:
- Checks code formatting with `cargo fmt --check`
- Runs clippy lints with strict warnings (`-D warnings`)
- Executes all unit and integration tests
- Builds release version to ensure compilation

**Usage**:
```bash
# Run all checks (same as CI pipeline)
./scripts/run-tests.sh
```

**What it does**:
1. ✅ Code formatting check
2. 🔧 Clippy linting 
3. 🧪 Test execution
4. 📦 Release build verification

### 📦 `update-version.sh`
**Purpose**: Automated version management for releases across all project files.

**Features**:
- Updates version in `Cargo.toml` and `Cargo.lock`
- Updates UI version in `ui/package.json` and `ui/src/App.tsx`
- Updates documentation references
- Validates semantic versioning format
- Provides colored output and verification

**Usage**:
```bash
# Update to a specific version
./scripts/update-version.sh 0.2.0

# The script will update:
# - Cargo.toml (main version)
# - Cargo.lock (via cargo check)
# - ui/package.json (UI package version)
# - ui/src/App.tsx (mock data version)
# - .cursor/rules/rules.mdc (documentation)
```

**Version Format**: Follows [Semantic Versioning](https://semver.org/) (MAJOR.MINOR.PATCH)

**Example Output**:
```
[INFO] Current version: 0.1.7
[INFO] New version: 0.2.0
[INFO] Starting version update process...
[SUCCESS] Updated Cargo.toml
[SUCCESS] Updated Cargo.lock
[SUCCESS] Updated ui/package.json
[SUCCESS] Updated ui/src/App.tsx
[SUCCESS] Version successfully updated to 0.2.0!
```

## Development Workflow

### Local Development
```bash
# Before committing - run all checks
./scripts/run-tests.sh

# When ready for release
./scripts/update-version.sh 0.2.0
```

### CI/CD Integration
The `run-tests.sh` script is designed to match exactly what runs in GitHub Actions CI pipeline, ensuring local and CI environments are consistent.

## Script Guidelines

### Prerequisites
- **Bash**: Scripts require Bash/sh
- **Rust**: Latest stable Rust toolchain
- **Git**: For version management

### Error Handling
Both scripts use `set -e` to exit on first error, ensuring failures are caught immediately.

### Exit Codes
- `0`: Success
- `1`: Error (invalid arguments, validation failure, etc.)

## Contributing

The existing scripts follow these patterns:
- Clear colored output with status indicators
- Proper error handling with immediate exit on failure
- Semantic versioning validation
- Cross-platform compatibility (macOS/Linux)

When modifying scripts:
1. Test on both macOS and Linux
2. Ensure proper error handling
3. Add appropriate logging/output
4. Update this documentation

## Troubleshooting

**Permission Denied**: Make scripts executable with `chmod +x scripts/*.sh`

**Version Update Fails**: Ensure you're using valid semantic versioning (e.g., 0.2.0, not 0.2)

**Test Script Fails**: This indicates issues that would also fail in CI - fix the underlying code issues

---

For more information, see the main [README.md](../README.md) or [project documentation](../rules.md). 