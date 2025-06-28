# Contributing to solsec

Thank you for your interest in contributing to **solsec** (Solana Smart Contract Security Toolkit)! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Code Quality Standards](#code-quality-standards)
- [Testing Requirements](#testing-requirements)
- [Pre-commit Setup](#pre-commit-setup)
- [Submission Guidelines](#submission-guidelines)
- [Security Rule Development](#security-rule-development)
- [Documentation](#documentation)

## Getting Started

### Prerequisites

- **Rust**: Latest stable version (2021 edition)
- **Git**: For version control
- **bun**: Package manager (for UI development)

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/solsec.git
   cd solsec
   ```

3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/hasip-timurtas/solsec.git
   ```

4. Create a new branch for your feature:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Workflow

### Building the Project

```bash
# Build in debug mode
cargo build

# Build in release mode
cargo build --release
```

### Running Tests

**IMPORTANT**: Before submitting any changes, you MUST run the full test suite:

```bash
# Run the comprehensive test script
./scripts/run-tests.sh
```

This script will:
- ✅ Check code formatting with `cargo fmt`
- ✅ Run linting with `cargo clippy` (strict mode)
- ✅ Execute all tests with `cargo test`
- ✅ Verify release build compilation

### Manual Testing Commands

```bash
# Check formatting
cargo fmt --all -- --check

# Run linting (strict mode - all warnings treated as errors)
cargo clippy --all-targets --all-features -- -D warnings

# Run tests
cargo test --verbose

# Build release
cargo build --release --verbose
```

## Code Quality Standards

### Clippy Compliance

**CRITICAL**: This project uses **strict clippy mode** with `-D warnings`, meaning ALL clippy warnings are treated as errors.

#### Required Practices

1. **Use `is_some_and()` instead of `map_or(false, |x| condition)`**
   ```rust
   // ❌ Bad
   if path.extension().map_or(false, |ext| ext == "rs") {
   
   // ✅ Good  
   if path.extension().is_some_and(|ext| ext == "rs") {
   ```

2. **Move regex compilation outside loops**
   ```rust
   // ❌ Bad - creates regex in every iteration
   for line in lines {
       if Regex::new(r"pattern").unwrap().is_match(line) {
   
   // ✅ Good - compile once, use many times
   let regex = Regex::new(r"pattern")?;
   for line in lines {
       if regex.is_match(line) {
   ```

3. **Remove unnecessary borrows**
   ```rust
   // ❌ Bad
   Command::new("cargo").args(&["test", "arg"])
   
   // ✅ Good
   Command::new("cargo").args(["test", "arg"])
   ```

4. **Handle dead code properly**
   - **Don't use `#[allow(dead_code)]` as first resort**
   - **Actually integrate code** into the system
   - **Only allow dead code** for FFI interfaces and public APIs

### Formatting Standards

- Use `cargo fmt --all` to format your code
- All code must pass `cargo fmt --all -- --check`
- Follow Rust standard formatting conventions

### Error Handling

- Use `anyhow::Result` for error handling
- Avoid `unwrap()` in production code - use proper error propagation
- Provide clear, actionable error messages

## Testing Requirements

### Test Coverage

All new features must include:

1. **Unit Tests**: Test individual functions and components
2. **Integration Tests**: Test CLI commands and workflows
3. **Edge Cases**: Test error conditions and boundary cases

### Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_security_rule_detection() {
        // Test implementation
    }
    
    #[test]
    fn test_error_handling() {
        // Test error conditions
    }
}
```

### Running Specific Tests

```bash
# Run all tests
cargo test

# Run tests for specific module
cargo test analyzer

# Run tests with output
cargo test -- --nocapture
```

## Pre-commit Setup

### Native Git Hooks Approach

**PHILOSOPHY**: We use native git hooks, NOT external frameworks.

**Why native hooks?**
- ✅ Zero dependencies
- ✅ Built into Git
- ✅ Simple shell script
- ✅ Project-specific
- ✅ Easy to debug and modify

### Setup Instructions

1. **Create the pre-commit hook** (if not already present):
   ```bash
   # The hook should already exist, but if not:
   cp .git/hooks/pre-commit.sample .git/hooks/pre-commit
   chmod +x .git/hooks/pre-commit
   ```

2. **Verify the hook works**:
   ```bash
   .git/hooks/pre-commit
   ```

The pre-commit hook will:
- Format code with `cargo fmt --all`
- Run linting with `cargo clippy --all-targets --all-features -- -D warnings`
- Validate build with `cargo check --all-targets`
- Auto-add formatted changes to commit

## Submission Guidelines

### Before Submitting

1. **Run the full test suite**:
   ```bash
   ./scripts/run-tests.sh
   ```

2. **Ensure all tests pass**:
   ```bash
   cargo test
   ```

3. **Check code formatting**:
   ```bash
   cargo fmt --all -- --check
   ```

4. **Verify clippy compliance**:
   ```bash
   cargo clippy --all-targets --all-features -- -D warnings
   ```

### Pull Request Process

1. **Update your branch**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Create descriptive commits**:
   ```bash
   git commit -m "feat: Add new security rule for PDA validation"
   ```

3. **Push your changes**:
   ```bash
   git push origin feature/your-feature-name
   ```

4. **Create Pull Request**:
   - Use a clear, descriptive title
   - Include detailed description of changes
   - Reference any related issues
   - Include testing instructions

### Commit Message Format

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
- `feat: Add new security rule for integer overflow detection`
- `fix: Resolve false positives in reentrancy detection`
- `docs: Update README with new CLI options`
- `test: Add comprehensive tests for analyzer module`

## Security Rule Development

### Implementing New Security Rules

1. **Create the rule struct**:
   ```rust
   #[derive(Debug)]
   pub struct MySecurityRule {
       // Rule-specific fields
   }
   ```

2. **Implement the Rule trait**:
   ```rust
   impl Rule for MySecurityRule {
       fn name(&self) -> &str { "my_security_rule" }
       fn description(&self) -> &str { "Detects my specific vulnerability" }
       fn check(&self, content: &str, file_path: &Path) -> Result<Vec<RuleResult>> {
           // Implementation
       }
   }
   ```

3. **Add comprehensive tests**:
   ```rust
   #[cfg(test)]
   mod tests {
       use super::*;
       
       #[test]
       fn test_my_rule_detects_vulnerability() {
           // Test positive cases
       }
       
       #[test]
       fn test_my_rule_avoids_false_positives() {
           // Test negative cases
       }
   }
   ```

4. **Update examples** in the `examples/` directory with:
   - Vulnerable code example
   - Secure code example
   - Clear documentation

### Rule Quality Standards

- **High Accuracy**: Minimize false positives
- **Clear Messages**: Provide actionable feedback
- **Proper Severity**: Use appropriate severity levels
- **Comprehensive Testing**: Cover edge cases and variations

## Documentation

### Code Documentation

- Add rustdoc comments for public APIs
- Include examples in documentation
- Document complex algorithms and security patterns

### README Updates

When adding new features:
- Update feature list
- Add usage examples
- Update command documentation
- Include performance impact notes

### Example Updates

- Add both vulnerable and secure examples
- Include clear explanations
- Update the examples README
- Test examples with the tool

## UI Development (Optional)

If contributing to the UI component:

### Prerequisites
- **bun**: Package manager (preferred over npm/yarn)

### Setup
```bash
cd ui
bun install
```

### Development
```bash
# Start development server
bun dev

# Build for production
bun run build
```

### Standards
- Use TypeScript for type safety
- Follow Tailwind CSS for styling
- Maintain responsive design
- Test across different screen sizes

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/hasip-timurtas/solsec/issues)
- **Discussions**: [GitHub Discussions](https://github.com/hasip-timurtas/solsec/discussions)
- **Discord**: [Solana Security Community](https://discord.gg/solana-security)

## License

By contributing to solsec, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to solsec! Your efforts help make Solana smart contracts more secure for everyone.** 🛡️ 