# Version Management Scripts

This directory contains scripts for managing version updates across the solsec project.

## Best Practices for Version Management

### Option 1: Automated Script (Recommended)

Use the custom script that updates all relevant files:

```bash
./scripts/update-version.sh 0.1.2
```

**What it does:**
- ✅ Updates `Cargo.toml` 
- ✅ Updates `Cargo.lock` (via `cargo check`)
- ✅ Updates `ui/package.json`
- ✅ Updates mock version in `ui/src/App.tsx`
- ✅ Updates documentation
- ✅ Validates semantic versioning format
- ✅ Provides confirmation prompt
- ✅ Shows verification of changes

### Option 2: Using cargo-edit (Alternative)

Install cargo-edit for standard Rust version management:

```bash
# Install cargo-edit
cargo install cargo-edit

# Update version (only updates Cargo.toml and Cargo.lock)
cargo set-version 0.1.2

# Then manually update other files
```

### Option 3: Manual Updates

If you prefer manual control, update these files in order:

1. **Cargo.toml** - Main version
2. **ui/package.json** - UI package version  
3. **ui/src/App.tsx** - Mock data version
4. **.cursor/rules/rules.mdc** - Documentation
5. Run `cargo check` to update Cargo.lock

## Files That Contain Version Information

| File | Purpose | Auto-updated? |
|------|---------|---------------|
| `Cargo.toml` | Main Rust package version | ✅ Script |
| `Cargo.lock` | Dependency lock file | ✅ Script (via cargo) |
| `ui/package.json` | UI package version | ✅ Script |
| `ui/src/App.tsx` | Mock data in UI | ✅ Script |
| `.cursor/rules/rules.mdc` | Documentation | ✅ Script |
| `solsec-results` | Generated file | ✅ Cleaned by script |

## Version Update Workflow

1. **Run the script:**
   ```bash
   ./scripts/update-version.sh 0.1.2
   ```

2. **Test the changes:**
   ```bash
   cargo build --release
   cargo test
   ```

3. **Commit and tag:**
   ```bash
   git add -A
   git commit -m "chore: bump version to 0.1.2"
   git tag v0.1.2
   ```

4. **Push with tags:**
   ```bash
   git push origin main --tags
   ```

## Semantic Versioning Guidelines

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.1.0): New features, backward compatible  
- **PATCH** (0.0.1): Bug fixes, backward compatible

For this project in 0.x.x phase:
- **0.X.0**: New features or significant changes
- **0.x.X**: Bug fixes and minor improvements

## CI/CD Integration

The version is automatically used in:
- GitHub Actions workflows
- Release artifacts naming  
- Security report metadata
- Plugin information

## Troubleshooting

**Script fails on macOS:**
- The script uses `sed -i.bak` for macOS compatibility
- Backup files (.bak) are automatically cleaned up

**Permission denied:**
```bash
chmod +x scripts/update-version.sh
```

**Invalid version format:**
- Must follow semantic versioning: `MAJOR.MINOR.PATCH`
- Example: `0.1.2`, `1.0.0`, `2.1.3` 