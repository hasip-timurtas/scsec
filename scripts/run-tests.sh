#!/bin/sh

# This script runs all the checks required by the CI pipeline.
# It will exit immediately if any command fails.
set -e

# Announce the start of the script
echo "🚀 Running full test suite..."

# 1. Check code formatting
echo "\n🔍 Checking code formatting with 'cargo fmt'..."
cargo fmt --all -- --check

# 2. Run the linter
echo "\n linting code with 'cargo clippy'..."
cargo clippy --all-targets --all-features -- -D warnings

# 3. Run unit and integration tests
echo "\n🧪 Running tests with 'cargo test'..."
cargo test --verbose

# 4. Build the release version to ensure it compiles
echo "\n📦 Building release version with 'cargo build'..."
cargo build --release --verbose

# Announce completion
echo "\n✅ All checks passed successfully!" 