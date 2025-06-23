#!/usr/bin/env bash

# Version Update Script for solsec
# Usage: ./scripts/update-version.sh <new-version>
# Example: ./scripts/update-version.sh 0.1.2

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if new version is provided
if [ $# -eq 0 ]; then
    log_error "Please provide a new version number"
    echo "Usage: $0 <new-version>"
    echo "Example: $0 0.1.2"
    exit 1
fi

NEW_VERSION="$1"

# Validate semantic version format
if ! [[ $NEW_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    log_error "Invalid version format. Please use semantic versioning (e.g., 0.1.2)"
    exit 1
fi

# Get current version from Cargo.toml
CURRENT_VERSION=$(grep '^version = ' Cargo.toml | sed 's/version = "\(.*\)"/\1/')

log_info "Current version: $CURRENT_VERSION"
log_info "New version: $NEW_VERSION"

# # Confirm the update
# echo ""
# read -p "Are you sure you want to update from $CURRENT_VERSION to $NEW_VERSION? (y/N): " -r
# if [[ ! $REPLY =~ ^[Yy]$ ]]; then
#     log_info "Version update cancelled"
#     exit 0
# fi

log_info "Starting version update process..."

# 1. Update Cargo.toml
log_info "Updating Cargo.toml..."
sed -i.bak "s/^version = \"$CURRENT_VERSION\"/version = \"$NEW_VERSION\"/" Cargo.toml
rm Cargo.toml.bak
log_success "Updated Cargo.toml"

# 2. Update Cargo.lock (by running cargo check)
log_info "Updating Cargo.lock..."
cargo check --quiet
log_success "Updated Cargo.lock"

# 3. Update UI package.json
if [ -f "ui/package.json" ]; then
    log_info "Updating ui/package.json..."
    sed -i.bak "s/\"version\": \"$CURRENT_VERSION\"/\"version\": \"$NEW_VERSION\"/" ui/package.json
    rm ui/package.json.bak
    log_success "Updated ui/package.json"
fi

# 4. Update mock data in UI App.tsx
if [ -f "ui/src/App.tsx" ]; then
    log_info "Updating mock version in ui/src/App.tsx..."
    sed -i.bak "s/solsec_version: \"$CURRENT_VERSION\"/solsec_version: \"$NEW_VERSION\"/" ui/src/App.tsx
    rm ui/src/App.tsx.bak
    log_success "Updated ui/src/App.tsx"
fi

# 5. Update documentation in rules file
if [ -f ".cursor/rules/rules.mdc" ]; then
    log_info "Updating version in documentation..."
    sed -i.bak "s/Cargo.toml version**: $CURRENT_VERSION/Cargo.toml version**: $NEW_VERSION/" .cursor/rules/rules.mdc
    rm .cursor/rules/rules.mdc.bak
    log_success "Updated documentation"
fi

# 6. Clean up any generated files that contain old version
if [ -f "solsec-results" ]; then
    log_warning "Removing old generated file: solsec-results"
    rm solsec-results
fi

# 7. Verify the updates
log_info "Verifying updates..."
echo ""
echo "Updated files:"
echo "- Cargo.toml: $(grep '^version = ' Cargo.toml)"
if [ -f "ui/package.json" ]; then
    echo "- ui/package.json: $(grep '"version":' ui/package.json | tr -d ' ')"
fi
if [ -f "ui/src/App.tsx" ]; then
    echo "- ui/src/App.tsx: $(grep 'solsec_version:' ui/src/App.tsx | tr -d ' ')"
fi

echo ""
log_success "Version successfully updated to $NEW_VERSION!"
echo ""
log_info "Next steps:"
echo "1. Test the build: cargo build --release"
echo "2. Run tests: cargo test"
echo "3. Update CHANGELOG.md if you have one"
echo "4. Commit changes: git add -A && git commit -m \"chore: bump version to $NEW_VERSION\""
echo "5. Create a git tag: git tag v$NEW_VERSION" 