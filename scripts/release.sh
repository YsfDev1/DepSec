#!/bin/bash

# SecChain Release Script
# Automated release preparation and publishing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Configuration
GITHUB_REPO="YsfDev1/SecChain"
RELEASE_NOTES_FILE="RELEASE_NOTES.md"

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if gh CLI is installed
    if ! command -v gh &> /dev/null; then
        print_error "GitHub CLI (gh) is not installed. Please install it first."
        exit 1
    fi
    
    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository."
        exit 1
    fi
    
    # Check if working directory is clean
    if [ -n "$(git status --porcelain)" ]; then
        print_error "Working directory is not clean. Please commit or stash changes."
        exit 1
    fi
    
    # Check if we're on main branch
    current_branch=$(git branch --show-current)
    if [ "$current_branch" != "main" ]; then
        print_error "Not on main branch. Current branch: $current_branch"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Get current version
get_current_version() {
    grep -o 'Version: "[^"]*"' main.go | sed 's/Version: "//; s/"//'
}

# Get next version
get_next_version() {
    local current_version="$1"
    local version_type="$2"
    
    # Parse version (semantic versioning)
    IFS='.' read -r major minor patch <<< "$current_version"
    
    case "$version_type" in
        "patch")
            patch=$((patch + 1))
            ;;
        "minor")
            minor=$((minor + 1))
            patch=0
            ;;
        "major")
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        *)
            print_error "Invalid version type: $version_type"
            exit 1
            ;;
    esac
    
    echo "${major}.${minor}.${patch}"
}

# Update version in files
update_version() {
    local new_version="$1"
    
    print_status "Updating version to $new_version..."
    
    # Update main.go
    sed -i "s/Version: \"[^\"]*\"/Version: \"$new_version\"/" main.go
    
    # Update CHANGELOG.md
    sed -i "s/## \[Unreleased\]/## [Unreleased]\n\n## [$new_version] - $(date +%Y-%m-%d)/" CHANGELOG.md
    
    print_success "Version updated to $new_version"
}

# Run tests
run_tests() {
    print_status "Running tests..."
    
    ./scripts/test.sh --quick
    
    if [ $? -eq 0 ]; then
        print_success "All tests passed"
    else
        print_error "Tests failed"
        exit 1
    fi
}

# Build release
build_release() {
    print_status "Building release..."
    
    ./scripts/build.sh
    
    if [ $? -eq 0 ]; then
        print_success "Release built successfully"
    else
        print_error "Build failed"
        exit 1
    fi
}

# Generate release notes
generate_release_notes() {
    local version="$1"
    local previous_tag="$2"
    
    print_status "Generating release notes..."
    
    # Get commits since last tag
    if [ -n "$previous_tag" ]; then
        commits=$(git log --pretty=format:"- %s (%h)" "$previous_tag"..HEAD)
    else
        commits=$(git log --pretty=format:"- %s (%h)")
    fi
    
    # Create release notes
    cat > "$RELEASE_NOTES_FILE" << EOF
## SecChain $version

### 🚀 Installation

#### Binary Downloads
Download the appropriate binary for your platform:

\`\`\`bash
# Linux (AMD64)
curl -L -o secchain "https://github.com/$GITHUB_REPO/releases/download/$version/secchain-linux-amd64.tar.gz"
tar -xzf secchain-linux-amd64.tar.gz
chmod +x secchain
sudo mv secchain /usr/local/bin/

# macOS (Intel)
curl -L -o secchain "https://github.com/$GITHUB_REPO/releases/download/$version/secchain-darwin-amd64.tar.gz"
tar -xzf secchain-darwin-amd64.tar.gz
chmod +x secchain
sudo mv secchain /usr/local/bin/

# macOS (Apple Silicon)
curl -L -o secchain "https://github.com/$GITHUB_REPO/releases/download/$version/secchain-darwin-arm64.tar.gz"
tar -xzf secchain-darwin-arm64.tar.gz
chmod +x secchain
sudo mv secchain /usr/local/bin/

# Windows (AMD64)
curl -L -o secchain.zip "https://github.com/$GITHUB_REPO/releases/download/$version/secchain-windows-amd64.zip"
unzip secchain.zip
move secchain.exe C:\Program Files\SecChain\
\`\`\`

#### Go Install
\`\`\`bash
go install github.com/$GITHUB_REPO/cmd/secchain@$version
\`\`\`

### 📋 What's Changed

$commits

### 🔐 Verification

Verify the downloaded binaries using the SHA256 checksums:
\`\`\`bash
sha256sum -c SHA256SUMS
\`\`\`

### 📚 Documentation

- [Getting Started Guide](https://github.com/$GITHUB_REPO#getting-started)
- [Full Documentation](https://github.com/$GITHUB_REPO/docs)
- [API Reference](https://pkg.go.dev/github.com/$GITHUB_REPO)

---

🛡️ *SecChain - Protecting your dependencies from supply chain attacks*
EOF
    
    print_success "Release notes generated"
}

# Create git tag and push
create_tag() {
    local version="$1"
    
    print_status "Creating git tag..."
    
    # Commit changes
    git add main.go CHANGELOG.md
    git commit -m "chore: bump version to $version"
    
    # Create tag
    git tag -a "v$version" -m "Release $version"
    
    # Push to GitHub
    git push origin main
    git push origin "v$version"
    
    print_success "Tag v$version created and pushed"
}

# Create GitHub release
create_github_release() {
    local version="$1"
    
    print_status "Creating GitHub release..."
    
    # Create release using gh CLI
    gh release create "v$version" \
        --title "SecChain $version" \
        --notes-file "$RELEASE_NOTES_FILE" \
        --latest \
        release/*
    
    print_success "GitHub release created"
}

# Clean up
cleanup() {
    print_status "Cleaning up..."
    rm -f "$RELEASE_NOTES_FILE"
    print_success "Cleanup completed"
}

# Show help
show_help() {
    echo "SecChain Release Script"
    echo ""
    echo "Usage: $0 [version-type]"
    echo ""
    echo "Version types:"
    echo "  patch   Increment patch version (e.g., 0.1.0 -> 0.1.1)"
    echo "  minor   Increment minor version (e.g., 0.1.0 -> 0.2.0)"
    echo "  major   Increment major version (e.g., 0.1.0 -> 1.0.0)"
    echo ""
    echo "Examples:"
    echo "  $0 patch   Release 0.1.1"
    echo "  $0 minor   Release 0.2.0"
    echo "  $0 major   Release 1.0.0"
    echo ""
    echo "Prerequisites:"
    echo "  - GitHub CLI (gh) installed and authenticated"
    echo "  - Clean working directory on main branch"
    echo "  - All tests passing"
}

# Main function
main() {
    local version_type="$1"
    
    if [ -z "$version_type" ]; then
        show_help
        exit 1
    fi
    
    if [ "$version_type" = "--help" ] || [ "$version_type" = "-h" ]; then
        show_help
        exit 0
    fi
    
    echo "🚀 SecChain Release Process"
    echo "======================="
    echo ""
    
    # Check prerequisites
    check_prerequisites
    
    # Get current version
    current_version=$(get_current_version)
    print_status "Current version: $current_version"
    
    # Calculate next version
    next_version=$(get_next_version "$current_version" "$version_type")
    print_status "Next version: $next_version ($version_type)"
    
    # Confirm release
    echo ""
    read -p "Are you sure you want to release $next_version? (y/N): " -n 1 -r
    echo ""
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Release cancelled"
        exit 0
    fi
    
    # Get previous tag
    previous_tag=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
    
    # Release process
    update_version "$next_version"
    run_tests
    build_release
    generate_release_notes "$next_version" "$previous_tag"
    create_tag "$next_version"
    create_github_release "$next_version"
    cleanup
    
    echo ""
    print_success "🎉 Release $next_version completed successfully!"
    print_status "Release is available at: https://github.com/$GITHUB_REPO/releases/tag/v$next_version"
}

# Run main function
main "$@"
