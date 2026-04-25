#!/bin/bash

# DepSec Build Script
# This script builds DepSec for multiple platforms and creates release artifacts

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

# Check if Go is installed
check_go() {
    if ! command -v go &> /dev/null; then
        print_error "Go is not installed. Please install Go 1.21 or later."
        exit 1
    fi
    
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_status "Go version: $GO_VERSION"
}

# Clean previous builds
clean_build() {
    print_status "Cleaning previous builds..."
    rm -rf release/
    rm -f depsec*
    mkdir -p release
}

# Build for multiple platforms
build_platforms() {
    print_status "Building for multiple platforms..."
    
    # Define platforms
    platforms=(
        "linux/amd64"
        "linux/arm64" 
        "darwin/amd64"
        "darwin/arm64"
        "windows/amd64"
    )
    
    # Build for each platform
    for platform in "${platforms[@]}"; do
        IFS='/' read -r GOOS GOARCH <<< "$platform"
        
        print_status "Building for $GOOS/$GOARCH..."
        
        # Set binary name
        if [ "$GOOS" = "windows" ]; then
            BINARY="depsec-${GOOS}-${GOARCH}.exe"
        else
            BINARY="depsec-${GOOS}-${GOARCH}"
        fi
        
        # Build
        GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o "release/$BINARY" main.go
        
        if [ $? -eq 0 ]; then
            print_success "Built $BINARY"
        else
            print_error "Failed to build $BINARY"
            exit 1
        fi
    done
}

# Create release archives
create_archives() {
    print_status "Creating release archives..."
    
    cd release
    
    # Create tar.gz for Unix systems
    for binary in depsec-linux-* depsec-darwin-*; do
        if [ -f "$binary" ]; then
            print_status "Creating ${binary}.tar.gz..."
            tar -czf "${binary}.tar.gz" "$binary"
            print_success "Created ${binary}.tar.gz"
        fi
    done
    
    # Create zip for Windows
    for binary in depsec-windows-*.exe; do
        if [ -f "$binary" ]; then
            print_status "Creating ${binary%.exe}.zip..."
            zip "${binary%.exe}.zip" "$binary"
            print_success "Created ${binary%.exe}.zip"
        fi
    done
    
    cd ..
}

# Generate checksums
generate_checksums() {
    print_status "Generating SHA256 checksums..."
    
    cd release
    sha256sum * > SHA256SUMS
    print_success "Generated SHA256SUMS"
    cd ..
}

# Run tests
run_tests() {
    print_status "Running tests..."
    
    if [ -n "$SKIP_TESTS" ]; then
        print_warning "Skipping tests (SKIP_TESTS is set)"
        return
    fi
    
    go test -v ./...
    
    if [ $? -eq 0 ]; then
        print_success "All tests passed"
    else
        print_error "Tests failed"
        exit 1
    fi
}

# Build local binary
build_local() {
    print_status "Building local binary..."
    go build -o depsec main.go
    print_success "Built local binary: depsec"
}

# Show help
show_help() {
    echo "DepSec Build Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message"
    echo "  -l, --local     Build only local binary"
    echo "  -t, --test      Run tests before building"
    echo "  -c, --clean     Clean build artifacts"
    echo "  -s, --skip-tests Skip tests"
    echo ""
    echo "Examples:"
    echo "  $0              Build for all platforms"
    echo "  $0 --local      Build only local binary"
    echo "  $0 --test       Run tests and build for all platforms"
}

# Main function
main() {
    LOCAL_ONLY=false
    RUN_TESTS=false
    CLEAN_ONLY=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -l|--local)
                LOCAL_ONLY=true
                shift
                ;;
            -t|--test)
                RUN_TESTS=true
                shift
                ;;
            -c|--clean)
                CLEAN_ONLY=true
                shift
                ;;
            -s|--skip-tests)
                export SKIP_TESTS=1
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Check prerequisites
    check_go
    
    # Clean if requested
    if [ "$CLEAN_ONLY" = true ]; then
        clean_build
        print_success "Clean completed"
        exit 0
    fi
    
    # Run tests if requested
    if [ "$RUN_TESTS" = true ]; then
        run_tests
    fi
    
    # Build local only if requested
    if [ "$LOCAL_ONLY" = true ]; then
        build_local
        print_success "Local build completed"
        exit 0
    fi
    
    # Full build process
    clean_build
    run_tests
    build_platforms
    create_archives
    generate_checksums
    
    print_success "Build completed successfully!"
    print_status "Release artifacts are in the 'release/' directory"
}

# Run main function
main "$@"
