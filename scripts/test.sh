#!/bin/bash

# DepSec Test Script
# Comprehensive testing for DepSec CLI tool

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

# Test counters
TESTS_TOTAL=0
TESTS_PASSED=0
TESTS_FAILED=0

# Test result tracking
test_result() {
    local test_name="$1"
    local result="$2"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    
    if [ "$result" = "0" ]; then
        TESTS_PASSED=$((TESTS_PASSED + 1))
        print_success "$test_name - PASSED"
    else
        TESTS_FAILED=$((TESTS_FAILED + 1))
        print_error "$test_name - FAILED"
    fi
}

# Check if DepSec binary exists
check_binary() {
    print_status "Checking if DepSec binary exists..."
    
    if [ -f "./depsec" ]; then
        test_result "Binary exists" "0"
    else
        print_status "Building DepSec binary..."
        go build -o depsec main.go
        test_result "Binary build" "$?"
    fi
}

# Test basic commands
test_basic_commands() {
    print_status "Testing basic commands..."
    
    # Test help
    ./depsec --help > /dev/null 2>&1
    test_result "Help command" "$?"
    
    # Test version
    ./depsec version > /dev/null 2>&1
    test_result "Version command" "$?"
    
    # Test doctor
    ./depsec doctor > /dev/null 2>&1
    test_result "Doctor command" "$?"
}

# Test configuration commands
test_config_commands() {
    print_status "Testing configuration commands..."
    
    # Test config show
    ./depsec config show > /dev/null 2>&1
    test_result "Config show" "$?"
    
    # Test config set
    ./depsec config set test_mode test_value > /dev/null 2>&1
    test_result "Config set" "$?"
    
    # Test config reset
    ./depsec config reset > /dev/null 2>&1
    test_result "Config reset" "$?"
}

# Test auto-scan commands
test_auto_commands() {
    print_status "Testing auto-scan commands..."
    
    # Test auto status
    ./depsec auto status > /dev/null 2>&1
    test_result "Auto status" "$?"
    
    # Note: We don't test enable/disable to avoid modifying shell config
}

# Test scanning commands
test_scan_commands() {
    print_status "Testing scanning commands..."
    
    # Test package scanning (known vulnerable package)
    ./depsec scan --pkg lodash --version 4.17.15 --ecosystem node > /dev/null 2>&1
    test_result "Package scan (lodash)" "$?"
    
    # Test package scanning with different output format
    ./depsec scan --pkg express --version 4.18.2 --ecosystem node --format json > /dev/null 2>&1
    test_result "Package scan (express, JSON)" "$?"
    
    # Test package scanning with minimal format
    ./depsec scan --pkg requests --version 2.28.1 --ecosystem python --format minimal > /dev/null 2>&1
    test_result "Package scan (requests, minimal)" "$?"
}

# Test report commands
test_report_commands() {
    print_status "Testing report commands..."
    
    # Test report (no history yet)
    ./depsec report > /dev/null 2>&1
    test_result "Report command" "$?"
    
    # Test report with package filter
    ./depsec report --pkg lodash > /dev/null 2>&1
    test_result "Report with package filter" "$?"
}

# Test maintenance commands
test_maintenance_commands() {
    print_status "Testing maintenance commands..."
    
    # Test update-rules (may fail without proper setup, but should not crash)
    ./depsec update-rules > /dev/null 2>&1
    test_result "Update rules command" "$?"
}

# Test error handling
test_error_handling() {
    print_status "Testing error handling..."
    
    # Test invalid command
    ./depsec invalid-command > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        test_result "Invalid command handling" "0"
    else
        test_result "Invalid command handling" "1"
    fi
    
    # Test invalid package
    ./depsec scan --pkg nonexistent-package-12345 --version 1.0.0 --ecosystem node > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        test_result "Invalid package handling" "0"
    else
        test_result "Invalid package handling" "1"
    fi
}

# Test real CVE detection
test_cve_detection() {
    print_status "Testing real CVE detection..."
    
    # Scan lodash@4.17.15 (known to have CVEs)
    output=$(./depsec scan --pkg lodash --version 4.17.15 --ecosystem node --format table 2>/dev/null)
    
    # Check if CVEs were found
    if echo "$output" | grep -q "CVE"; then
        test_result "CVE detection (lodash)" "0"
        print_status "Found CVEs in lodash@4.17.15"
    else
        test_result "CVE detection (lodash)" "1"
        print_warning "No CVEs found in lodash@4.17.15 (may be expected)"
    fi
}

# Test JSON output format
test_json_output() {
    print_status "Testing JSON output format..."
    
    # Scan with JSON output
    output=$(./depsec scan --pkg express --version 4.18.2 --ecosystem node --format json 2>/dev/null)
    
    # Check if output is valid JSON
    if echo "$output" | python3 -m json.tool > /dev/null 2>&1; then
        test_result "JSON output format" "0"
    else
        test_result "JSON output format" "1"
    fi
}

# Test configuration file handling
test_config_file() {
    print_status "Testing configuration file handling..."
    
    # Test config file creation
    if [ ! -d "$HOME/.config/depsec" ]; then
        ./depsec config show > /dev/null 2>&1
        if [ -d "$HOME/.config/depsec" ]; then
            test_result "Config directory creation" "0"
        else
            test_result "Config directory creation" "1"
        fi
    else
        test_result "Config directory exists" "0"
    fi
    
    # Test config file existence
    if [ -f "$HOME/.config/depsec/config.toml" ]; then
        test_result "Config file creation" "0"
    else
        test_result "Config file creation" "1"
    fi
}

# Run Go tests
run_go_tests() {
    print_status "Running Go unit tests..."
    
    go test -v ./... > /dev/null 2>&1
    test_result "Go unit tests" "$?"
}

# Integration test
integration_test() {
    print_status "Running integration test..."
    
    # Create a temporary test project
    temp_dir=$(mktemp -d)
    trap "rm -rf $temp_dir" EXIT
    
    # Create a simple package.json
    cat > "$temp_dir/package.json" << 'EOF'
{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15"
  }
}
EOF
    
    # Test project scanning (may not be fully implemented yet)
    ./depsec scan "$temp_dir" > /dev/null 2>&1
    test_result "Project scanning" "$?"
}

# Performance test
performance_test() {
    print_status "Running performance test..."
    
    # Time a simple scan
    start_time=$(date +%s.%N)
    ./depsec scan --pkg express --version 4.18.2 --ecosystem node > /dev/null 2>&1
    end_time=$(date +%s.%N)
    
    duration=$(echo "$end_time - $start_time" | bc)
    
    # Check if scan completes in reasonable time (less than 30 seconds)
    if (( $(echo "$duration < 30" | bc -l) )); then
        test_result "Performance test (< 30s)" "0"
        print_status "Scan completed in ${duration}s"
    else
        test_result "Performance test (< 30s)" "1"
        print_warning "Scan took ${duration}s (slow but may be acceptable)"
    fi
}

# Show test summary
show_summary() {
    echo ""
    echo "==================================="
    echo "Test Summary"
    echo "==================================="
    echo "Total Tests: $TESTS_TOTAL"
    echo "Passed: $TESTS_PASSED"
    echo "Failed: $TESTS_FAILED"
    echo "Success Rate: $(( TESTS_PASSED * 100 / TESTS_TOTAL ))%"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        print_success "All tests passed! 🎉"
        exit 0
    else
        print_error "Some tests failed. Please review the output above."
        exit 1
    fi
}

# Show help
show_help() {
    echo "DepSec Test Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message"
    echo "  -q, --quick     Run quick tests only (skip performance/integration)"
    echo "  -v, --verbose   Show verbose output"
    echo "  --skip-go      Skip Go unit tests"
    echo ""
    echo "Examples:"
    echo "  $0              Run all tests"
    echo "  $0 --quick      Run quick tests only"
    echo "  $0 --skip-go    Skip Go unit tests"
}

# Main function
main() {
    QUICK=false
    VERBOSE=false
    SKIP_GO=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -q|--quick)
                QUICK=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                set -x
                shift
                ;;
            --skip-go)
                SKIP_GO=true
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    echo "🧪 DepSec Test Suite"
    echo "===================="
    echo ""
    
    # Run tests
    check_binary
    
    if [ "$SKIP_GO" = false ]; then
        run_go_tests
    fi
    
    test_basic_commands
    test_config_commands
    test_auto_commands
    test_scan_commands
    test_report_commands
    test_maintenance_commands
    test_error_handling
    test_cve_detection
    test_json_output
    test_config_file
    
    if [ "$QUICK" = false ]; then
        integration_test
        performance_test
    fi
    
    show_summary
}

# Run main function
main "$@"
