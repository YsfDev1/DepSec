#!/bin/bash

echo "🔍 Testing Real CVE and Metadata Scanning"
echo "========================================"

# Check if Go is available
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    exit 1
fi

# Build the project
echo "🔨 Building DepSec..."
cd /home/yusuf/Belgeler/DepSec
go build -o depsec main.go

if [ $? -ne 0 ]; then
    echo "❌ Build failed"
    exit 1
fi

echo "✅ Build successful"
echo ""

# Test 1: CVE scanning with known vulnerable package
echo "🧪 Test 1: CVE Scanning with lodash@4.17.15"
echo "Expected: CVE-2021-23337 (Prototype Pollution), CVE-2022-2879 (ReDoS)"
echo ""

./depsec scan --pkg lodash --version 4.17.15 --ecosystem node --format table

echo ""
echo "================================"

# Test 2: Metadata scanning with a recent package
echo "🧪 Test 2: Metadata Scanning with express@4.18.2"
echo "Expected: Should show publish date, analyze install scripts"
echo ""

./depsec scan --pkg express --version 4.18.2 --ecosystem node --format table

echo ""
echo "================================"

# Test 3: Python package scanning
echo "🧪 Test 3: Python Package Scanning with requests@2.28.1"
echo "Expected: Should query PyPI for metadata and CVEs"
echo ""

./depsec scan --pkg requests --version 2.28.1 --ecosystem python --format table

echo ""
echo "================================"

# Test 4: JSON output format
echo "🧪 Test 4: JSON Output Format"
echo "Testing JSON output with lodash package..."
echo ""

./depsec scan --pkg lodash --version 4.17.15 --ecosystem node --format json | head -20

echo ""
echo "================================"

# Test 5: Minimal output format
echo "🧪 Test 5: Minimal Output Format"
echo "Testing minimal output..."
echo ""

./depsec scan --pkg lodash --version 4.17.15 --ecosystem node --format minimal

echo ""
echo "🎯 Analysis:"
echo "If you see real CVE IDs (like CVE-2021-23337) above, CVE scanning is working!"
echo "If you see package metadata and publish dates, registry APIs are working!"
echo "If you see findings with severity levels, the pipeline is working!"
echo ""
echo "📝 What to look for:"
echo "   - Real CVE IDs in the CVE layer"
echo "   - Package publish dates in metadata layer"
echo "   - Proper severity classification (LOW/MEDIUM/HIGH/CRITICAL)"
echo "   - Structured output in different formats"
