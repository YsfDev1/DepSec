#!/bin/bash

echo "🔍 Testing CVE Scanning with Real OSV API"
echo "=========================================="

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

# Test CVE scanning with known vulnerable package
echo "🧪 Testing CVE scanning with lodash@4.17.15 (known vulnerable)..."
echo "This should return CVE-2021-23337 and other vulnerabilities"
echo ""

./depsec scan --pkg lodash --version 4.17.15 --ecosystem node --format table

echo ""
echo "🎯 Expected results:"
echo "   - CVE-2021-23337 (Prototype Pollution)"
echo "   - CVE-2022-2879 (Regular Expression Denial of Service)"
echo "   - Other potential vulnerabilities"
echo ""
echo "📝 If you see real CVE data above, the OSV API integration is working!"
echo "   If you see placeholder data, there may be network issues or API changes."
