#!/bin/bash

echo "🧪 Testing DepSec CLI Implementation"
echo "=================================="

# Check if Go is available
if ! command -v go &> /dev/null; then
    echo "❌ Go is not installed. Please install Go first."
    echo "   On Fedora: sudo dnf install golang"
    echo "   Or download from: https://golang.org/dl/"
    exit 1
fi

echo "✅ Go is available"

# Build the project
echo "🔨 Building DepSec..."
cd /home/yusuf/Belgeler/DepSec
go build -o depsec main.go

if [ $? -eq 0 ]; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi

# Test basic commands
echo ""
echo "🔍 Testing basic commands..."

echo "Testing: ./depsec --help"
./depsec --help

echo ""
echo "Testing: ./depsec doctor"
./depsec doctor

echo ""
echo "Testing: ./depsec config show"
./depsec config show

echo ""
echo "Testing: ./depsec auto status"
./depsec auto status

echo ""
echo "Testing: ./depsec version"
./depsec version

echo ""
echo "🎉 Basic testing completed!"
echo ""
echo "📝 Next steps:"
echo "   1. Install Docker for sandbox scanning (optional)"
echo "   2. Install ClamAV for binary scanning (optional)"
echo "   3. Try scanning a package: ./depsec scan --pkg lodash --ecosystem node"
echo "   4. Enable auto-scan: ./depsec auto enable"
