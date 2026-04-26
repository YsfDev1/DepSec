#!/bin/bash

echo "🧪 Testing SecChain CLI Implementation"
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
echo "🔨 Building SecChain..."
cd /home/yusuf/Belgeler/SecChain
go build -o secchain main.go

if [ $? -eq 0 ]; then
    echo "✅ Build successful"
else
    echo "❌ Build failed"
    exit 1
fi

# Test basic commands
echo ""
echo "🔍 Testing basic commands..."

echo "Testing: ./secchain --help"
./secchain --help

echo ""
echo "Testing: ./cc doctor"
./cc doctor

echo ""
echo "Testing: ./cc config show"
./cc config show

echo ""
echo "Testing: ./cc auto status"
./cc auto status

echo ""
echo "Testing: ./cc version"
./cc version

echo ""
echo "🎉 Basic testing completed!"
echo ""
echo "📝 Next steps:"
echo "   1. Install Docker for sandbox scanning (optional)"
echo "   2. Install ClamAV for binary scanning (optional)"
echo "   3. Try scanning a package: ./cc scan --pkg lodash --ecosystem node"
echo "   4. Enable auto-scan: ./cc auto enable"
