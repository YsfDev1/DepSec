# SecChain Documentation

Welcome to the SecChain documentation! Here you'll find comprehensive guides for using and contributing to SecChain.

## 📚 Table of Contents

- [Getting Started](#getting-started)
- [Installation](#installation)
- [Configuration](#configuration)
- [Commands](#commands)
- [Security Scanning](#security-scanning)
- [Development](#development)
- [API Reference](#api-reference)
- [Troubleshooting](#troubleshooting)

## 🚀 Getting Started

### What is SecChain?

SecChain is a CLI security tool that automatically scans packages and their dependencies in an isolated sandbox before they are installed on the host system. It provides layered security scanning including:

- **CVE Detection** - Real-time vulnerability scanning using OSV database
- **Metadata Analysis** - Package registry metadata anomaly detection
- **Sandbox Scanning** - Isolated container-based package analysis
- **YARA Rules** - Custom rule-based binary analysis
- **ClamAV Integration** - Antivirus scanning

### Quick Start

```bash
# Install SecChain
curl -L https://github.com/YsfDev1/SecChain/releases/latest/download/secchain-linux-amd64.tar.gz | tar -xz
sudo mv secchain /usr/local/bin/

# Scan a package
cc scan --pkg lodash --version 4.17.15 --ecosystem node

# Enable auto-scan
cc auto enable

# Check system health
cc doctor
```

## 🔧 Installation

### Binary Installation

#### Linux (AMD64)
```bash
curl -L -o secchain.tar.gz "https://github.com/YsfDev1/SecChain/releases/latest/download/secchain-linux-amd64.tar.gz"
tar -xzf secchain.tar.gz
chmod +x secchain
sudo mv secchain /usr/local/bin/
```

#### macOS (Intel)
```bash
curl -L -o secchain.tar.gz "https://github.com/YsfDev1/SecChain/releases/latest/download/secchain-darwin-amd64.tar.gz"
tar -xzf secchain.tar.gz
chmod +x secchain
sudo mv secchain /usr/local/bin/
```

#### macOS (Apple Silicon)
```bash
curl -L -o secchain.tar.gz "https://github.com/YsfDev1/SecChain/releases/latest/download/secchain-darwin-arm64.tar.gz"
tar -xzf secchain.tar.gz
chmod +x secchain
sudo mv secchain /usr/local/bin/
```

#### Windows (AMD64)
```powershell
Invoke-WebRequest -Uri "https://github.com/YsfDev1/SecChain/releases/latest/download/secchain-windows-amd64.zip" -OutFile "secchain.zip"
Expand-Archive -Path "secchain.zip" -DestinationPath "."
Move-Item "secchain.exe" -Destination "C:\Program Files\SecChain\"
```

### Go Install

```bash
go install github.com/YsfDev1/SecChain/cmd/secchain@latest
```

### From Source

```bash
git clone https://github.com/YsfDev1/SecChain.git
cd SecChain
go build -o secchain main.go
sudo mv secchain /usr/local/bin/
```

## ⚙️ Configuration

SecChain uses a TOML configuration file located at `~/.config/secchain/config.toml`.

### Default Configuration

```toml
[mode]
mode = "interactive"           # interactive, strict, log-only
min_severity = "medium"         # low, medium, high, critical
offline = false                 # Use cached data only

[auto_scan]
enabled = false                 # Auto-scan enabled
ecosystems = ["node", "python", "rust", "go", "ruby"]

[docker]
enabled = true                  # Docker sandbox scanning

[clamav]
enabled = true                  # ClamAV scanning

[yara]
enabled = true                  # YARA rule scanning

[cache]
enabled = true                  # Local caching
ttl = "24h"                     # Cache TTL

[output]
format = "table"                # table, json, minimal
show_clean = true               # Show clean packages
verbose = false                 # Verbose output
```

### Configuration Commands

```bash
# Show current configuration
cc config show

# Set configuration values
cc config set mode strict
cc config set min_severity high
cc config set offline true

# Reset to defaults
cc config reset
```

## 📋 Commands

### Scanning Commands

#### Scan a Package
```bash
cc scan --pkg <package> --version <version> --ecosystem <ecosystem>
```

**Examples:**
```bash
# Scan a specific version
cc scan --pkg lodash --version 4.17.15 --ecosystem node

# Scan latest version
cc scan --pkg express --ecosystem node

# Scan with different output format
cc scan --pkg requests --ecosystem python --format json

# Scan in strict mode
cc scan --pkg react --ecosystem node --strict
```

#### Scan a Project
```bash
cc scan /path/to/project
```

### Auto-Scan Commands

#### Enable Auto-Scan
```bash
cc auto enable
```

This injects shell hooks that automatically scan packages before installation.

#### Disable Auto-Scan
```bash
cc auto disable
```

#### Check Status
```bash
cc auto status
```

### Configuration Commands

#### Show Configuration
```bash
cc config show
```

#### Set Configuration
```bash
cc config set <key> <value>
```

#### Reset Configuration
```bash
cc config reset
```

### Maintenance Commands

#### System Health Check
```bash
cc doctor
```

#### Update Rules and Cache
```bash
cc update-rules
```

#### Show Version
```bash
cc version
```

### Report Commands

#### Show Last Scan Report
```bash
cc report
```

#### Show Scan History
```bash
cc report --history
```

#### Show Package Report
```bash
cc report --pkg lodash
```

## 🔍 Security Scanning

### CVE Detection

SecChain queries the OSV (Open Source Vulnerability) database for known vulnerabilities:

```bash
# CVE scanning example
cc scan --pkg lodash --version 4.17.15 --ecosystem node

# Output example
PACKAGE  VERSION  ECOSYSTEM  SEVERITY  LAYER  REASON
lodash   4.17.15  node       HIGH      CVE    CVE-2021-23337: Prototype Pollution
lodash   4.17.15  node       MEDIUM    CVE    CVE-2022-2879: Regular Expression DoS
```

### Metadata Analysis

SecChain analyzes package metadata for anomalies:

- **Publish Date Analysis** - Identifies suspiciously new or old packages
- **Typosquatting Detection** - Detects packages with similar names to popular packages
- **Install Script Analysis** - Scans package install scripts for suspicious commands

### Sandbox Scanning

When Docker is available, SecChain can scan packages in an isolated container:

- **Network Monitoring** - Detects unauthorized network calls
- **File System Monitoring** - Monitors file access patterns
- **Process Monitoring** - Analyzes running processes
- **Environment Access** - Monitors environment variable access

### YARA Rules

SecChain uses YARA rules for binary pattern matching:

```bash
# Update YARA rules
cc update-rules

# Custom rules location
~/.config/secchain/rules/
```

## 🛠️ Development

### Development Setup

```bash
# Clone the repository
git clone https://github.com/YsfDev1/SecChain.git
cd SecChain

# Install dependencies
go mod tidy

# Build the project
go build -o secchain main.go

# Run tests
go test ./...

# Run integration tests
./test_real_scanning.sh
```

### Project Structure

```
SecChain/
├── cmd/           # CLI commands
├── scanner/       # Core scanning logic
├── config/        # Configuration management
├── cache/         # Caching layer
├── hooks/         # Shell hook management
├── output/        # Output formatting
├── rules/         # YARA rules (created on first use)
├── docs/          # Documentation
├── scripts/       # Build and utility scripts
└── .github/       # GitHub workflows and templates
```

### Adding New Scanners

1. Implement the scanner interface in `scanner/`
2. Add configuration options in `config/`
3. Update CLI commands in `cmd/`
4. Add comprehensive tests
5. Update documentation

### Adding New Ecosystems

1. Update dependency resolver in `scanner/resolver.go`
2. Add ecosystem-specific metadata fetching
3. Update configuration defaults
4. Add test cases

## 📖 API Reference

### Scanner Interface

```go
type Scanner interface {
    Init() error
    IsAvailable() bool
    Scan(ctx context.Context, pkg, version, ecosystem string) ([]Finding, error)
    Close() error
}
```

### Finding Structure

```go
type Finding struct {
    Layer    string // CVE, Metadata, Sandbox, YARA, ClamAV
    Severity string // LOW, MEDIUM, HIGH, CRITICAL
    Reason   string
    Details  string
}
```

## 🔧 Troubleshooting

### Common Issues

#### Docker Not Available
```bash
# Check Docker status
cc doctor

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
```

#### ClamAV Not Found
```bash
# Install ClamAV
sudo apt install clamav  # Ubuntu/Debian
brew install clamav       # macOS
```

#### Permission Issues
```bash
# Check permissions
ls -la ~/.config/secchain/
ls -la ~/.cache/secchain/

# Fix permissions
chmod 755 ~/.config/secchain/
chmod 755 ~/.cache/secchain/
```

#### Network Issues
```bash
# Use offline mode
cc scan --pkg example --ecosystem node --offline

# Check network connectivity
cc doctor
```

### Debug Mode

```bash
# Enable verbose output
cc scan --pkg example --ecosystem node --verbose

# Check logs
tail -f ~/.cache/secchain/secchain.log
```

### Getting Help

- [GitHub Issues](https://github.com/YsfDev1/SecChain/issues)
- [GitHub Discussions](https://github.com/YsfDev1/SecChain/discussions)
- [Security Issues](mailto:security@secchain.dev)

---

🛡️ **SecChain - Protecting your dependencies from supply chain attacks**
