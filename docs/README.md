# DepSec Documentation

Welcome to the DepSec documentation! Here you'll find comprehensive guides for using and contributing to DepSec.

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

### What is DepSec?

DepSec is a CLI security tool that automatically scans packages and their dependencies in an isolated sandbox before they are installed on the host system. It provides layered security scanning including:

- **CVE Detection** - Real-time vulnerability scanning using OSV database
- **Metadata Analysis** - Package registry metadata anomaly detection
- **Sandbox Scanning** - Isolated container-based package analysis
- **YARA Rules** - Custom rule-based binary analysis
- **ClamAV Integration** - Antivirus scanning

### Quick Start

```bash
# Install DepSec
curl -L https://github.com/your-org/DepSec/releases/latest/download/depsec-linux-amd64.tar.gz | tar -xz
sudo mv depsec /usr/local/bin/

# Scan a package
depsec scan --pkg lodash --version 4.17.15 --ecosystem node

# Enable auto-scan
depsec auto enable

# Check system health
depsec doctor
```

## 🔧 Installation

### Binary Installation

#### Linux (AMD64)
```bash
curl -L -o depsec.tar.gz "https://github.com/your-org/DepSec/releases/latest/download/depsec-linux-amd64.tar.gz"
tar -xzf depsec.tar.gz
chmod +x depsec
sudo mv depsec /usr/local/bin/
```

#### macOS (Intel)
```bash
curl -L -o depsec.tar.gz "https://github.com/your-org/DepSec/releases/latest/download/depsec-darwin-amd64.tar.gz"
tar -xzf depsec.tar.gz
chmod +x depsec
sudo mv depsec /usr/local/bin/
```

#### macOS (Apple Silicon)
```bash
curl -L -o depsec.tar.gz "https://github.com/your-org/DepSec/releases/latest/download/depsec-darwin-arm64.tar.gz"
tar -xzf depsec.tar.gz
chmod +x depsec
sudo mv depsec /usr/local/bin/
```

#### Windows (AMD64)
```powershell
Invoke-WebRequest -Uri "https://github.com/your-org/DepSec/releases/latest/download/depsec-windows-amd64.zip" -OutFile "depsec.zip"
Expand-Archive -Path "depsec.zip" -DestinationPath "."
Move-Item "depsec.exe" -Destination "C:\Program Files\DepSec\"
```

### Go Install

```bash
go install github.com/your-org/DepSec/cmd/depsec@latest
```

### From Source

```bash
git clone https://github.com/your-org/DepSec.git
cd DepSec
go build -o depsec main.go
sudo mv depsec /usr/local/bin/
```

## ⚙️ Configuration

DepSec uses a TOML configuration file located at `~/.config/depsec/config.toml`.

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
depsec config show

# Set configuration values
depsec config set mode strict
depsec config set min_severity high
depsec config set offline true

# Reset to defaults
depsec config reset
```

## 📋 Commands

### Scanning Commands

#### Scan a Package
```bash
depsec scan --pkg <package> --version <version> --ecosystem <ecosystem>
```

**Examples:**
```bash
# Scan a specific version
depsec scan --pkg lodash --version 4.17.15 --ecosystem node

# Scan latest version
depsec scan --pkg express --ecosystem node

# Scan with different output format
depsec scan --pkg requests --ecosystem python --format json

# Scan in strict mode
depsec scan --pkg react --ecosystem node --strict
```

#### Scan a Project
```bash
depsec scan /path/to/project
```

### Auto-Scan Commands

#### Enable Auto-Scan
```bash
depsec auto enable
```

This injects shell hooks that automatically scan packages before installation.

#### Disable Auto-Scan
```bash
depsec auto disable
```

#### Check Status
```bash
depsec auto status
```

### Configuration Commands

#### Show Configuration
```bash
depsec config show
```

#### Set Configuration
```bash
depsec config set <key> <value>
```

#### Reset Configuration
```bash
depsec config reset
```

### Maintenance Commands

#### System Health Check
```bash
depsec doctor
```

#### Update Rules and Cache
```bash
depsec update-rules
```

#### Show Version
```bash
depsec version
```

### Report Commands

#### Show Last Scan Report
```bash
depsec report
```

#### Show Scan History
```bash
depsec report --history
```

#### Show Package Report
```bash
depsec report --pkg lodash
```

## 🔍 Security Scanning

### CVE Detection

DepSec queries the OSV (Open Source Vulnerability) database for known vulnerabilities:

```bash
# CVE scanning example
depsec scan --pkg lodash --version 4.17.15 --ecosystem node

# Output example
PACKAGE  VERSION  ECOSYSTEM  SEVERITY  LAYER  REASON
lodash   4.17.15  node       HIGH      CVE    CVE-2021-23337: Prototype Pollution
lodash   4.17.15  node       MEDIUM    CVE    CVE-2022-2879: Regular Expression DoS
```

### Metadata Analysis

DepSec analyzes package metadata for anomalies:

- **Publish Date Analysis** - Identifies suspiciously new or old packages
- **Typosquatting Detection** - Detects packages with similar names to popular packages
- **Install Script Analysis** - Scans package install scripts for suspicious commands

### Sandbox Scanning

When Docker is available, DepSec can scan packages in an isolated container:

- **Network Monitoring** - Detects unauthorized network calls
- **File System Monitoring** - Monitors file access patterns
- **Process Monitoring** - Analyzes running processes
- **Environment Access** - Monitors environment variable access

### YARA Rules

DepSec uses YARA rules for binary pattern matching:

```bash
# Update YARA rules
depsec update-rules

# Custom rules location
~/.config/depsec/rules/
```

## 🛠️ Development

### Development Setup

```bash
# Clone the repository
git clone https://github.com/your-org/DepSec.git
cd DepSec

# Install dependencies
go mod tidy

# Build the project
go build -o depsec main.go

# Run tests
go test ./...

# Run integration tests
./test_real_scanning.sh
```

### Project Structure

```
DepSec/
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
depsec doctor

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
ls -la ~/.config/depsec/
ls -la ~/.cache/depsec/

# Fix permissions
chmod 755 ~/.config/depsec/
chmod 755 ~/.cache/depsec/
```

#### Network Issues
```bash
# Use offline mode
depsec scan --pkg example --ecosystem node --offline

# Check network connectivity
depsec doctor
```

### Debug Mode

```bash
# Enable verbose output
depsec scan --pkg example --ecosystem node --verbose

# Check logs
tail -f ~/.cache/depsec/depsec.log
```

### Getting Help

- [GitHub Issues](https://github.com/your-org/DepSec/issues)
- [GitHub Discussions](https://github.com/your-org/DepSec/discussions)
- [Security Issues](mailto:security@depsec.dev)

---

🛡️ **DepSec - Protecting your dependencies from supply chain attacks**
