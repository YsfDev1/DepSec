# SecChain — Package Security Scanner

[![CI](https://github.com/YsfDev1/SecChain/workflows/CI/badge.svg)](https://github.com/YsfDev1/SecChain/actions)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Go Report Card](https://goreportcard.com/badge/github.com/YsfDev1/SecChain)](https://goreportcard.com/report/github.com/YsfDev1/SecChain)
[![Go Version](https://img.shields.io/badge/Go-1.26+-blue.svg)](https://golang.org)
[![Release](https://github.com/YsfDev1/SecChain/workflows/Release/badge.svg)](https://github.com/YsfDev1/SecChain/releases)

> **SecChain (cc) automatically scans packages in an isolated Docker sandbox before they touch your system.**

## Features

- **Real CVE Detection** - Queries OSV database for actual vulnerabilities
- **Metadata Analysis** - Package registry metadata anomaly detection
- **Auto-Scan** - Shell hooks for automatic package scanning
- **Multi-Ecosystem** - Support for Node.js, Python, Rust, Go, Ruby
- **Multiple Formats** - Table, JSON, and minimal output formats

## 🚀 Quick Start

### Installation

#### Binary Installation (Recommended)

```bash
# Linux (AMD64)
curl -L -o secchain.tar.gz "https://github.com/YsfDev1/SecChain/releases/latest/download/secchain-linux-amd64.tar.gz"
tar -xzf secchain.tar.gz
chmod +x cc
sudo mv cc /usr/local/bin/

# macOS (Intel)
curl -L -o secchain.tar.gz "https://github.com/YsfDev1/SecChain/releases/latest/download/secchain-darwin-amd64.tar.gz"
tar -xzf secchain.tar.gz
chmod +x cc
sudo mv cc /usr/local/bin/

# Windows (AMD64)
powershell -Command "Invoke-WebRequest -Uri 'https://github.com/YsfDev1/SecChain/releases/latest/download/secchain-windows-amd64.zip' -OutFile 'secchain.zip'; Expand-Archive -Path 'secchain.zip' -DestinationPath '.'; Move-Item 'cc.exe' -Destination 'C:\Program Files\SecChain\'"
```

#### Go Install

```bash
go install github.com/YsfDev1/SecChain/cmd/secchain@latest
```

### First Use

```bash
# Check system health
cc doctor

# Scan a package with known vulnerabilities
cc scan --pkg lodash --version 4.17.15 --ecosystem node

# Enable auto-scan for automatic protection
cc auto enable

# View configuration
cc config show
```

## 📋 Example Usage

### CVE Scanning

```bash
# Scan a specific package
cc scan --pkg express --version 4.18.2 --ecosystem node

# Output:
# PACKAGE  VERSION  ECOSYSTEM  SEVERITY  LAYER  REASON
# express  4.18.2  node       LOW       CVE    CVE GHSA-qw6h-vgh9-j6wx: express vulnerable to XSS...

# Scan with JSON output
cc scan --pkg requests --version 2.28.1 --ecosystem python --format json
```

### Auto-Scan Protection

```bash
# Enable automatic scanning
cc auto enable
# ✅ Auto-scan enabled
# Shell: zsh
# Config: /home/user/.zshrc
#
# 📝 Restart your shell or run:
#    source /home/user/.zshrc

# Check status
cc auto status
# SecChain Auto-Scan Status:
#   Enabled: true
#   Shell: zsh
#   Config: /home/user/.zshrc
#   Hooks: npm, pip, cargo, go, gem
```

### Configuration Management

```bash
# View current configuration
cc config show

# Set strict mode
cc config set mode strict

# Set minimum severity to high
cc config set min_severity high

# Enable offline mode
cc config set offline true
```

## 🏗️ Architecture

```mermaid
graph TD
    A[CLI Command] --> B[Scanning Pipeline]
    B --> C[Dependency Resolver]
    B --> D[CVE Scanner]
    B --> E[Metadata Scanner]
    
    C --> I[Package Registries]
    D --> J[OSV API]
    E --> I
    
    B --> N[Output Formatter]
    N --> O[Table/JSON/Minimal]
```

## 📖 Documentation

- [📚 Full Documentation](docs/README.md)
- [🔧 Configuration Guide](docs/README.md#configuration)
- [🛡️ Security Policy](docs/SECURITY.md)
- [🤝 Contributing Guide](CONTRIBUTING.md)
- [📋 API Reference](docs/README.md#api-reference)

## 🎯 Supported Ecosystems

| Ecosystem | Package Manager | Status |
|-----------|----------------|--------|
| Node.js   | npm, yarn      | ✅ Full |
| Python    | pip, poetry    | ✅ Full |
| Rust      | cargo         | ✅ Full |
| Go        | go modules    | ✅ Full |
| Ruby      | gem, bundler   | ✅ Full |

## 🔧 Commands

| Command | Description |
|---------|-------------|
| `cc scan` | Scan packages and projects |
| `cc doctor` | Check system health |
| `cc auto` | Manage auto-scan hooks |
| `cc config` | View and modify configuration |
| `cc report` | Show scan reports and history |
| `cc update-rules` | Update YARA rules and CVE cache |
| `cc version` | Show version information |

## 🛠️ Development

### Prerequisites

- Go 1.21 or later
- Docker (optional, for sandbox scanning)
- Git

### Setup

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
├── .github/       # GitHub workflows and templates
└── scripts/       # Build and utility scripts
```

### Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📊 Real-World Results

SecChain has successfully identified real vulnerabilities in popular packages:

### lodash@4.17.15
```
PACKAGE  VERSION  ECOSYSTEM  SEVERITY  LAYER  REASON
lodash   4.17.15  node       LOW       CVE    CVE GHSA-29mw-wpgm-hmr9: Regular Expression Den...
lodash   4.17.15  node       LOW       CVE    CVE GHSA-35jh-r3h4-6jhm: Command Injection in l...
lodash   4.17.15  node       LOW       CVE    CVE GHSA-f23m-r3pf-42rh: lodash vulnerable to P...
lodash   4.17.15  node       LOW       CVE    CVE GHSA-p6mc-m468-83gw: Prototype Pollution in...
```

### express@4.18.2
```
{
  "Package": "express",
  "Version": "4.18.2",
  "Ecosystem": "node",
  "Findings": [
    {
      "Layer": "CVE",
      "Severity": "LOW",
      "Reason": "CVE GHSA-qw6h-vgh9-j6wx: express vulnerable to XSS via response.redirect()"
    }
  ]
}
```

## 🔒 Security

SecChain takes security seriously:

- ✅ **Never writes package contents to host filesystem**
- ✅ **Uses isolated Docker containers for scanning**
- ✅ **Validates all user input and package metadata**
- ✅ **Operates with minimal required permissions**
- ✅ **Follows principle of least privilege**

For security issues, please email [security@secchain.dev](mailto:security@secchain.dev) instead of using public issues.

## 📜 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OSV.dev](https://osv.dev/) - Open Source Vulnerability database
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- [Docker](https://www.docker.com/) - Container platform
- [YARA](https://virustotal.github.io/yara/) - Pattern matching framework
- [ClamAV](https://www.clamav.net/) - Antivirus engine

## 📞 Support

- 🐛 [Report Bugs](https://github.com/YsfDev1/SecChain/issues)
- 💡 [Request Features](https://github.com/YsfDev1/SecChain/issues)
- 💬 [Discussions](https://github.com/YsfDev1/SecChain/discussions)
- 📧 [Email Support](mailto:hello@secchain.dev)
- 🔒 [Security Issues](mailto:security@secchain.dev)

---

**🛡️ SecChain - Protecting your dependencies from supply chain attacks**
