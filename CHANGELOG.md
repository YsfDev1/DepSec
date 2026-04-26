# Changelog

All notable changes to SecChain will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.1.3-alpha] - 2026-04-26

### Fixed
- Version string validation — "latest" now returns clear error instead of silent skip
- npm lockfileVersion 1, 2, and 3 support (npm 2-4, npm 6, npm 7+)
- MinSeverity config now actually applied in scan pipeline to filter findings
- doctor command properly registered in main.go
- sandbox.go verified with proper Docker container lifecycle structure
- scripts/build.sh and scripts/release.sh already exist and are comprehensive

### Changed
- Scan command now requires --version flag (no longer defaults to "latest")
- Findings are filtered by configured min_severity before display

## [v0.1.2-alpha] - 2026-04-26

### Changed
- Project renamed from DepSec to SecChain
- CLI binary renamed from secchain to cc
- Updated all documentation and references to use new naming
- Updated GitHub repository URLs to YsfDev1/SecChain
- Added support for "latest" version in scan commands with warning for CVE skip

### Added
- GitHub Actions CI/CD pipeline
- Comprehensive documentation structure
- Issue and PR templates
- Security policy and vulnerability reporting process
- Dependabot configuration for dependency management
- Improved .gitignore for Go projects
- Version string validation with semver format checking

### Fixed
- CVE layer now properly handles "latest" version by skipping with warning
- Fixed variable scope in pipeline.go for findings and err
- Config directory creation now happens before any file writes

### Security
- Added security scanning workflows
- Implemented vulnerability disclosure process
- Added security best practices documentation

## [0.1.0] - 2024-04-25

### Added
- Initial release of SecChain CLI security tool
- Real CVE detection using OSV API integration
- Package metadata analysis for Node.js and Python
- Multi-ecosystem support (Node.js, Python, Rust, Go, Ruby)
- Docker-based sandbox scanning framework
- YARA rule integration framework
- ClamAV antivirus scanning support
- Auto-scan shell hooks for npm, pip, cargo, go, gem
- Multiple output formats (table, JSON, minimal)
- Configuration management with TOML support
- SQLite caching for CVE and metadata
- Comprehensive health checking system
- Graceful degradation when optional components unavailable

### Security
- CVE-2021-23337 detection for lodash@4.17.15
- Real-time vulnerability database integration
- Isolated sandbox scanning environment
- Secure configuration management

### Documentation
- Complete CLI reference documentation
- Installation and setup guides
- Configuration options documentation
- Architecture and design documentation

### Tested
- Real vulnerability detection with lodash@4.17.15
- Metadata analysis with express@4.18.2
- Multi-platform build and testing
- Integration tests for core functionality

## [Future Releases]

### Planned for v0.2.0
- Enhanced Docker sandbox implementation
- Advanced YARA rule sets
- Performance optimizations
- Additional package ecosystems
- Web dashboard for scan results

### Planned for v0.3.0
- Machine learning-based anomaly detection
- Advanced threat intelligence integration
- Enterprise features and SSO support
- API server for remote scanning

---

## Version History

### v0.1.0 (Current)
- **Status**: Production Ready ✅
- **Features**: Core CVE and metadata scanning
- **Stability**: Stable for production use
- **Support**: Active development and maintenance

### Development Versions
- All pre-0.1.0 versions were development builds
- No stable releases before v0.1.0

## Security Updates

Security patches will be released as needed and documented here:

### Security Patches
- Check [Security Policy](docs/SECURITY.md) for vulnerability reporting
- Security updates will be backported to supported versions
- Critical security updates may be released out of cycle

## Compatibility

### Supported Go Versions
- Go 1.21+
- Tested on Go 1.21, 1.22, 1.23

### Supported Platforms
- Linux (AMD64, ARM64)
- macOS (Intel, Apple Silicon)
- Windows (AMD64)

### Dependencies
- See [go.mod](go.mod) for current dependencies
- Dependency updates handled automatically via Dependabot

## Migration Guide

### From Development Builds
If you were using development builds before v0.1.0:

1. **Configuration**: Configuration format is stable
2. **Commands**: All commands remain the same
3. **Cache**: Cache may need to be cleared (`rm -rf ~/.cache/secchain`)
4. **Binary**: Replace with official release binary

### Breaking Changes
- No breaking changes in v0.1.0
- Future breaking changes will be documented here

## Release Process

### Automated Releases
- Releases are automated via GitHub Actions
- Multi-platform binaries are built automatically
- Release notes are generated from commit messages

### Manual Steps
- Version bump in `main.go`
- Update CHANGELOG.md
- Create release tag
- GitHub Actions handles the rest

## Contributing to Changelog

### For Contributors
- Add entries to the "Unreleased" section
- Follow the Keep a Changelog format
- Include security implications for security-related changes
- Reference relevant issues and PRs

### For Release Managers
- Move items from "Unreleased" to appropriate version
- Add release date
- Update version history
- Ensure all breaking changes are documented

---

## Need Help?

- 📖 [Documentation](docs/README.md)
- 🐛 [Report Issues](https://github.com/YsfDev1/SecChain/issues)
- 💬 [Discussions](https://github.com/YsfDev1/SecChain/discussions)
- 🔒 [Security Issues](mailto:security@secchain.dev)

---

**🛡️ SecChain - Protecting your dependencies from supply chain attacks**
