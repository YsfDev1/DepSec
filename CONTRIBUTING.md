# Contributing to DepSec

Thank you for your interest in contributing to DepSec! This document provides guidelines and information for contributors.

## 🚀 Quick Start

1. Fork the repository
2. Clone your fork locally
3. Create a new branch for your feature
4. Make your changes
5. Test your changes thoroughly
6. Submit a Pull Request

## 🛠️ Development Setup

### Prerequisites

- Go 1.21 or later
- Docker (optional, for sandbox scanning)
- Git

### Setup

```bash
# Clone the repository
git clone https://github.com/your-username/DepSec.git
cd DepSec

# Install dependencies
go mod tidy

# Build the project
go build -o depsec main.go

# Run tests
go test ./...
```

### Testing

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run integration tests
./test_real_scanning.sh
```

## 📝 Code Style

We follow the standard Go coding conventions:

- Use `gofmt` to format code
- Use `golint` for linting
- Write meaningful commit messages
- Add tests for new features
- Document public functions and types

## 🏗️ Project Structure

```
DepSec/
├── cmd/           # CLI commands
├── scanner/       # Core scanning logic
├── config/        # Configuration management
├── cache/         # Caching layer
├── hooks/         # Shell hook management
├── output/        # Output formatting
├── rules/         # YARA rules (created on first use)
├── .github/       # GitHub workflows and templates
├── docs/          # Documentation
└── scripts/       # Build and utility scripts
```

## 🐛 Bug Reports

When filing bug reports, please include:

- Go version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

## ✨ Feature Requests

- Use descriptive titles
- Explain the use case
- Consider breaking changes
- Discuss implementation approach if possible

## 🔄 Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### PR Requirements

- Tests pass for new functionality
- Code follows project style guidelines
- Documentation is updated
- Commit messages are clear and descriptive
- PR description explains the changes

## 📚 Development Guidelines

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

### Security Considerations

- Never write package contents to host filesystem
- Always validate user input
- Use secure defaults
- Follow principle of least privilege

## 🏷️ Release Process

Releases are automated through GitHub Actions:

1. Update version in `main.go`
2. Update CHANGELOG.md
3. Create a release tag
4. GitHub Actions builds and releases binaries

## 🤝 Community

- Be respectful and inclusive
- Help others in issues and discussions
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md)
- Ask questions in GitHub Discussions

## 📖 Resources

- [Go Documentation](https://golang.org/doc/)
- [Effective Go](https://golang.org/doc/effective_go.html)
- [Cobra CLI Guide](https://github.com/spf13/cobra/blob/main/README.md)
- [OSV API Documentation](https://osv.dev/docs/)

## 🙋‍♂️ Getting Help

- Create an issue for bugs or questions
- Start a discussion for general topics
- Check existing issues and documentation
- Join our community discussions

Thank you for contributing to DepSec! 🛡️
