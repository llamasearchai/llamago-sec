# Contributing to LlamaSec

Thank you for considering contributing to LlamaSec! This document outlines the process for contributing to the project and helps ensure a smooth collaboration experience.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Submitting Changes](#submitting-changes)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Vulnerability Signatures](#vulnerability-signatures)
- [Release Process](#release-process)
- [Community](#community)

## Code of Conduct

This project adheres to a Code of Conduct that sets expectations for participation in our community. By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

We expect all contributors to:

- Be respectful and inclusive in their language and actions
- Be collaborative and open to different perspectives
- Focus on what is best for the community
- Show empathy towards other community members

## Getting Started

### Prerequisites

- Go 1.18 or higher
- Git
- Docker (optional, for containerized development)

### Setting Up Your Development Environment

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/<your-username>/llamasec.git
   cd llamasec
   ```
3. Add the upstream repository as a remote to keep your fork in sync:
   ```bash
   git remote add upstream https://github.com/yourusername/llamasec.git
   ```
4. Install dependencies:
   ```bash
   go mod download
   ```

### Running LlamaSec Locally

Build and run the project locally:

```bash
go build -o llamasec ./cmd/llamasec
./llamasec --help
```

## Development Workflow

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature/your-feature-name
   ```
   
2. Make your changes and commit them with clear, descriptive messages:
   ```bash
   git commit -m "Add feature X" -m "This feature adds the ability to scan for X vulnerability type"
   ```

3. Keep your branch updated with upstream changes:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

4. Push your changes to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

## Submitting Changes

1. Ensure your code adheres to our [Coding Standards](#coding-standards)
2. Make sure all tests pass with `go test ./...`
3. Update documentation as needed
4. Submit a pull request (PR) from your fork to the main repository
5. In your PR description, clearly explain the changes and their purpose
6. Link any related issues using keywords like "Fixes #123" or "Resolves #456"

### Pull Request Process

1. Maintainers will review your PR
2. Address any requested changes or feedback
3. Once approved, a maintainer will merge your PR
4. Celebrate your contribution! 🎉

## Coding Standards

We follow standard Go best practices and conventions:

- Code should be formatted with `gofmt` or `go fmt`
- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use meaningful variable and function names
- Write comments for non-obvious code
- Aim for code that is clear and maintainable over clever solutions
- Keep functions focused and not too long (ideally under 50 lines)
- Use proper error handling (no panics in production code)

### Code Quality Tools

We use several tools to maintain code quality:

- `golangci-lint` for static code analysis
- `go vet` to examine Go source code and report suspicious constructs
- `gosec` for security-focused static analysis

To run these tools:

```bash
# Install golangci-lint
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Run the linter
golangci-lint run

# Run Go vet
go vet ./...

# Run gosec (if installed)
gosec ./...
```

## Testing

All code changes should include appropriate tests:

- **Unit tests** for individual functions and components
- **Integration tests** for features that interact with external systems
- **End-to-end tests** for complete workflows

### Writing Tests

- Place tests in the same package as the code being tested
- Name test files with `_test.go` suffix
- Use table-driven tests for multiple test cases
- Aim for high test coverage, especially for critical code paths
- Mock external dependencies for more reliable tests

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with race detection
go test -race ./...

# Run tests with coverage
go test -cover ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Documentation

Good documentation is critical for project adoption and user satisfaction:

- **Code comments**: Document complex logic and function purposes
- **GoDoc**: Follow [GoDoc conventions](https://blog.golang.org/godoc-documenting-go-code)
- **README**: Keep it updated with installation and basic usage instructions
- **Wiki/Docs**: Maintain comprehensive documentation for advanced features

When adding new features, please update:

1. Code comments and GoDoc
2. README.md if the feature changes basic usage
3. Official documentation (if applicable)
4. Examples in the `examples/` directory (if applicable)

## Vulnerability Signatures

LlamaSec relies on YAML-based vulnerability signatures. When adding new signatures:

1. Place them in the `config/signatures.yaml` file
2. Follow the established format:
   ```yaml
   - id: "UNIQUE-ID"
     name: "Vulnerability Name"
     description: "Detailed description"
     severity: "high|medium|low|info"
     patterns:
       - "regex_pattern_here"
   ```
3. Include patterns that are specific enough to avoid false positives
4. Document any complex regex patterns
5. Add tests to verify signature detection

## Release Process

Our release process follows semantic versioning (SEMVER):

1. **Major releases** (X.0.0): Breaking changes
2. **Minor releases** (0.X.0): New features, non-breaking
3. **Patch releases** (0.0.X): Bug fixes and minor improvements

Release tasks:

1. Update version information in relevant files
2. Merge release PR to main
3. Tag the release commit
4. Create GitHub release with changelog
5. Build and upload binaries to release
6. Update documentation for the new version
7. Announce the release in appropriate channels

## Community

We value our community and encourage active participation:

- **Issues**: Use GitHub issues to report bugs or request features
- **Discussions**: Join GitHub Discussions for broader topics
- **Good First Issues**: Look for issues labeled "good first issue" to get started

Thank you for contributing to LlamaSec! Your efforts help make the project better for everyone. 