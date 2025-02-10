# 🦙 LlamaSec - Concurrent URL Vulnerability Scanner 🦙

[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/llamasec)](https://goreportcard.com/report/github.com/yourusername/llamasec)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![codecov](https://codecov.io/gh/yourusername/llamasec/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/llamasec)
[![Docker Pulls](https://img.shields.io/docker/pulls/yourusername/llamasec)](https://hub.docker.com/r/yourusername/llamasec)

LlamaSec is a high-performance, concurrent URL vulnerability scanner written in Go. It leverages Go's powerful concurrency model with goroutines and channels to scan multiple websites simultaneously for common security vulnerabilities and misconfigurations.

![LlamaSec Screenshot](docs/images/screenshot.png)

## 🔍 Features

- **Concurrent URL Scanning**: Efficiently scan multiple URLs simultaneously
- **Vulnerability Detection**: Identify common security issues such as:
  - Exposed API keys and secrets
  - SQL injection vectors
  - Cross-Site Scripting (XSS) vectors
  - Outdated software versions
  - Information disclosure
  - Missing security headers
  - Directory listing
  - Debug information exposure
- **AI-Powered Analysis**: ✨ Leverage OpenAI to analyze vulnerabilities and provide remediation guidance
- **TLS Inspection**: Analyze TLS/SSL configuration for weaknesses
- **Flexible Output Formats**: Generate reports in Markdown, JSON, or CSV
- **Rate Limiting**: Control request rates to avoid overwhelming target servers
- **Proxy Support**: Route requests through HTTP/SOCKS proxies
- **Extensive Configurability**: Customize behavior through CLI flags or config files
- **Detailed Reporting**: Comprehensive vulnerability reports with severity ratings
- **Error Handling**: Robust error handling with automatic retries
- **Docker Support**: Easily deploy and run in containers
- **WebAssembly Plugin System**: Extend scanning capabilities with custom WASM modules

## 📋 Requirements

- Go 1.20 or higher
- Internet connection (for scanning external URLs)
- OpenAI API key (optional, for AI-powered vulnerability analysis)

## 🚀 Installation

### Using Go Install

```bash
go install github.com/yourusername/llamasec@latest
```

### From Source

```bash
git clone https://github.com/yourusername/llamasec.git
cd llamasec
go build ./cmd/llamasec
```

### Using Docker

```bash
docker pull yourusername/llamasec:latest
```

## 🔧 Usage

### Basic Usage

Scan a single URL:

```bash
llamasec https://example.com
```

Scan multiple URLs:

```bash
llamasec https://example.com https://example.org https://example.net
```

Scan URLs from a file (one URL per line):

```bash
llamasec -file urls.txt
```

### AI-Powered Vulnerability Analysis

LlamaSec can leverage OpenAI's API to provide detailed vulnerability analysis, impact assessment, and remediation guidance. To enable this feature:

```bash
llamasec -enable-ai -openai-key "your-openai-api-key" https://example.com
```

The AI-powered analysis will:
1. Analyze the context of each vulnerability
2. Provide detailed explanations of security risks
3. Assess the potential impact
4. Recommend specific remediation steps
5. Include references for further learning

This is particularly useful for:
- Understanding complex vulnerabilities
- Prioritizing remediation efforts
- Learning about security best practices
- Explaining technical findings to non-technical stakeholders

### WebAssembly Plugins

LlamaSec supports extending its scanning capabilities with custom WebAssembly plugins:

```bash
llamasec -wasm-plugin my-custom-scanner.wasm https://example.com
```

This allows you to:
- Implement custom scanning logic in any language that compiles to WASM
- Detect application-specific vulnerabilities
- Integrate with other security tools
- Add proprietary detection capabilities

See [Using WebAssembly Plugins](docs/wasm-plugins.md) for more information.

### Advanced Options

```
Usage of llamasec:
  -concurrency int
        Number of concurrent requests (default 10)
  -config string
        Path to configuration file
  -enable-ai
        Enable AI-powered vulnerability analysis
  -file string
        File containing URLs to scan (one per line)
  -format string
        Output format (markdown, json, csv) (default "markdown")
  -openai-key string
        OpenAI API key for enhanced vulnerability analysis
  -output string
        Output file path (default "llamasec_report.md")
  -proxy string
        Proxy URL (e.g., http://proxy:8080)
  -rate float
        Rate limit in requests per second (default 5.0)
  -signatures string
        Path to vulnerability signatures file (default "config/signatures.yaml")
  -timeout duration
        HTTP request timeout (default 30s)
  -user-agent string
        User-Agent string for HTTP requests (default "LlamaSec/1.0.0")
  -verbose
        Enable verbose output
  -version
        Print version information and exit
  -serve
        Serve the report on a web server
  -port int
        Port to serve the report on (only used with -serve) (default 8080)
  -wasm-plugin string
        Path to WebAssembly plugin for custom scanning logic
```

### Configuration File

You can use a YAML or JSON configuration file to customize LlamaSec's behavior:

```bash
llamasec -config config.yaml -file urls.txt
```

Sample configuration file (YAML):

```yaml
concurrency: 15
timeout: 45s
outputFormat: "json"
outputFile: "vulnerabilities.json"
rateLimit: 10.0
verboseOutput: true
enableAIAnalysis: true
openAIAPIKey: "your-openai-api-key"
```

### Docker Usage

```bash
docker run -v $(pwd):/app/reports -e OPENAI_API_KEY="your-openai-api-key" yourusername/llamasec -output /app/reports/report.md -enable-ai https://example.com
```

## 📊 Performance

LlamaSec's concurrent scanning significantly outperforms sequential scanning, particularly for large batches of URLs. Here are some benchmark results scanning 100 URLs:

| Method | Time |
|--------|------|
| Sequential | 42.3s |
| Concurrent (10 workers) | 4.7s |
| Concurrent (20 workers) | 2.4s |

For more detailed performance information, see the [Performance Documentation](docs/PERFORMANCE.md).

## 🛡️ Vulnerability Signatures

LlamaSec uses a YAML-based signature database to detect vulnerabilities. The default signatures cover common web vulnerabilities, but you can customize or extend these by creating your own signature file:

```yaml
- id: "CUSTOM-001"
  name: "Custom Vulnerability"
  description: "A custom vulnerability pattern"
  severity: "high"
  pattern: "regex_pattern_here"
```

For more information on creating custom signatures, see [Custom Signatures Documentation](docs/SIGNATURES.md).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

For major changes, please open an issue first to discuss what you would like to change.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgements

- The Go team for creating an excellent language for concurrent programming
- OpenAI for providing the APIs that power our advanced vulnerability analysis
- The open-source security community for inspiration and guidance
- All contributors who have helped improve this project

## 📊 Sample Report

LlamaSec generates comprehensive reports in various formats. Here's a sample of the Markdown report:

```markdown
# LlamaSec Security Scan Report

**Date:** 2025-03-09 19:58:44

**Total URLs Scanned:** 1

**Total Vulnerabilities Found:** 0

## Summary

| URL | Status | Vulnerabilities | Response Time | Size |
|-----|--------|----------------|---------------|------|
| https://example.com | 200 | 0 | 275.106208ms | 1.2 KB |

## Detailed Results

### https://example.com

- **Status Code:** 200
- **Response Time:** 275.106208ms
- **Response Size:** 1.2 KB

#### TLS Information

- **TLS Version:** TLS 1.3
- **Cipher Suite:** Unknown (0x1302)
- **Certificate Expiration:** 2026-01-15
- **Certificate Issuer:** CN=DigiCert Global G3 TLS ECC SHA384 2020 CA1,O=DigiCert Inc,C=US
- **Certificate Subject:** CN=*.example.com,O=Internet Corporation for Assigned Names and Numbers,L=Los Angeles,ST=California,C=US
```

## 🛡️ Vulnerability Signatures

LlamaSec uses regex-based signature matching to detect vulnerabilities. The built-in signatures cover common web vulnerabilities, including:

- Cross-Site Scripting (XSS)
- SQL Injection
- API Key Exposure
- And more...

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 
# Updated in commit 1 - 2025-04-04 17:36:30

# Updated in commit 9 - 2025-04-04 17:36:30

# Updated in commit 17 - 2025-04-04 17:36:30

# Updated in commit 25 - 2025-04-04 17:36:31

# Updated in commit 1 - 2025-04-05 14:38:16

# Updated in commit 9 - 2025-04-05 14:38:16

# Updated in commit 17 - 2025-04-05 14:38:16

# Updated in commit 25 - 2025-04-05 14:38:16

# Updated in commit 1 - 2025-04-05 15:24:42

# Updated in commit 9 - 2025-04-05 15:24:43

# Updated in commit 17 - 2025-04-05 15:24:43

# Updated in commit 25 - 2025-04-05 15:24:43

# Updated in commit 1 - 2025-04-05 16:00:26

# Updated in commit 9 - 2025-04-05 16:00:26

# Updated in commit 17 - 2025-04-05 16:00:26

# Updated in commit 25 - 2025-04-05 16:00:26

# Updated in commit 1 - 2025-04-05 17:05:44

# Updated in commit 9 - 2025-04-05 17:05:44

# Updated in commit 17 - 2025-04-05 17:05:44
