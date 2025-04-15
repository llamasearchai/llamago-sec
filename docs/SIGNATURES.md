# LlamaSec Signature System

The LlamaSec vulnerability scanner uses a flexible, regex-based signature system to detect security vulnerabilities in web applications. This document explains how signatures work and how to create your own custom signatures.

## Table of Contents

- [Signature Structure](#signature-structure)
- [Signature Fields](#signature-fields)
- [Regular Expression Syntax](#regular-expression-syntax)
- [Severity Levels](#severity-levels)
- [Creating Custom Signatures](#creating-custom-signatures)
- [Testing Signatures](#testing-signatures)
- [Best Practices](#best-practices)
- [Example Signatures](#example-signatures)

## Signature Structure

LlamaSec signatures are defined in YAML format. Each signature represents a specific type of vulnerability or security issue. Signatures can be defined individually or grouped in a signatures file.

A signature file contains an array of signature objects:

```yaml
- id: "XSS-001"
  name: "Reflected Cross-Site Scripting"
  description: "Detects potential reflected XSS vulnerabilities"
  severity: "high"
  pattern: "document\\.write\\s*\\(\\s*[\"']?<[^>]+>[^<]*[\"']?\\s*\\+"
  category: "xss"
  tags: 
    - "xss"
    - "injection"
    - "owasp-top-10"

- id: "API-001"
  name: "API Key Exposure"
  description: "Detects exposed API keys in HTML/JavaScript"
  severity: "high"
  pattern: "[\"']?[a-zA-Z0-9_-]+_api_key[\"']?\\s*[=:]\\s*[\"'][a-zA-Z0-9_-]{16,}[\"']"
  category: "information-disclosure"
  tags:
    - "api"
    - "secrets"
    - "credentials"
```

## Signature Fields

Each signature has the following fields:

| Field | Required | Description |
|-------|----------|-------------|
| `id` | Yes | Unique identifier for the signature (e.g., "XSS-001") |
| `name` | Yes | Human-readable name of the vulnerability |
| `description` | Yes | Detailed description of what the signature detects |
| `severity` | Yes | Severity level: "critical", "high", "medium", "low", or "info" |
| `pattern` | Yes | Regular expression pattern to match vulnerabilities |
| `patterns` | No | Array of multiple patterns (alternative to single pattern) |
| `category` | No | Category for grouping similar vulnerabilities |
| `tags` | No | Array of tags for filtering and categorization |

### Notes:

- Either `pattern` or `patterns` must be specified, but not both
- If `patterns` is used, a match on any pattern will trigger the signature
- Use unique, descriptive IDs prefixed with a category abbreviation

## Regular Expression Syntax

LlamaSec uses Go's regular expression engine ([re2](https://github.com/google/re2/wiki/Syntax)). Some key points to remember:

- Patterns are case-sensitive by default
- Use `(?i)` for case-insensitive matching
- Use `\s` for whitespace, `\d` for digits
- Use `\b` for word boundaries
- Backslashes must be escaped (`\\`) in YAML

### Useful Regex Examples

```
# Match API keys
(?i)api[_-]?key[_-]?=\s*["']?[a-zA-Z0-9]{16,}["']?

# Match SQL injection patterns
(?i)(?:SELECT|INSERT|UPDATE|DELETE|UNION|DROP)\s+.*\s+(?:FROM|INTO|WHERE|TABLE|DATABASE)

# Match JWT tokens
eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}

# Match server information in headers
(?i)(apache|nginx|iis|tomcat|jetty|jboss|websphere|weblogic)[\s/][\d.]+
```

## Severity Levels

LlamaSec uses the following severity levels:

- **Critical**: Severe vulnerabilities that could lead to system compromise, data theft, or service disruption
- **High**: Serious vulnerabilities that could significantly impact security
- **Medium**: Moderate vulnerabilities that could pose security risks
- **Low**: Minor vulnerabilities with limited security impact
- **Info**: Informational findings that may not represent vulnerabilities

## Creating Custom Signatures

To create custom signatures:

1. Create a YAML file with your signatures (e.g., `custom-signatures.yaml`)
2. Use the structure described above
3. Run LlamaSec with the `-signatures` flag:

```
llamasec -signatures custom-signatures.yaml https://example.com
```

### Tips for Creating Effective Signatures

1. Start with specific patterns and broaden as needed
2. Test patterns against known vulnerable samples
3. Use word boundaries (`\b`) to avoid false positives
4. Use non-greedy quantifiers (`*?`, `+?`) when appropriate
5. Add context to patterns (e.g., match HTML tags for XSS)

## Testing Signatures

Test your signatures against known vulnerable and non-vulnerable content:

```go
package main

import (
	"fmt"
	"github.com/yourusername/llamasec/internal/signature"
)

func main() {
	// Create test signature
	signatures := []signature.Signature{
		{
			ID:          "TEST-XSS-001",
			Name:        "Test XSS",
			Description: "Detects XSS patterns",
			Severity:    "high",
			Pattern:     `document\.write\s*\(\s*["']?<[^>]+>[^<]*["']?\s*\+`,
		},
	}

	// Create signature manager
	sigManager, _ := signature.NewSignatureManager(signatures)

	// Test content
	vulnerableContent := `document.write("<div>" + userInput + "</div>");`
	safeContent := `console.log("Hello, world!");`

	// Check matches
	vulnMatches := sigManager.MatchContent(vulnerableContent, nil)
	safeMatches := sigManager.MatchContent(safeContent, nil)

	fmt.Printf("Vulnerable content matches: %d\n", len(vulnMatches))
	fmt.Printf("Safe content matches: %d\n", len(safeMatches))
}
```

## Best Practices

1. **Be specific**: Create targeted signatures to reduce false positives
2. **Provide context**: Add detailed descriptions and evidence
3. **Categorize properly**: Use appropriate severity levels and categories
4. **Use meaningful IDs**: Follow a consistent naming convention
5. **Test thoroughly**: Validate against known vulnerable and safe content
6. **Maintain signatures**: Update regularly to catch new vulnerability patterns

## Example Signatures

### Cross-Site Scripting (XSS)

```yaml
- id: "XSS-001"
  name: "Reflected Cross-Site Scripting"
  description: "Detects potential reflected XSS vulnerabilities"
  severity: "high"
  pattern: "document\\.write\\s*\\(\\s*[\"']?<[^>]+>[^<]*[\"']?\\s*\\+"
  category: "xss"
  tags: ["xss", "injection"]

- id: "XSS-002"
  name: "innerHTML XSS"
  description: "Detects potential DOM XSS via innerHTML"
  severity: "high"
  pattern: "(?i)\\.innerHTML\\s*=\\s*[\"']?.*?[\\${\\(]"
  category: "xss"
  tags: ["xss", "dom", "injection"]
```

### Sensitive Information Disclosure

```yaml
- id: "INFO-001"
  name: "API Key Exposure"
  description: "Detects exposed API keys"
  severity: "high"
  pattern: "(?i)api[_-]?key[_-]?=\\s*[\"']?[a-zA-Z0-9]{16,}[\"']?"
  category: "information-disclosure"
  tags: ["api", "secrets"]

- id: "INFO-002"
  name: "AWS Access Key Exposure"
  description: "Detects exposed AWS access keys"
  severity: "critical"
  pattern: "(?i)AKIA[0-9A-Z]{16}"
  category: "information-disclosure"
  tags: ["aws", "cloud", "secrets"]
```

### SQL Injection

```yaml
- id: "SQL-001"
  name: "SQL Injection"
  description: "Detects potential SQL injection vulnerabilities"
  severity: "high"
  pattern: "(?i)(?:SELECT|INSERT|UPDATE|DELETE|UNION|DROP)\\s+.*\\s+(?:FROM|INTO|WHERE|TABLE|DATABASE)"
  category: "injection"
  tags: ["sql", "injection", "database"]
```

### Server Information Disclosure

```yaml
- id: "SERVER-001"
  name: "Server Information Disclosure"
  description: "Detects server information disclosure in headers"
  severity: "low"
  pattern: "(?i)(apache|nginx|iis|tomcat|jetty|jboss|websphere|weblogic)[\\s/][\\d.]+"
  category: "information-disclosure"
  tags: ["headers", "server", "configuration"]
``` 