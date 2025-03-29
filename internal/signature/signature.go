package signature

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// DefaultSignatureDBPath is the default path to the signatures file
const DefaultSignatureDBPath = "config/signatures.yaml"

// Signature represents a security signature for vulnerability detection
type Signature struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Severity    string   `yaml:"severity" json:"severity"`
	Pattern     string   `yaml:"pattern" json:"pattern"`
	Patterns    []string `yaml:"patterns,omitempty" json:"patterns,omitempty"`
	Category    string   `yaml:"category,omitempty" json:"category,omitempty"`
	Tags        []string `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// SignatureMatch represents a matched signature
type SignatureMatch struct {
	SignatureID   string
	SignatureName string
	Description   string
	Severity      string
	Evidence      string
}

// SignatureManager manages signatures and performs matching
type SignatureManager struct {
	signatures   []Signature
	regexPattern map[string]*regexp.Regexp
}

// NewSignatureManager creates a new signature manager
func NewSignatureManager(signatures []Signature) (*SignatureManager, error) {
	manager := &SignatureManager{
		signatures:   signatures,
		regexPattern: make(map[string]*regexp.Regexp),
	}

	// Pre-compile regular expressions
	for _, sig := range signatures {
		// Compile primary pattern
		if sig.Pattern != "" {
			regex, err := regexp.Compile(sig.Pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex pattern for signature %s: %v", sig.ID, err)
			}
			manager.regexPattern[sig.ID+"-primary"] = regex
		}

		// Compile additional patterns
		for i, pattern := range sig.Patterns {
			regex, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("invalid regex pattern %d for signature %s: %v", i, sig.ID, err)
			}
			manager.regexPattern[fmt.Sprintf("%s-extra-%d", sig.ID, i)] = regex
		}
	}

	return manager, nil
}

// MatchContent checks content for signature matches
func (sm *SignatureManager) MatchContent(content string, headers map[string]string) []SignatureMatch {
	var matches []SignatureMatch

	// Check each signature
	for _, sig := range sm.signatures {
		var found bool

		// Check primary pattern
		if primaryPattern, ok := sm.regexPattern[sig.ID+"-primary"]; ok {
			if match := primaryPattern.FindString(content); match != "" {
				matches = append(matches, SignatureMatch{
					SignatureID:   sig.ID,
					SignatureName: sig.Name,
					Description:   sig.Description,
					Severity:      sig.Severity,
					Evidence:      match,
				})
				found = true
			}
		}

		// If primary pattern didn't match, check additional patterns
		if !found {
			for i := range sig.Patterns {
				if pattern, ok := sm.regexPattern[fmt.Sprintf("%s-extra-%d", sig.ID, i)]; ok {
					if match := pattern.FindString(content); match != "" {
						matches = append(matches, SignatureMatch{
							SignatureID:   sig.ID,
							SignatureName: sig.Name,
							Description:   sig.Description,
							Severity:      sig.Severity,
							Evidence:      match,
						})
						break
					}
				}
			}
		}
	}

	return matches
}

// MatchHeaders checks headers for signature matches
func (sm *SignatureManager) MatchHeaders(headers map[string]string) []SignatureMatch {
	// Convert headers to a single string to simplify matching
	var headersStr strings.Builder
	for name, value := range headers {
		headersStr.WriteString(fmt.Sprintf("%s: %s\n", name, value))
	}

	// Use the standard content matching on the headers string
	return sm.MatchContent(headersStr.String(), nil)
}

// GetSignatures returns all signatures
func (sm *SignatureManager) GetSignatures() []Signature {
	// Return a copy of signatures to prevent modification
	signaturesCopy := make([]Signature, len(sm.signatures))
	copy(signaturesCopy, sm.signatures)
	return signaturesCopy
}

// isMissingSecurityHeader checks if the header is a security header that should be present
func isMissingSecurityHeader(header string) bool {
	securityHeaders := map[string]bool{
		"Content-Security-Policy":      true,
		"X-Content-Type-Options":       true,
		"X-Frame-Options":              true,
		"X-XSS-Protection":             true,
		"Strict-Transport-Security":    true,
		"Referrer-Policy":              true,
		"Permissions-Policy":           true,
		"Cross-Origin-Opener-Policy":   true,
		"Cross-Origin-Resource-Policy": true,
	}

	return securityHeaders[header]
}

// isVersionDisclosure checks if the header reveals version information
func isVersionDisclosure(header, value string) bool {
	// Common headers that might disclose version info
	versionHeaders := map[string]bool{
		"server":           true,
		"x-powered-by":     true,
		"x-aspnet-version": true,
		"x-runtime":        true,
	}

	if !versionHeaders[strings.ToLower(header)] {
		return false
	}

	// Check if value contains version numbers
	versionRegex := regexp.MustCompile(`(?i)(^|[^\d])(\d+\.[\d\.]+)($|[^\d])`)
	return versionRegex.MatchString(value)
}

// createDefaultSignatures creates a default signatures file
func createDefaultSignatures(path string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Default signatures content
	content := `# LlamaSec Default Vulnerability Signatures
- id: "XSS-001"
  name: "Cross-Site Scripting (Reflected)"
  description: "Detects potential reflected XSS vulnerabilities"
  severity: "high"
  patterns:
    - "<script[^>]*>.*?</script>"
    - "javascript:.*?\\("
    - "on(load|click|mouseover|focus|blur)\\s*=\\s*[\"']"

- id: "INFO-001"
  name: "Information Disclosure"
  description: "Detects potential information disclosure in HTTP headers"
  severity: "medium"
  headers:
    - "X-Powered-By"
    - "Server"
    - "X-AspNet-Version"
    - "X-Runtime"

- id: "SEC-001"
  name: "Missing Security Headers"
  description: "Detects missing important security headers"
  severity: "medium"
  headers:
    - "Content-Security-Policy"
    - "X-Frame-Options"
    - "X-XSS-Protection"
    - "Strict-Transport-Security"

- id: "API-001"
  name: "API Key Exposure"
  description: "Detects potential exposure of API keys or tokens"
  severity: "high"
  patterns:
    - "api[_-]?key[\"']?\\s*[=:]\\s*[\"'][a-zA-Z0-9_\\-]{20,}[\"']"
    - "access[_-]?token[\"']?\\s*[=:]\\s*[\"'][a-zA-Z0-9_\\-]{20,}[\"']"
    - "secret[_-]?key[\"']?\\s*[=:]\\s*[\"'][a-zA-Z0-9_\\-]{20,}[\"']"

- id: "SQL-001"
  name: "SQL Injection"
  description: "Detects potential SQL injection attack vectors"
  severity: "high"
  patterns:
    - "\\b(union|select|insert|update|delete|drop|alter)\\b.*?\\b(from|into|where)\\b"
    - "';\\s*--"
    - "\"';\\s*or\\s*'1'='1"
    - "';\\s*or\\s*1=1"
`

	// Write the file
	return ioutil.WriteFile(path, []byte(content), 0644)
}
