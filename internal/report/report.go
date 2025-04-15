package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ScanResult represents a scan result for reporting
type ScanResult struct {
	URL             string               `json:"url" yaml:"url"`
	StatusCode      int                  `json:"statusCode" yaml:"statusCode"`
	ResponseTime    time.Duration        `json:"responseTime" yaml:"responseTime"`
	ResponseSize    int64                `json:"responseSize" yaml:"responseSize"`
	Headers         map[string]string    `json:"headers" yaml:"headers"`
	Vulnerabilities []VulnerabilityMatch `json:"vulnerabilities" yaml:"vulnerabilities"`
	Error           string               `json:"error,omitempty" yaml:"error,omitempty"`
	TLSInfo         *TLSInfo             `json:"tlsInfo,omitempty" yaml:"tlsInfo,omitempty"`
}

// VulnerabilityMatch represents a vulnerability match for reporting
type VulnerabilityMatch struct {
	SignatureID    string `json:"signatureID" yaml:"signatureID"`
	SignatureName  string `json:"signatureName" yaml:"signatureName"`
	Description    string `json:"description" yaml:"description"`
	Severity       string `json:"severity" yaml:"severity"`
	Evidence       string `json:"evidence" yaml:"evidence"`
	AIAnalysis     string `json:"aiAnalysis,omitempty" yaml:"aiAnalysis,omitempty"`
	Recommendation string `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
}

// TLSInfo represents TLS information for reporting
type TLSInfo struct {
	Version               string    `json:"version" yaml:"version"`
	CipherSuite           string    `json:"cipherSuite" yaml:"cipherSuite"`
	CertificateExpiration time.Time `json:"certificateExpiration" yaml:"certificateExpiration"`
	CertificateIssuer     string    `json:"certificateIssuer" yaml:"certificateIssuer"`
	CertificateSubject    string    `json:"certificateSubject" yaml:"certificateSubject"`
	InsecureProtocols     []string  `json:"insecureProtocols,omitempty" yaml:"insecureProtocols,omitempty"`
	InsecureCiphers       []string  `json:"insecureCiphers,omitempty" yaml:"insecureCiphers,omitempty"`
}

// Generator represents a report generator
type Generator struct {
	Format string
	Output string
}

// NewGenerator creates a new report generator
func NewGenerator(format, output string) *Generator {
	return &Generator{
		Format: format,
		Output: output,
	}
}

// Generate generates a report from scan results
func (g *Generator) Generate(results []ScanResult) error {
	// Create the output directory if it doesn't exist
	outputDir := filepath.Dir(g.Output)
	if outputDir != "." && outputDir != "" {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("error creating output directory: %v", err)
		}
	}

	switch strings.ToLower(g.Format) {
	case "markdown", "md":
		return g.generateMarkdown(results)
	case "json":
		return g.generateJSON(results)
	case "csv":
		return g.generateCSV(results)
	default:
		return fmt.Errorf("unsupported report format: %s", g.Format)
	}
}

// generateMarkdown generates a Markdown report
func (g *Generator) generateMarkdown(results []ScanResult) error {
	var content strings.Builder

	// Write report header
	content.WriteString("# LlamaSec Security Scan Report\n\n")
	content.WriteString(fmt.Sprintf("**Date:** %s\n\n", time.Now().Format("2006-01-02 15:04:05")))
	content.WriteString(fmt.Sprintf("**Total URLs Scanned:** %d\n\n", len(results)))

	// Count total vulnerabilities
	vulnCount := 0
	errorCount := 0
	for _, result := range results {
		vulnCount += len(result.Vulnerabilities)
		if result.Error != "" {
			errorCount++
		}
	}
	content.WriteString(fmt.Sprintf("**Total Vulnerabilities Found:** %d\n\n", vulnCount))
	if errorCount > 0 {
		content.WriteString(fmt.Sprintf("**Scan Errors:** %d\n\n", errorCount))
	}

	// Write summary table
	content.WriteString("## Summary\n\n")
	content.WriteString("| URL | Status | Vulnerabilities | Response Time | Size |\n")
	content.WriteString("|-----|--------|----------------|---------------|------|\n")

	for _, result := range results {
		statusStr := fmt.Sprintf("%d", result.StatusCode)
		if result.Error != "" {
			statusStr = "Error"
		}

		content.WriteString(fmt.Sprintf("| %s | %s | %d | %s | %s |\n",
			result.URL,
			statusStr,
			len(result.Vulnerabilities),
			result.ResponseTime.String(),
			formatBytes(result.ResponseSize),
		))
	}
	content.WriteString("\n")

	// Write detailed results
	content.WriteString("## Detailed Results\n\n")

	for _, result := range results {
		content.WriteString(fmt.Sprintf("### %s\n\n", result.URL))

		if result.Error != "" {
			content.WriteString(fmt.Sprintf("**Error:** %s\n\n", result.Error))
			continue
		}

		content.WriteString(fmt.Sprintf("- **Status Code:** %d\n", result.StatusCode))
		content.WriteString(fmt.Sprintf("- **Response Time:** %s\n", result.ResponseTime))
		content.WriteString(fmt.Sprintf("- **Response Size:** %s\n\n", formatBytes(result.ResponseSize)))

		// Write TLS info if available
		if result.TLSInfo != nil {
			content.WriteString("#### TLS Information\n\n")
			content.WriteString(fmt.Sprintf("- **TLS Version:** %s\n", result.TLSInfo.Version))
			content.WriteString(fmt.Sprintf("- **Cipher Suite:** %s\n", result.TLSInfo.CipherSuite))
			content.WriteString(fmt.Sprintf("- **Certificate Expiration:** %s\n", result.TLSInfo.CertificateExpiration.Format("2006-01-02")))
			content.WriteString(fmt.Sprintf("- **Certificate Issuer:** %s\n", result.TLSInfo.CertificateIssuer))
			content.WriteString(fmt.Sprintf("- **Certificate Subject:** %s\n\n", result.TLSInfo.CertificateSubject))

			if len(result.TLSInfo.InsecureProtocols) > 0 {
				content.WriteString("- **Insecure Protocols:**\n")
				for _, protocol := range result.TLSInfo.InsecureProtocols {
					content.WriteString(fmt.Sprintf("  - %s\n", protocol))
				}
				content.WriteString("\n")
			}

			if len(result.TLSInfo.InsecureCiphers) > 0 {
				content.WriteString("- **Insecure Ciphers:**\n")
				for _, cipher := range result.TLSInfo.InsecureCiphers {
					content.WriteString(fmt.Sprintf("  - %s\n", cipher))
				}
				content.WriteString("\n")
			}
		}

		// Write response headers
		content.WriteString("#### Response Headers\n\n")
		content.WriteString("```\n")
		for name, value := range result.Headers {
			content.WriteString(fmt.Sprintf("%s: %s\n", name, value))
		}
		content.WriteString("```\n\n")

		// Write vulnerabilities
		if len(result.Vulnerabilities) > 0 {
			content.WriteString("#### Vulnerabilities\n\n")

			for i, vuln := range result.Vulnerabilities {
				content.WriteString(fmt.Sprintf("##### %d. %s (%s)\n\n", i+1, vuln.SignatureName, formatSeverity(vuln.Severity)))
				content.WriteString(fmt.Sprintf("- **Signature ID:** %s\n", vuln.SignatureID))
				content.WriteString(fmt.Sprintf("- **Description:** %s\n", vuln.Description))
				content.WriteString(fmt.Sprintf("- **Severity:** %s\n", vuln.Severity))
				content.WriteString("- **Evidence:**\n```\n")
				content.WriteString(vuln.Evidence)
				content.WriteString("\n```\n\n")

				// Include AI analysis if available
				if vuln.AIAnalysis != "" {
					content.WriteString("- **AI Analysis:**\n")
					content.WriteString(vuln.AIAnalysis)
					content.WriteString("\n\n")
				}

				// Include recommendation if available
				if vuln.Recommendation != "" {
					content.WriteString("- **Recommendation:**\n")
					content.WriteString(vuln.Recommendation)
					content.WriteString("\n\n")
				}
			}
		} else {
			content.WriteString("#### No Vulnerabilities Found\n\n")
		}
	}

	return os.WriteFile(g.Output, []byte(content.String()), 0644)
}

// generateJSON generates a JSON report
func (g *Generator) generateJSON(results []ScanResult) error {
	// Convert results to JSON
	jsonData, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling results to JSON: %v", err)
	}

	// Write JSON file
	return os.WriteFile(g.Output, jsonData, 0644)
}

// generateCSV generates a CSV report
func (g *Generator) generateCSV(results []ScanResult) error {
	// Create file
	file, err := os.Create(g.Output)
	if err != nil {
		return fmt.Errorf("error creating CSV file: %v", err)
	}
	defer file.Close()

	// Create CSV writer
	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	header := []string{
		"URL", "Status Code", "Response Time (ms)", "Response Size (bytes)",
		"Vulnerability ID", "Vulnerability Name", "Description", "Severity", "Evidence",
		"AI Recommendation", "AI Analysis",
	}
	if err := writer.Write(header); err != nil {
		return fmt.Errorf("error writing CSV header: %v", err)
	}

	// Write rows
	for _, result := range results {
		// Skip if there was an error scanning
		if result.Error != "" {
			row := []string{
				result.URL,
				"Error",
				"0",
				"0",
				"",
				"",
				result.Error,
				"error",
				"",
				"",
				"",
			}
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("error writing CSV row: %v", err)
			}
			continue
		}

		// Write vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			row := []string{
				result.URL,
				fmt.Sprintf("%d", result.StatusCode),
				fmt.Sprintf("%d", result.ResponseTime.Milliseconds()),
				fmt.Sprintf("%d", result.ResponseSize),
				vuln.SignatureID,
				vuln.SignatureName,
				vuln.Description,
				vuln.Severity,
				vuln.Evidence,
				vuln.Recommendation,
				// Use a shortened version of AI analysis for CSV
				shortenText(vuln.AIAnalysis, 500),
			}
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("error writing CSV row: %v", err)
			}
		}

		// If no vulnerabilities, write a row with just the URL info
		if len(result.Vulnerabilities) == 0 {
			row := []string{
				result.URL,
				fmt.Sprintf("%d", result.StatusCode),
				fmt.Sprintf("%d", result.ResponseTime.Milliseconds()),
				fmt.Sprintf("%d", result.ResponseSize),
				"", "", "No vulnerabilities found", "info", "", "", "",
			}
			if err := writer.Write(row); err != nil {
				return fmt.Errorf("error writing CSV row: %v", err)
			}
		}
	}

	return nil
}

// shortenText shortens text to maxLen characters, preserving whole words
func shortenText(text string, maxLen int) string {
	if len(text) <= maxLen {
		return text
	}

	// Find last space before maxLen
	lastSpace := strings.LastIndex(text[:maxLen], " ")
	if lastSpace > 0 {
		return text[:lastSpace] + "..."
	}

	// If no space found, just cut at maxLen
	return text[:maxLen] + "..."
}

// formatBytes formats bytes as human-readable string
func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// formatSeverity formats severity as a string
func formatSeverity(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "CRITICAL"
	case "high":
		return "HIGH"
	case "medium":
		return "MEDIUM"
	case "low":
		return "LOW"
	case "info":
		return "INFO"
	default:
		return strings.ToUpper(severity)
	}
}
