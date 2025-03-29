// Package examples contains example code for using LlamaSec
package examples

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/yourusername/llamasec/internal/scanner"
	"github.com/yourusername/llamasec/internal/signature"
)

// TestingExample demonstrates how to test LlamaSec components
func TestingExample() {
	// Create a test server that serves vulnerable content
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Inject some "vulnerabilities" for testing
		w.Header().Set("Server", "Apache/2.4.49")
		w.WriteHeader(http.StatusOK)

		// Response with a fake vulnerability (XSS)
		html := `
			<!DOCTYPE html>
			<html>
			<head>
				<title>Test Vulnerable Page</title>
			</head>
			<body>
				<h1>Test Page with Vulnerabilities</h1>
				
				<!-- XSS vulnerability -->
				<script>
					var input = location.hash.substring(1);
					document.write("<div>" + input + "</div>");
				</script>
				
				<!-- API Key exposure -->
				<div id="config" data-api-key="sk_test_12345abcdefghijklmnopqrstuvwxyz"></div>
				
				<!-- SQL query in JavaScript -->
				<script>
					var query = "SELECT * FROM users WHERE username = '" + username + "'";
				</script>
			</body>
			</html>
		`

		fmt.Fprintln(w, html)
	}))
	defer server.Close()

	fmt.Printf("Test server running at %s\n", server.URL)

	// Create signature definitions
	signatures := []signature.Signature{
		{
			ID:          "XSS-001",
			Name:        "Cross-Site Scripting",
			Description: "Detects potential XSS vulnerabilities",
			Severity:    "high",
			Pattern:     `document\.write\s*\(\s*["']?<[^>]+>[^<]*["']?\s*\+`,
		},
		{
			ID:          "API-001",
			Name:        "API Key Exposure",
			Description: "Detects exposed API keys",
			Severity:    "high",
			Pattern:     `["']?sk_test_[a-zA-Z0-9]+["']?`,
		},
		{
			ID:          "SQL-001",
			Name:        "SQL Injection",
			Description: "Detects potential SQL injection vulnerabilities",
			Severity:    "high",
			Pattern:     `(?i)(?:SELECT|INSERT|UPDATE|DELETE|UNION|DROP)\s+.*\s+(?:FROM|INTO|WHERE|TABLE|DATABASE)`,
		},
		{
			ID:          "SERVER-001",
			Name:        "Server Information Disclosure",
			Description: "Detects server information disclosure in headers",
			Severity:    "low",
			Pattern:     `(?i)(apache|nginx|iis|tomcat)[\s/][\d.]+`,
		},
	}

	// Create signature manager for testing
	sigManager, err := signature.NewSignatureManager(signatures)
	if err != nil {
		fmt.Printf("Error creating signature manager: %v\n", err)
		return
	}

	// Create scanner configuration for testing
	config := &scanner.Configuration{
		Concurrency:      1,
		Timeout:          5 * time.Second,
		RateLimit:        10.0,
		UserAgent:        "LlamaSec-Test/1.0",
		OutputFormat:     "json",
		OutputFile:       "test_results.json",
		RetryCount:       1,
		VerboseOutput:    true,
		EnableAIAnalysis: false,
	}

	// Create scan manager
	scanManager, err := scanner.NewScanManager(config, sigManager, nil)
	if err != nil {
		fmt.Printf("Error creating scan manager: %v\n", err)
		return
	}

	// Scan the test server URL
	results, err := scanManager.ScanURLs(context.Background(), []string{server.URL})
	if err != nil {
		fmt.Printf("Error scanning URLs: %v\n", err)
		return
	}

	// Verify results
	if len(results) != 1 {
		fmt.Printf("Expected 1 result, got %d\n", len(results))
		return
	}

	result := results[0]
	fmt.Printf("URL: %s\nStatus: %d\nVulnerabilities: %d\n\n",
		result.URL, result.StatusCode, len(result.Vulnerabilities))

	// Check for specific vulnerabilities
	expectedVulnerabilities := map[string]bool{
		"XSS-001":    false,
		"API-001":    false,
		"SQL-001":    false,
		"SERVER-001": false,
	}

	for _, vuln := range result.Vulnerabilities {
		fmt.Printf("Found: %s (%s)\n", vuln.SignatureName, vuln.Severity)
		fmt.Printf("  Evidence: %s\n", vuln.Evidence)

		// Mark vulnerability as found
		if _, exists := expectedVulnerabilities[vuln.SignatureID]; exists {
			expectedVulnerabilities[vuln.SignatureID] = true
		}
	}

	// Check if all expected vulnerabilities were found
	fmt.Println("\nVerification:")
	allFound := true
	for id, found := range expectedVulnerabilities {
		if found {
			fmt.Printf("✓ %s was detected\n", id)
		} else {
			fmt.Printf("✗ %s was NOT detected\n", id)
			allFound = false
		}
	}

	if allFound {
		fmt.Println("\nAll expected vulnerabilities were successfully detected!")
	} else {
		fmt.Println("\nSome expected vulnerabilities were not detected.")
	}
}
