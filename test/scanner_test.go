package test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yourusername/llamasec/internal/scanner"
	"github.com/yourusername/llamasec/internal/signature"
)

// TestScannerBasic tests the basic URL scanning functionality
func TestScannerBasic(t *testing.T) {
	// Create a test server that returns a fixed response with a fake vulnerability
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)

		// Response with a fake vulnerability (XSS)
		html := `
		<!DOCTYPE html>
		<html>
		<head>
			<title>Test Page</title>
		</head>
		<body>
			<h1>Test Page</h1>
			<script>
				// Vulnerable code with XSS
				var input = location.hash.substring(1);
				document.write("<div>" + input + "</div>");
			</script>
			<div>
				<!-- API key in the HTML source -->
				var apiKey = "sk_test_12345abcdef";
			</div>
		</body>
		</html>`

		fmt.Fprintln(w, html)
	}))
	defer server.Close()

	// Create test signatures
	xssSignature := signature.Signature{
		ID:          "XSS-001",
		Name:        "Reflected XSS",
		Description: "Reflected Cross-Site Scripting Vulnerability",
		Severity:    "high",
		Pattern:     `document\.write\s*\(\s*["']?<[^>]+>[^<]*["']?\s*\+`,
	}

	apiKeySignature := signature.Signature{
		ID:          "API-001",
		Name:        "API Key Exposure",
		Description: "API key found in source code",
		Severity:    "high",
		Pattern:     `["']?sk_test_[a-zA-Z0-9]+["']?`,
	}

	signatures := []signature.Signature{xssSignature, apiKeySignature}

	// Create a signature manager with the test signatures
	sigManager, err := signature.NewSignatureManager(signatures)
	if err != nil {
		t.Fatalf("Error creating signature manager: %v", err)
	}

	// Create scanner configuration
	config := &scanner.Configuration{
		Concurrency:      1,
		Timeout:          5 * time.Second,
		RateLimit:        10.0,
		UserAgent:        "LlamaSec-Test",
		OutputFormat:     "json",
		OutputFile:       "test_report.json",
		VerboseOutput:    false,
		RetryCount:       1,
		RespectRobotsTxt: false,
	}

	// Create scan manager
	scanManager, err := scanner.NewScanManager(config, sigManager, nil)
	if err != nil {
		t.Fatalf("Error creating scan manager: %v", err)
	}

	// Scan the test server URL
	results, err := scanManager.ScanURLs(context.Background(), []string{server.URL})
	if err != nil {
		t.Fatalf("Error scanning URLs: %v", err)
	}

	// Verify results
	if len(results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(results))
	}

	result := results[0]

	// Check status code
	if result.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, result.StatusCode)
	}

	// Check vulnerabilities
	if len(result.Vulnerabilities) != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", len(result.Vulnerabilities))
	}

	// Verify each vulnerability
	foundXSS := false
	foundAPIKey := false

	for _, vuln := range result.Vulnerabilities {
		switch vuln.SignatureID {
		case "XSS-001":
			foundXSS = true
		case "API-001":
			foundAPIKey = true
		}
	}

	if !foundXSS {
		t.Errorf("XSS vulnerability not found")
	}

	if !foundAPIKey {
		t.Errorf("API key vulnerability not found")
	}
}
