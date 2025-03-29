// Package examples demonstrates how to use LlamaSec as a Go module
package examples

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/yourusername/llamasec/internal/scanner"
	"github.com/yourusername/llamasec/internal/signature"
)

// UseAsModule demonstrates how to use LlamaSec as a module in your Go application
func UseAsModule() {
	// Create sample signatures
	signatures := []signature.Signature{
		{
			ID:          "XSS-001",
			Name:        "Cross-Site Scripting",
			Description: "Detects potential XSS vulnerabilities",
			Severity:    "high",
			Pattern:     `<script>[^>]*alert\(`,
		},
		{
			ID:          "API-001",
			Name:        "API Key Exposure",
			Description: "Detects exposed API keys",
			Severity:    "high",
			Pattern:     `(?i)api[_-]?key[_-]?=\s*["']?[a-zA-Z0-9]{16,}["']?`,
		},
	}

	// Create signature manager
	sigManager, err := signature.NewSignatureManager(signatures)
	if err != nil {
		log.Fatalf("Error creating signature manager: %v", err)
	}

	// Configure scanner
	config := &scanner.Configuration{
		Concurrency:      5,
		Timeout:          10 * time.Second,
		RateLimit:        5.0,
		UserAgent:        "LlamaSec-Example/1.0",
		OutputFormat:     "json",
		OutputFile:       "scan_results.json",
		RetryCount:       2,
		VerboseOutput:    true,
		EnableAIAnalysis: false,
	}

	// Create scan manager
	scanManager, err := scanner.NewScanManager(config, sigManager, nil)
	if err != nil {
		log.Fatalf("Error creating scan manager: %v", err)
	}

	// Define URLs to scan
	urls := []string{
		"https://example.com",
		"https://example.org",
	}

	// Set up context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Scan URLs
	fmt.Println("Starting scan...")
	results, err := scanManager.ScanURLs(ctx, urls)
	if err != nil {
		log.Fatalf("Error scanning URLs: %v", err)
	}

	// Process results
	fmt.Printf("Scanned %d URLs\n", len(results))
	for _, result := range results {
		fmt.Printf("- %s: %d vulnerabilities found\n", result.URL, len(result.Vulnerabilities))
		for _, vuln := range result.Vulnerabilities {
			fmt.Printf("  - %s (%s): %s\n", vuln.SignatureName, vuln.Severity, vuln.Description)
		}
	}

	// Generate report
	reportPath, err := scanManager.GenerateReport(results)
	if err != nil {
		log.Fatalf("Error generating report: %v", err)
	}
	fmt.Printf("Report saved to: %s\n", reportPath)
}
