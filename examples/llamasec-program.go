// Package examples contains example code for using LlamaSec
package examples

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/yourusername/llamasec/internal/ai"
	"github.com/yourusername/llamasec/internal/scanner"
	"github.com/yourusername/llamasec/internal/signature"
)

// CompleteLlamaSec demonstrates a complete LlamaSec program with AI integration
func CompleteLlamaSec() {
	// Set up colored output
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()

	// Print banner
	fmt.Print("\n    /\\__/\\    🦙 LlamaSec Example 🦙\n")
	fmt.Print("   ( o.o  )   Concurrent URL Vulnerability Scanner\n")
	fmt.Print("   > ^ <     Demonstration\n\n")

	// Define URLs to scan
	urls := []string{
		"https://example.com",
		"https://example.org",
	}

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
		{
			ID:          "SQL-001",
			Name:        "SQL Injection",
			Description: "Detects potential SQL injection vulnerabilities",
			Severity:    "high",
			Pattern:     `(?i)(?:SELECT|INSERT|UPDATE|DELETE|UNION|DROP)\s+.*\s+(?:FROM|INTO|WHERE|TABLE|DATABASE)`,
		},
		{
			ID:          "JWT-001",
			Name:        "JWT Secret Exposure",
			Description: "Detects JWT secrets in source code",
			Severity:    "medium",
			Pattern:     `(?i)(?:jwt|token)(?:[\._-]?secret|[\._-]?key)\s*=\s*['"]([^'"]{8,})['"]`,
		},
		{
			ID:          "INFO-001",
			Name:        "Server Information Disclosure",
			Description: "Detects server information disclosure in headers",
			Severity:    "low",
			Pattern:     `(?i)(apache|nginx|iis|tomcat|jetty|jboss|websphere|weblogic)[\s/][\d.]+`,
		},
	}

	// Create signature manager
	sigManager, err := signature.NewSignatureManager(signatures)
	if err != nil {
		log.Fatalf("Error creating signature manager: %v", err)
	}

	// Check for OpenAI API key
	apiKey := os.Getenv("OPENAI_API_KEY")
	enableAI := apiKey != ""

	// Create OpenAI client if API key is available
	var openAIClient *ai.OpenAIClient
	if enableAI {
		openAIClient = ai.NewOpenAIClient(apiKey)
		fmt.Println(green("✓ AI-powered analysis enabled"))
	} else {
		fmt.Println(yellow("⚠ AI-powered analysis disabled (no API key found)"))
		fmt.Println(yellow("  Set OPENAI_API_KEY environment variable to enable AI features"))
	}

	// Configure scanner
	config := &scanner.Configuration{
		Concurrency:      3,
		Timeout:          10 * time.Second,
		RateLimit:        5.0,
		UserAgent:        "LlamaSec-Example/1.0",
		OutputFormat:     "markdown",
		OutputFile:       "llamasec_example_report.md",
		RetryCount:       2,
		VerboseOutput:    true,
		EnableAIAnalysis: enableAI,
		OpenAIAPIKey:     apiKey,
	}

	// Create scan manager
	scanManager, err := scanner.NewScanManager(config, sigManager, openAIClient)
	if err != nil {
		log.Fatalf("Error creating scan manager: %v", err)
	}

	// Set up signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signalChan
		fmt.Println("\n🦙 Stopping scan and saving results...")
		cancel()
	}()

	// Start scan
	fmt.Printf("🦙 Starting scan of %d URLs with concurrency %d...\n", len(urls), config.Concurrency)
	startTime := time.Now()

	// Run the scan
	results, err := scanManager.ScanURLs(ctx, urls)
	if err != nil && err != context.Canceled {
		log.Fatalf("Error during scan: %v", err)
	}

	scanDuration := time.Since(startTime)

	// Generate report
	reportPath, err := scanManager.GenerateReport(results)
	if err != nil {
		log.Fatalf("Error generating report: %v", err)
	}

	fmt.Printf("\n🦙 Scan completed in %s! Report saved to %s\n", scanDuration.Round(time.Millisecond), reportPath)

	// Print summary
	fmt.Println("\n📊 Scan Summary:")

	// Count statistics
	var totalVulns, highSeverity, mediumSeverity, lowSeverity, infoSeverity int
	var urlsWithVulns, urlsWithErrors int

	for _, result := range results {
		if result.Error != "" {
			urlsWithErrors++
			continue
		}

		if len(result.Vulnerabilities) > 0 {
			urlsWithVulns++
			totalVulns += len(result.Vulnerabilities)

			// Count by severity
			for _, vuln := range result.Vulnerabilities {
				switch vuln.Severity {
				case "high", "critical":
					highSeverity++
				case "medium":
					mediumSeverity++
				case "low":
					lowSeverity++
				default:
					infoSeverity++
				}
			}
		}
	}

	// Print statistics
	fmt.Printf("- URLs Scanned: %s\n", green(len(results)))
	fmt.Printf("- URLs with Vulnerabilities: %s\n", yellow(urlsWithVulns))
	fmt.Printf("- URLs with Errors: %s\n", yellow(urlsWithErrors))
	fmt.Printf("- Total Vulnerabilities: %s\n", yellow(totalVulns))
	fmt.Printf("  - High Severity: %s\n", red(highSeverity))
	fmt.Printf("  - Medium Severity: %s\n", yellow(mediumSeverity))
	fmt.Printf("  - Low Severity: %s\n", green(lowSeverity))
	fmt.Printf("  - Info: %s\n", color.New(color.FgCyan).Sprintf("%d", infoSeverity))

	// Print detailed results
	if totalVulns > 0 {
		fmt.Println("\n🔍 Vulnerability Details:")
		for _, result := range results {
			if len(result.Vulnerabilities) > 0 {
				fmt.Printf("\n%s (%d vulnerabilities):\n", result.URL, len(result.Vulnerabilities))
				for i, vuln := range result.Vulnerabilities {
					// Print vulnerability with color based on severity
					var severityColor func(a ...interface{}) string
					switch vuln.Severity {
					case "high", "critical":
						severityColor = red
					case "medium":
						severityColor = yellow
					case "low":
						severityColor = green
					default:
						severityColor = color.New(color.FgCyan).SprintFunc()
					}

					fmt.Printf("%d. %s (%s): %s\n", i+1,
						color.New(color.Bold).Sprint(vuln.SignatureName),
						severityColor(vuln.Severity),
						vuln.Description)

					// Print evidence (truncated if too long)
					evidence := vuln.Evidence
					if len(evidence) > 80 {
						evidence = evidence[:77] + "..."
					}
					fmt.Printf("   Evidence: %s\n", evidence)

					// Print AI recommendation if available
					if vuln.Recommendation != "" {
						fmt.Printf("   Recommendation: %s\n",
							color.New(color.FgHiGreen).Sprint(vuln.Recommendation))
					}
				}
			}
		}
	}

	fmt.Println("\n🦙 Example completed successfully!")
}
