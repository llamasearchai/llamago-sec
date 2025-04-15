package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/yourusername/llamasec/internal/ai"
	"github.com/yourusername/llamasec/internal/scanner"
	"github.com/yourusername/llamasec/internal/signature"
	"github.com/yourusername/llamasec/internal/version"
	"github.com/yourusername/llamasec/pkg/utils"
)

// ASCII art for the Llama theme
const llamaASCII = `
    /\__/\    🦙 LlamaSec 🦙
   ( o.o  )   Concurrent URL Vulnerability Scanner
   > ^ <     Version: %s
`

func main() {
	// Print banner
	printLlamaArt()

	// Define command line flags
	configPath := flag.String("config", "", "Path to configuration file")
	urlFile := flag.String("file", "", "File containing URLs to scan (one per line)")
	concurrency := flag.Int("concurrency", 10, "Number of concurrent requests")
	rateLimit := flag.Float64("rate", 5.0, "Rate limit in requests per second")
	timeout := flag.Duration("timeout", 30*time.Second, "HTTP request timeout")
	userAgent := flag.String("user-agent", "LlamaSec/"+version.Version+" (+https://github.com/yourusername/llamasec)", "User-Agent string for HTTP requests")
	proxy := flag.String("proxy", "", "Proxy URL (e.g., http://proxy:8080)")
	outputPath := flag.String("output", "llamasec_report.md", "Output file path")
	outputFormat := flag.String("format", "markdown", "Output format (markdown, json, csv)")
	signaturesPath := flag.String("signatures", "config/signatures.yaml", "Path to vulnerability signatures file")
	serveFlag := flag.Bool("serve", false, "Serve the report on a web server")
	portFlag := flag.Int("port", 8080, "Port to serve the report on (only used with -serve)")
	versionFlag := flag.Bool("version", false, "Print version information and exit")
	verboseFlag := flag.Bool("verbose", false, "Enable verbose output")
	wasmPlugin := flag.String("wasm-plugin", "", "Path to WebAssembly plugin for custom scanning logic")
	openAIAPIKey := flag.String("openai-key", os.Getenv("OPENAI_API_KEY"), "OpenAI API key for enhanced vulnerability analysis")
	enableAI := flag.Bool("enable-ai", false, "Enable AI-powered vulnerability analysis")

	// Parse command line flags
	flag.Parse()

	// Print version information if requested
	if *versionFlag {
		fmt.Printf("LlamaSec version %s\n", version.Version)
		fmt.Printf("Build date: %s\n", version.BuildDate)
		fmt.Printf("Commit: %s\n", version.Commit)
		os.Exit(0)
	}

	// Configure default scanner settings
	scannerConfig := &scanner.Configuration{
		Concurrency:      *concurrency,
		RateLimit:        *rateLimit,
		Timeout:          *timeout,
		UserAgent:        *userAgent,
		ProxyURL:         *proxy,
		OutputFile:       *outputPath,
		OutputFormat:     *outputFormat,
		VerboseOutput:    *verboseFlag,
		WasmPluginPath:   *wasmPlugin,
		SignatureDBPath:  *signaturesPath,
		RetryCount:       3,
		OpenAIAPIKey:     *openAIAPIKey,
		EnableAIAnalysis: *enableAI,
	}

	// Override with config file if provided
	if *configPath != "" {
		config, err := utils.LoadConfig(*configPath, scannerConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
			os.Exit(1)
		}

		// Type assertion
		if cfg, ok := config.(*scanner.Configuration); ok {
			scannerConfig = cfg
		} else {
			fmt.Fprintf(os.Stderr, "Error: Invalid configuration type\n")
			os.Exit(1)
		}
	}

	// Validate that we have URLs to scan
	var urls []string

	// Get URLs from command line arguments
	urls = append(urls, flag.Args()...)

	// Get URLs from file if provided
	if *urlFile != "" {
		fileURLs, err := utils.LoadURLsFromFile(*urlFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading URLs from file: %v\n", err)
			os.Exit(1)
		}
		urls = append(urls, fileURLs...)
	}

	// Make sure we have at least one URL
	if len(urls) == 0 {
		fmt.Println("No URLs provided. Use -file flag to specify a file with URLs or provide them as arguments.")
		flag.Usage()
		os.Exit(1)
	}

	// Create sample signatures for testing
	sampleSignatures := []signature.Signature{
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
	}

	// Create signature manager
	signatureManager, err := signature.NewSignatureManager(sampleSignatures)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating signature manager: %v\n", err)
		os.Exit(1)
	}

	// Create OpenAI client if AI analysis is enabled
	var openAIClient *ai.OpenAIClient
	if scannerConfig.EnableAIAnalysis {
		if scannerConfig.OpenAIAPIKey == "" {
			fmt.Fprintf(os.Stderr, "Error: OpenAI API key is required for AI analysis\n")
			fmt.Fprintf(os.Stderr, "Set it with -openai-key flag or OPENAI_API_KEY environment variable\n")
			os.Exit(1)
		}

		openAIClient = ai.NewOpenAIClient(scannerConfig.OpenAIAPIKey)
		if *verboseFlag {
			fmt.Println("AI-powered analysis enabled")
		}
	}

	// Initialize scanner
	scanManager, err := scanner.NewScanManager(scannerConfig, signatureManager, openAIClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing scanner: %v\n", err)
		os.Exit(1)
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
	fmt.Printf("🦙 Starting scan of %d URLs with concurrency %d...\n", len(urls), scannerConfig.Concurrency)

	// Run the scan
	results, err := scanManager.ScanURLs(ctx, urls)
	if err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "Error during scan: %v\n", err)
		os.Exit(1)
	}

	// Generate report
	reportPath, err := scanManager.GenerateReport(results)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🦙 Scan completed! Report saved to %s\n", reportPath)

	// Print summary
	printSummary(results)

	// Serve report if requested
	if *serveFlag {
		// Get absolute path to report
		absReportPath, err := filepath.Abs(reportPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting absolute path to report: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Starting web server to serve report...\n")
		fmt.Printf("Report available at http://localhost:%d\n", *portFlag)
		fmt.Println("Press Ctrl+C to stop the server")

		// Create and start server
		server := &http.Server{
			Addr:         fmt.Sprintf(":%d", *portFlag),
			Handler:      http.FileServer(http.Dir(filepath.Dir(absReportPath))),
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
		}

		// Set up signal handling for server shutdown
		serverSigChan := make(chan os.Signal, 1)
		signal.Notify(serverSigChan, os.Interrupt, syscall.SIGTERM)

		go func() {
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
			}
		}()

		<-serverSigChan
		fmt.Println("\nShutting down server...")

		// Gracefully shutdown server
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(os.Stderr, "Error shutting down server: %v\n", err)
		}
	}
}

// printLlamaArt prints the LlamaSec ASCII art
func printLlamaArt() {
	boldGreen := color.New(color.FgGreen, color.Bold).SprintfFunc()
	fmt.Println(boldGreen(llamaASCII, version.Version))
}

// printSummary prints a summary of the scan results
func printSummary(results []scanner.ScanResult) {
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
				switch strings.ToLower(vuln.Severity) {
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

	// Create colored output
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	red := color.New(color.FgRed).SprintFunc()
	cyan := color.New(color.FgCyan).SprintFunc()

	// Print summary
	fmt.Println("\n📊 Scan Summary:")
	fmt.Printf("- URLs Scanned: %s\n", green(len(results)))
	fmt.Printf("- URLs with Vulnerabilities: %s\n", yellow(urlsWithVulns))
	fmt.Printf("- URLs with Errors: %s\n", yellow(urlsWithErrors))
	fmt.Printf("- Total Vulnerabilities: %s\n", yellow(totalVulns))
	fmt.Printf("  - High Severity: %s\n", red(highSeverity))
	fmt.Printf("  - Medium Severity: %s\n", yellow(mediumSeverity))
	fmt.Printf("  - Low Severity: %s\n", green(lowSeverity))
	fmt.Printf("  - Info: %s\n", cyan(infoSeverity))
}
