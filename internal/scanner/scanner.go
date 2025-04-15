package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/yourusername/llamasec/internal/ai"
	"github.com/yourusername/llamasec/internal/report"
	"github.com/yourusername/llamasec/internal/signature"
	"github.com/yourusername/llamasec/internal/wasm"
)

// Default configuration values
const (
	DefaultConcurrency  = 10
	DefaultTimeout      = 30 * time.Second
	DefaultRateLimit    = 5.0
	DefaultRetryCount   = 3
	DefaultOutputFormat = "markdown"
	DefaultOutputFile   = "llamasec_report.md"
	DefaultUserAgent    = "LlamaSec/1.0.0 (+https://github.com/yourusername/llamasec)"
)

// Configuration represents scanner configuration
type Configuration struct {
	// Core settings
	Concurrency int           `json:"concurrency" yaml:"concurrency"`
	Timeout     time.Duration `json:"timeout" yaml:"timeout"`
	RateLimit   float64       `json:"rateLimit" yaml:"rateLimit"`
	UserAgent   string        `json:"userAgent" yaml:"userAgent"`

	// HTTP settings
	ProxyURL string   `json:"proxyURL" yaml:"proxyURL"`
	Headers  []Header `json:"headers" yaml:"headers"`

	// Output settings
	OutputFormat  string `json:"outputFormat" yaml:"outputFormat"`
	OutputFile    string `json:"outputFile" yaml:"outputFile"`
	VerboseOutput bool   `json:"verboseOutput" yaml:"verboseOutput"`

	// Scanner settings
	SignatureDBPath  string `json:"signatureDBPath" yaml:"signatureDBPath"`
	RetryCount       int    `json:"retryCount" yaml:"retryCount"`
	RespectRobotsTxt bool   `json:"respectRobotsTxt" yaml:"respectRobotsTxt"`

	// Extensions
	WasmPluginPath string `json:"wasmPluginPath" yaml:"wasmPluginPath"`

	// OpenAI integration
	OpenAIAPIKey     string `json:"openAIAPIKey" yaml:"openAIAPIKey"`
	EnableAIAnalysis bool   `json:"enableAIAnalysis" yaml:"enableAIAnalysis"`
}

// Header represents an HTTP header
type Header struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
}

// ScanResult represents the result of scanning a URL
type ScanResult struct {
	URL             string            `json:"url" yaml:"url"`
	StatusCode      int               `json:"statusCode" yaml:"statusCode"`
	ResponseTime    time.Duration     `json:"responseTime" yaml:"responseTime"`
	ResponseSize    int64             `json:"responseSize" yaml:"responseSize"`
	Headers         map[string]string `json:"headers" yaml:"headers"`
	Vulnerabilities []VulnMatch       `json:"vulnerabilities" yaml:"vulnerabilities"`
	Error           string            `json:"error,omitempty" yaml:"error,omitempty"`
	TLSInfo         *TLSInfo          `json:"tlsInfo,omitempty" yaml:"tlsInfo,omitempty"`
}

// VulnMatch represents a matched vulnerability
type VulnMatch struct {
	SignatureID    string `json:"signatureID" yaml:"signatureID"`
	SignatureName  string `json:"signatureName" yaml:"signatureName"`
	Description    string `json:"description" yaml:"description"`
	Severity       string `json:"severity" yaml:"severity"`
	Evidence       string `json:"evidence" yaml:"evidence"`
	AIAnalysis     string `json:"aiAnalysis,omitempty" yaml:"aiAnalysis,omitempty"`
	Recommendation string `json:"recommendation,omitempty" yaml:"recommendation,omitempty"`
}

// TLSInfo represents TLS information about a connection
type TLSInfo struct {
	Version               string    `json:"version" yaml:"version"`
	CipherSuite           string    `json:"cipherSuite" yaml:"cipherSuite"`
	CertificateExpiration time.Time `json:"certificateExpiration" yaml:"certificateExpiration"`
	CertificateIssuer     string    `json:"certificateIssuer" yaml:"certificateIssuer"`
	CertificateSubject    string    `json:"certificateSubject" yaml:"certificateSubject"`
	InsecureProtocols     []string  `json:"insecureProtocols,omitempty" yaml:"insecureProtocols,omitempty"`
	InsecureCiphers       []string  `json:"insecureCiphers,omitempty" yaml:"insecureCiphers,omitempty"`
}

// ScanManager manages the scanning process
type ScanManager struct {
	config      *Configuration
	client      *http.Client
	rateLimiter *rate.Limiter
	sigManager  *signature.SignatureManager
	aiClient    *ai.OpenAIClient
	wasmPlugin  *wasm.Plugin
	logger      *log.Logger
}

// NewScanManager creates a new scan manager
func NewScanManager(config *Configuration, sigManager *signature.SignatureManager, aiClient *ai.OpenAIClient) (*ScanManager, error) {
	// Create HTTP client
	client, err := createHTTPClient(config)
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP client: %v", err)
	}

	// Create rate limiter
	limiter := rate.NewLimiter(rate.Limit(config.RateLimit), 1)

	manager := &ScanManager{
		config:      config,
		client:      client,
		rateLimiter: limiter,
		sigManager:  sigManager,
		aiClient:    aiClient,
		logger:      log.New(os.Stdout, "LlamaSec: ", log.LstdFlags),
	}

	// Load WebAssembly plugin if provided
	if config.WasmPluginPath != "" {
		plugin, err := wasm.LoadPlugin(config.WasmPluginPath)
		if err != nil {
			if config.VerboseOutput {
				fmt.Printf("Warning: Failed to load WebAssembly plugin: %v\n", err)
			}
		} else {
			manager.wasmPlugin = plugin
			if config.VerboseOutput {
				fmt.Printf("Loaded WebAssembly plugin: %s\n", config.WasmPluginPath)
			}
		}
	}

	return manager, nil
}

// ScanURLs scans a list of URLs
func (sm *ScanManager) ScanURLs(ctx context.Context, urls []string) ([]ScanResult, error) {
	// Create channels for workers
	urlChan := make(chan string, len(urls))
	resultChan := make(chan ScanResult, len(urls))

	// Set up wait group for workers
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < sm.config.Concurrency; i++ {
		wg.Add(1)
		go sm.worker(ctx, &wg, urlChan, resultChan)
	}

	// Send URLs to workers
	for _, url := range urls {
		select {
		case urlChan <- url:
			// URL sent
		case <-ctx.Done():
			// Context canceled
			close(urlChan)
			return nil, ctx.Err()
		}
	}

	// Close URL channel after all URLs are sent
	close(urlChan)

	// Start a goroutine to close the result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var results []ScanResult
	for result := range resultChan {
		results = append(results, result)

		if sm.config.VerboseOutput {
			if result.Error != "" {
				fmt.Printf("[ERROR] %s - %s\n", result.URL, result.Error)
			} else {
				fmt.Printf("[%d] %s - %d vulnerabilities found\n",
					result.StatusCode, result.URL, len(result.Vulnerabilities))
			}
		}
	}

	// Perform AI analysis if enabled
	if sm.config.EnableAIAnalysis && sm.aiClient != nil {
		if sm.config.VerboseOutput {
			fmt.Println("Performing AI analysis of vulnerabilities...")
		}

		// Process each result with AI
		for i := range results {
			// Skip if there was an error or no vulnerabilities
			if results[i].Error != "" || len(results[i].Vulnerabilities) == 0 {
				continue
			}

			// Process each vulnerability with AI
			for j := range results[i].Vulnerabilities {
				vuln := &results[i].Vulnerabilities[j]

				// Skip low severity vulnerabilities to save API costs
				if vuln.Severity != "high" && vuln.Severity != "medium" {
					continue
				}

				if sm.config.VerboseOutput {
					fmt.Printf("Analyzing %s vulnerability in %s...\n",
						vuln.SignatureName, results[i].URL)
				}

				// Get AI recommendation
				recommendation, err := sm.aiClient.GetRemediation(vuln.SignatureName, vuln.Evidence)
				if err != nil {
					fmt.Printf("Error getting AI recommendation: %v\n", err)
					continue
				}
				vuln.Recommendation = recommendation

				// For high severity vulnerabilities, get detailed analysis
				if vuln.Severity == "high" {
					analysis, err := sm.aiClient.AnalyzeVulnerability(vuln.SignatureName, vuln.Evidence)
					if err != nil {
						fmt.Printf("Error getting AI analysis: %v\n", err)
						continue
					}
					vuln.AIAnalysis = analysis
				}
			}
		}
	}

	return results, nil
}

// worker handles scanning individual URLs
func (sm *ScanManager) worker(ctx context.Context, wg *sync.WaitGroup, urlChan <-chan string, resultChan chan<- ScanResult) {
	defer wg.Done()

	for {
		select {
		case url, ok := <-urlChan:
			if !ok {
				// Channel closed
				return
			}

			// Scan URL
			result := sm.scanURL(ctx, url)

			// Send result
			select {
			case resultChan <- result:
				// Result sent
			case <-ctx.Done():
				// Context canceled
				return
			}
		case <-ctx.Done():
			// Context canceled
			return
		}
	}
}

// scanURL scans a single URL
func (sm *ScanManager) scanURL(ctx context.Context, rawURL string) ScanResult {
	result := ScanResult{
		URL:     rawURL,
		Headers: make(map[string]string),
	}

	// Parse URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		result.Error = fmt.Sprintf("invalid URL: %v", err)
		return result
	}

	// Apply rate limiting
	err = sm.rateLimiter.Wait(ctx)
	if err != nil {
		result.Error = fmt.Sprintf("rate limiting error: %v", err)
		return result
	}

	// Create request
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		result.Error = fmt.Sprintf("error creating request: %v", err)
		return result
	}

	// Set headers
	req.Header.Set("User-Agent", sm.config.UserAgent)
	for _, header := range sm.config.Headers {
		req.Header.Set(header.Name, header.Value)
	}

	// Send request and measure time
	startTime := time.Now()
	resp, err := sm.client.Do(req)
	responseTime := time.Since(startTime)
	result.ResponseTime = responseTime

	if err != nil {
		result.Error = fmt.Sprintf("error sending request: %v", err)
		return result
	}
	defer resp.Body.Close()

	// Extract response info
	result.StatusCode = resp.StatusCode

	// Extract response headers
	for name, values := range resp.Header {
		if len(values) > 0 {
			result.Headers[name] = values[0]
		}
	}

	// Extract TLS info if HTTPS
	if parsedURL.Scheme == "https" && resp.TLS != nil {
		result.TLSInfo = extractTLSInfo(resp.TLS)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		result.Error = fmt.Sprintf("error reading response body: %v", err)
		return result
	}

	// Set response size
	result.ResponseSize = int64(len(body))

	// Scan for vulnerabilities
	matches := sm.sigManager.MatchContent(string(body), result.Headers)

	// Convert matches to vulnerabilities
	for _, match := range matches {
		vuln := VulnMatch{
			SignatureID:   match.SignatureID,
			SignatureName: match.SignatureName,
			Description:   match.Description,
			Severity:      match.Severity,
			Evidence:      match.Evidence,
		}

		result.Vulnerabilities = append(result.Vulnerabilities, vuln)
	}

	// Run content through WebAssembly plugin if available
	if sm.wasmPlugin != nil {
		pluginResult, err := sm.wasmPlugin.ScanURL(string(body))
		if err == nil && pluginResult.HasVulnerability {
			// Add vulnerability detected by WASM plugin
			vuln := VulnMatch{
				SignatureID:   "WASM-" + pluginResult.ID,
				SignatureName: pluginResult.Name,
				Description:   pluginResult.Description,
				Severity:      pluginResult.Severity,
				Evidence:      pluginResult.Evidence,
			}
			result.Vulnerabilities = append(result.Vulnerabilities, vuln)
		}
	}

	return result
}

// GenerateReport generates a report from scan results
func (sm *ScanManager) GenerateReport(results []ScanResult) (string, error) {
	// Create report generator
	reportGenerator := report.NewGenerator(sm.config.OutputFormat, sm.config.OutputFile)

	// Convert scanner results to report format
	reportResults := make([]report.ScanResult, len(results))
	for i, result := range results {
		reportResults[i] = report.ScanResult{
			URL:          result.URL,
			StatusCode:   result.StatusCode,
			ResponseTime: result.ResponseTime,
			ResponseSize: result.ResponseSize,
			Headers:      result.Headers,
			Error:        result.Error,
		}

		// Convert vulnerabilities
		if len(result.Vulnerabilities) > 0 {
			reportResults[i].Vulnerabilities = make([]report.VulnerabilityMatch, len(result.Vulnerabilities))
			for j, vuln := range result.Vulnerabilities {
				reportResults[i].Vulnerabilities[j] = report.VulnerabilityMatch{
					SignatureID:    vuln.SignatureID,
					SignatureName:  vuln.SignatureName,
					Description:    vuln.Description,
					Severity:       vuln.Severity,
					Evidence:       vuln.Evidence,
					AIAnalysis:     vuln.AIAnalysis,
					Recommendation: vuln.Recommendation,
				}
			}
		}

		// Convert TLS info
		if result.TLSInfo != nil {
			reportResults[i].TLSInfo = &report.TLSInfo{
				Version:               result.TLSInfo.Version,
				CipherSuite:           result.TLSInfo.CipherSuite,
				CertificateExpiration: result.TLSInfo.CertificateExpiration,
				CertificateIssuer:     result.TLSInfo.CertificateIssuer,
				CertificateSubject:    result.TLSInfo.CertificateSubject,
				InsecureProtocols:     result.TLSInfo.InsecureProtocols,
				InsecureCiphers:       result.TLSInfo.InsecureCiphers,
			}
		}
	}

	// Generate report
	if err := reportGenerator.Generate(reportResults); err != nil {
		return "", fmt.Errorf("error generating report: %v", err)
	}

	// Return report path
	return sm.config.OutputFile, nil
}

// createHTTPClient creates an HTTP client with the specified configuration
func createHTTPClient(config *Configuration) (*http.Client, error) {
	// Create transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
		},
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	// Configure proxy if specified
	if config.ProxyURL != "" {
		proxyURL, err := url.Parse(config.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	// Create client
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	return client, nil
}

// extractTLSInfo extracts TLS information from a connection state
func extractTLSInfo(tlsState *tls.ConnectionState) *TLSInfo {
	info := &TLSInfo{
		Version:     tlsVersionToString(tlsState.Version),
		CipherSuite: tlsCipherSuiteToString(tlsState.CipherSuite),
	}

	// Get certificate information if available
	if len(tlsState.PeerCertificates) > 0 {
		cert := tlsState.PeerCertificates[0]
		info.CertificateExpiration = cert.NotAfter
		info.CertificateIssuer = cert.Issuer.String()
		info.CertificateSubject = cert.Subject.String()
	}

	// Check for insecure protocols
	if tlsState.Version < tls.VersionTLS12 {
		info.InsecureProtocols = append(info.InsecureProtocols, info.Version)
	}

	// Check for insecure cipher suites
	if isInsecureCipher(tlsState.CipherSuite) {
		info.InsecureCiphers = append(info.InsecureCiphers, info.CipherSuite)
	}

	return info
}

// tlsVersionToString converts a TLS version to a string
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// tlsCipherSuiteToString converts a TLS cipher suite to a string
func tlsCipherSuiteToString(cipherSuite uint16) string {
	// Common cipher suites
	cipherSuites := map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         "TLS_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",
	}

	if name, ok := cipherSuites[cipherSuite]; ok {
		return name
	}

	return fmt.Sprintf("Unknown (0x%04x)", cipherSuite)
}

// isInsecureCipher checks if a cipher suite is considered insecure
func isInsecureCipher(cipherSuite uint16) bool {
	insecureCiphers := map[uint16]bool{
		tls.TLS_RSA_WITH_RC4_128_SHA:            true,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       true,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:    true,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:      true,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: true,
	}

	return insecureCiphers[cipherSuite]
}

// ParseURLsFromText extracts URLs from text
func ParseURLsFromText(text string) []string {
	// Split by newlines
	lines := strings.Split(text, "\n")

	var urls []string
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		urls = append(urls, line)
	}

	return urls
}
