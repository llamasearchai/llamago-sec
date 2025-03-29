package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	// Core settings
	Concurrency int           `mapstructure:"concurrency" json:"concurrency" yaml:"concurrency"`
	RateLimit   float64       `mapstructure:"rateLimit" json:"rateLimit" yaml:"rateLimit"`
	Timeout     time.Duration `mapstructure:"timeout" json:"timeout" yaml:"timeout"`
	UserAgent   string        `mapstructure:"userAgent" json:"userAgent" yaml:"userAgent"`

	// HTTP settings
	Proxy            string   `mapstructure:"proxy" json:"proxy" yaml:"proxy"`
	Headers          []Header `mapstructure:"headers" json:"headers" yaml:"headers"`
	RespectRobotsTxt bool     `mapstructure:"respectRobotsTxt" json:"respectRobotsTxt" yaml:"respectRobotsTxt"`

	// Retry settings
	RetryCount    int           `mapstructure:"retryCount" json:"retryCount" yaml:"retryCount"`
	RetryWaitTime time.Duration `mapstructure:"retryWaitTime" json:"retryWaitTime" yaml:"retryWaitTime"`
	RetryMaxTime  time.Duration `mapstructure:"retryMaxTime" json:"retryMaxTime" yaml:"retryMaxTime"`

	// Output settings
	OutputPath    string `mapstructure:"outputPath" json:"outputPath" yaml:"outputPath"`
	OutputFormat  string `mapstructure:"outputFormat" json:"outputFormat" yaml:"outputFormat"`
	VerboseOutput bool   `mapstructure:"verboseOutput" json:"verboseOutput" yaml:"verboseOutput"`
	LogFile       string `mapstructure:"logFile" json:"logFile" yaml:"logFile"`

	// Signatures and plugins
	SignaturesPath string `mapstructure:"signaturesPath" json:"signaturesPath" yaml:"signaturesPath"`
	WasmPluginPath string `mapstructure:"wasmPluginPath" json:"wasmPluginPath" yaml:"wasmPluginPath"`

	// OpenAI integration
	OpenAIAPIKey     string `mapstructure:"openAIAPIKey" json:"openAIAPIKey" yaml:"openAIAPIKey"`
	EnableAIAnalysis bool   `mapstructure:"enableAIAnalysis" json:"enableAIAnalysis" yaml:"enableAIAnalysis"`

	// Scan URLs
	URLs []string `mapstructure:"urls" json:"urls" yaml:"urls"`
}

// Header represents an HTTP header
type Header struct {
	Name  string `mapstructure:"name" json:"name" yaml:"name"`
	Value string `mapstructure:"value" json:"value" yaml:"value"`
}

// LoadConfig loads the configuration from a file
func LoadConfig(configPath string) (*Config, error) {
	// Create a new viper instance
	v := viper.New()

	// Set default values
	setDefaults(v)

	// Set environment variable prefix
	v.SetEnvPrefix("LLAMASEC")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// If config file is provided, read it
	if configPath != "" {
		// Set the config file path
		v.SetConfigFile(configPath)

		// Read the config file
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Override config with environment variables
	bindEnvVariables(v)

	// Unmarshal the config into a struct
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// Validate the configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// setDefaults sets the default values for the configuration
func setDefaults(v *viper.Viper) {
	v.SetDefault("concurrency", 10)
	v.SetDefault("rateLimit", 5.0)
	v.SetDefault("timeout", 30*time.Second)
	v.SetDefault("userAgent", "LlamaSec/1.0.0 (+https://github.com/yourusername/llamasec)")
	v.SetDefault("respectRobotsTxt", true)
	v.SetDefault("retryCount", 3)
	v.SetDefault("retryWaitTime", 1*time.Second)
	v.SetDefault("retryMaxTime", 15*time.Second)
	v.SetDefault("outputPath", "llamasec_report.md")
	v.SetDefault("outputFormat", "markdown")
	v.SetDefault("verboseOutput", false)
	v.SetDefault("logFile", "llamasec.log")
	v.SetDefault("signaturesPath", filepath.Join("config", "signatures.yaml"))
	v.SetDefault("enableAIAnalysis", false)
}

// bindEnvVariables binds the environment variables to the configuration
func bindEnvVariables(v *viper.Viper) {
	// Core settings
	v.BindEnv("concurrency", "LLAMASEC_CONCURRENCY")
	v.BindEnv("rateLimit", "LLAMASEC_RATE_LIMIT")
	v.BindEnv("timeout", "LLAMASEC_TIMEOUT")
	v.BindEnv("userAgent", "LLAMASEC_USER_AGENT")

	// HTTP settings
	v.BindEnv("proxy", "LLAMASEC_PROXY")
	v.BindEnv("respectRobotsTxt", "LLAMASEC_RESPECT_ROBOTS_TXT")

	// Output settings
	v.BindEnv("outputPath", "LLAMASEC_OUTPUT_PATH")
	v.BindEnv("outputFormat", "LLAMASEC_OUTPUT_FORMAT")
	v.BindEnv("verboseOutput", "LLAMASEC_VERBOSE")

	// OpenAI integration
	v.BindEnv("openAIAPIKey", "OPENAI_API_KEY")
	v.BindEnv("enableAIAnalysis", "LLAMASEC_ENABLE_AI_ANALYSIS")
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Check if concurrency is valid
	if config.Concurrency <= 0 {
		return fmt.Errorf("concurrency must be greater than 0")
	}

	// Check if rate limit is valid
	if config.RateLimit <= 0 {
		return fmt.Errorf("rate limit must be greater than 0")
	}

	// Check if timeout is valid
	if config.Timeout <= 0 {
		return fmt.Errorf("timeout must be greater than 0")
	}

	// Check if output format is valid
	outputFormat := strings.ToLower(config.OutputFormat)
	if outputFormat != "markdown" && outputFormat != "json" && outputFormat != "csv" {
		return fmt.Errorf("invalid output format: %s (must be markdown, json, or csv)", config.OutputFormat)
	}

	// Check if signatures path exists
	if config.SignaturesPath != "" {
		if _, err := os.Stat(config.SignaturesPath); os.IsNotExist(err) {
			// Create default signatures file if it doesn't exist
			if err := createDefaultSignaturesFile(config.SignaturesPath); err != nil {
				return fmt.Errorf("error creating default signatures file: %w", err)
			}
		}
	}

	// Validate OpenAI integration settings
	if config.EnableAIAnalysis && config.OpenAIAPIKey == "" {
		return fmt.Errorf("OpenAI API key is required when AI analysis is enabled")
	}

	return nil
}

// createDefaultSignaturesFile creates a default signatures file
func createDefaultSignaturesFile(path string) error {
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
  patterns:
    - "X-Powered-By:"
    - "Server:.*?(nginx|apache|iis|express).*?[0-9]"
    - "X-AspNet-Version:"
    - "X-Runtime:"

- id: "SEC-001"
  name: "Missing Security Headers"
  description: "Detects missing important security headers"
  severity: "medium"
  patterns:
    - "Content-Security-Policy:"
    - "X-Frame-Options:"
    - "X-XSS-Protection:"
    - "Strict-Transport-Security:"

- id: "API-001"
  name: "API Key Exposure"
  description: "Detects potential exposure of API keys or tokens"
  severity: "high"
  patterns:
    - "api[_-]?key[\"']?\\s*[=:]\\s*[\"'][a-zA-Z0-9_\\-]{20,}[\"']"
    - "access[_-]?token[\"']?\\s*[=:]\\s*[\"'][a-zA-Z0-9_\\-]{20,}[\"']"
    - "secret[_-]?key[\"']?\\s*[=:]\\s*[\"'][a-zA-Z0-9_\\-]{20,}[\"']"
`

	// Write the file
	return os.WriteFile(path, []byte(content), 0644)
}
