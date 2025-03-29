package ai

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// OpenAIClient represents a client for interacting with the OpenAI API
type OpenAIClient struct {
	APIKey       string
	Model        string
	MaxTokens    int
	Temperature  float64
	HTTPClient   *http.Client
	BaseURL      string
	Organization string
}

// ChatCompletionMessage represents a message in a chat completion request
type ChatCompletionMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatCompletionRequest represents a request to the OpenAI chat completion API
type ChatCompletionRequest struct {
	Model       string                  `json:"model"`
	Messages    []ChatCompletionMessage `json:"messages"`
	MaxTokens   int                     `json:"max_tokens,omitempty"`
	Temperature float64                 `json:"temperature"`
	Stream      bool                    `json:"stream,omitempty"`
}

// ChatCompletionResponse represents a response from the OpenAI chat completion API
type ChatCompletionResponse struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Choices []struct {
		Index   int `json:"index"`
		Message struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
		TotalTokens      int `json:"total_tokens"`
	} `json:"usage,omitempty"`
}

// ChatCompletionChunk represents a chunk of a streaming response
type ChatCompletionChunk struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Content string `json:"content,omitempty"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
}

// NewOpenAIClient creates a new OpenAI client with the given API key
func NewOpenAIClient(apiKey string) *OpenAIClient {
	// If no API key provided, try to get from environment variable
	if apiKey == "" {
		apiKey = os.Getenv("OPENAI_API_KEY")
	}

	// Create a custom HTTP client with reasonable timeouts
	httpClient := &http.Client{
		Timeout: 60 * time.Second,
		Transport: &http.Transport{
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}

	return &OpenAIClient{
		APIKey:       apiKey,
		Model:        "gpt-3.5-turbo",
		MaxTokens:    1000,
		Temperature:  0.7,
		HTTPClient:   httpClient,
		BaseURL:      "https://api.openai.com/v1",
		Organization: "",
	}
}

// WithModel sets the model to use for completions
func (c *OpenAIClient) WithModel(model string) *OpenAIClient {
	c.Model = model
	return c
}

// WithMaxTokens sets the maximum number of tokens to generate
func (c *OpenAIClient) WithMaxTokens(maxTokens int) *OpenAIClient {
	c.MaxTokens = maxTokens
	return c
}

// WithTemperature sets the temperature for sampling
func (c *OpenAIClient) WithTemperature(temperature float64) *OpenAIClient {
	c.Temperature = temperature
	return c
}

// WithOrganization sets the OpenAI organization ID
func (c *OpenAIClient) WithOrganization(org string) *OpenAIClient {
	c.Organization = org
	return c
}

// AnalyzeVulnerability analyzes a vulnerability and returns a detailed analysis
func (c *OpenAIClient) AnalyzeVulnerability(vulnType, evidence string) (string, error) {
	// Check if API key is set
	if !c.IsAPIKeySet() {
		return "", fmt.Errorf("OpenAI API key not set")
	}

	// Create context-aware prompt with a structured analysis format
	prompt := fmt.Sprintf(`You are a cybersecurity expert analyzing web vulnerabilities. 
Please provide a detailed analysis of the following vulnerability:

VULNERABILITY TYPE: %s
EVIDENCE: %s

Respond with a detailed analysis in the following format:
1. VULNERABILITY EXPLANATION: Brief explanation of what this vulnerability is.
2. POTENTIAL IMPACT: What could an attacker do by exploiting this vulnerability?
3. SEVERITY ASSESSMENT: Analyze how severe this particular instance is based on the evidence.
4. ROOT CAUSE: What typically causes this vulnerability to exist in applications?
5. REMEDIATION STEPS: Provide specific technical steps to fix this vulnerability.
6. REFERENCES: Include relevant OWASP, CWE, or other security standard references.

Focus on being technically precise and providing actionable insights.`, vulnType, evidence)

	messages := []ChatCompletionMessage{
		{Role: "system", Content: "You are a cybersecurity expert specializing in web application security."},
		{Role: "user", Content: prompt},
	}

	// Create chat completion request
	req := ChatCompletionRequest{
		Model:       c.Model,
		Messages:    messages,
		MaxTokens:   c.MaxTokens,
		Temperature: c.Temperature,
	}

	// Send request to OpenAI API
	resp, err := c.sendChatCompletionRequest(req)
	if err != nil {
		return "", fmt.Errorf("error sending request to OpenAI API: %w", err)
	}

	// Check if we have any choices in the response
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no analysis generated by OpenAI")
	}

	// Return the generated analysis
	return resp.Choices[0].Message.Content, nil
}

// AnalyzeVulnerabilityStream analyzes a vulnerability with streaming response
func (c *OpenAIClient) AnalyzeVulnerabilityStream(vulnType, evidence string, callback func(string) bool) error {
	// Check if API key is set
	if !c.IsAPIKeySet() {
		return fmt.Errorf("OpenAI API key not set")
	}

	// Create prompt with a structured analysis format
	prompt := fmt.Sprintf(`You are a cybersecurity expert analyzing web vulnerabilities. 
Please provide a detailed analysis of the following vulnerability:

VULNERABILITY TYPE: %s
EVIDENCE: %s

Respond with a detailed analysis in the following format:
1. VULNERABILITY EXPLANATION: Brief explanation of what this vulnerability is.
2. POTENTIAL IMPACT: What could an attacker do by exploiting this vulnerability?
3. SEVERITY ASSESSMENT: Analyze how severe this particular instance is based on the evidence.
4. ROOT CAUSE: What typically causes this vulnerability to exist in applications?
5. REMEDIATION STEPS: Provide specific technical steps to fix this vulnerability.
6. REFERENCES: Include relevant OWASP, CWE, or other security standard references.

Focus on being technically precise and providing actionable insights.`, vulnType, evidence)

	messages := []ChatCompletionMessage{
		{Role: "system", Content: "You are a cybersecurity expert specializing in web application security."},
		{Role: "user", Content: prompt},
	}

	// Create chat completion request with streaming enabled
	req := ChatCompletionRequest{
		Model:       c.Model,
		Messages:    messages,
		MaxTokens:   c.MaxTokens,
		Temperature: c.Temperature,
		Stream:      true,
	}

	// Send streaming request to OpenAI API
	return c.sendStreamingRequest(req, callback)
}

// GetRemediation retrieves a concise remediation strategy for a vulnerability
func (c *OpenAIClient) GetRemediation(vulnType, evidence string) (string, error) {
	// Check if API key is set
	if !c.IsAPIKeySet() {
		return "", fmt.Errorf("OpenAI API key not set")
	}

	// Create a focused prompt for remediation
	prompt := fmt.Sprintf(`Provide a concise, actionable remediation strategy for the following web security vulnerability:

VULNERABILITY TYPE: %s
EVIDENCE: %s

Focus only on remediation steps. Be specific and technical. Keep it under 200 words.`, vulnType, evidence)

	messages := []ChatCompletionMessage{
		{Role: "system", Content: "You are a cybersecurity engineer focused on practical remediation advice."},
		{Role: "user", Content: prompt},
	}

	// Create chat completion request
	req := ChatCompletionRequest{
		Model:       c.Model,
		Messages:    messages,
		MaxTokens:   300, // Shorter response for remediation
		Temperature: 0.5, // Lower temperature for more focused response
	}

	// Send request to OpenAI API
	resp, err := c.sendChatCompletionRequest(req)
	if err != nil {
		return "", fmt.Errorf("error sending request to OpenAI API: %w", err)
	}

	// Check if we have any choices in the response
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no remediation generated by OpenAI")
	}

	// Return the generated remediation
	return resp.Choices[0].Message.Content, nil
}

// GenerateSecurityReport generates a comprehensive security report for multiple vulnerabilities
func (c *OpenAIClient) GenerateSecurityReport(vulnerabilities []string, scanTarget string) (string, error) {
	// Check if API key is set
	if !c.IsAPIKeySet() {
		return "", fmt.Errorf("OpenAI API key not set")
	}

	// Join vulnerabilities with newlines for better prompt formatting
	vulnList := strings.Join(vulnerabilities, "\n- ")

	// Create a comprehensive report prompt
	prompt := fmt.Sprintf(`Generate a comprehensive security report for the following target: %s

DETECTED VULNERABILITIES:
- %s

Structure the report as follows:
1. EXECUTIVE SUMMARY: Brief overview of findings and risk level.
2. METHODOLOGY: How the scan was conducted.
3. DETAILED FINDINGS: Analysis of each vulnerability.
4. REMEDIATION PRIORITIES: Which issues should be addressed first.
5. REMEDIATION GUIDANCE: Technical steps to address the findings.
6. REFERENCES: Security standards and resources.

The report should be suitable for both technical and non-technical stakeholders.`, scanTarget, vulnList)

	messages := []ChatCompletionMessage{
		{Role: "system", Content: "You are an expert security consultant creating professional security assessment reports."},
		{Role: "user", Content: prompt},
	}

	// Create chat completion request with more tokens for comprehensive report
	req := ChatCompletionRequest{
		Model:       c.Model,
		Messages:    messages,
		MaxTokens:   2500,
		Temperature: 0.7,
	}

	// Send request to OpenAI API
	resp, err := c.sendChatCompletionRequest(req)
	if err != nil {
		return "", fmt.Errorf("error generating security report: %w", err)
	}

	// Check if we have any choices in the response
	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no report generated by OpenAI")
	}

	// Return the generated report
	return resp.Choices[0].Message.Content, nil
}

// sendChatCompletionRequest sends a chat completion request to the OpenAI API
func (c *OpenAIClient) sendChatCompletionRequest(req ChatCompletionRequest) (*ChatCompletionResponse, error) {
	// Marshal request to JSON
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("error marshaling request to JSON: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", c.BaseURL+"/chat/completions", bytes.NewBuffer(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	if c.Organization != "" {
		httpReq.Header.Set("OpenAI-Organization", c.Organization)
	}

	// Send request
	httpResp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("error sending HTTP request: %w", err)
	}
	defer httpResp.Body.Close()

	// Check for error status code
	if httpResp.StatusCode != http.StatusOK {
		// Read error response
		errBody, _ := io.ReadAll(httpResp.Body)
		return nil, fmt.Errorf("OpenAI API error (status %d): %s", httpResp.StatusCode, string(errBody))
	}

	// Read response body
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	// Unmarshal response
	var resp ChatCompletionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("error unmarshaling response: %w", err)
	}

	return &resp, nil
}

// sendStreamingRequest sends a streaming chat completion request
func (c *OpenAIClient) sendStreamingRequest(req ChatCompletionRequest, callback func(string) bool) error {
	// Ensure streaming is enabled
	req.Stream = true

	// Marshal request to JSON
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("error marshaling request to JSON: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", c.BaseURL+"/chat/completions", bytes.NewBuffer(reqJSON))
	if err != nil {
		return fmt.Errorf("error creating HTTP request: %w", err)
	}

	// Set headers
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.APIKey)
	if c.Organization != "" {
		httpReq.Header.Set("OpenAI-Organization", c.Organization)
	}
	httpReq.Header.Set("Accept", "text/event-stream")

	// Send request
	httpResp, err := c.HTTPClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("error sending streaming HTTP request: %w", err)
	}
	defer httpResp.Body.Close()

	// Check for error status code
	if httpResp.StatusCode != http.StatusOK {
		// Read error response
		errBody, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("OpenAI API error (status %d): %s", httpResp.StatusCode, string(errBody))
	}

	// Process streaming response
	reader := bufio.NewReader(httpResp.Body)
	for {
		// Read line from stream
		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading stream: %w", err)
		}

		// Skip empty lines or data: prefix
		line = strings.TrimSpace(line)
		if line == "" || line == "data: [DONE]" {
			continue
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}

		// Extract JSON data
		data := strings.TrimPrefix(line, "data: ")
		var chunk ChatCompletionChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			return fmt.Errorf("error unmarshaling chunk: %w", err)
		}

		// Process content from the chunk
		if len(chunk.Choices) > 0 {
			content := chunk.Choices[0].Delta.Content
			if content != "" {
				// Call callback with content, stop if callback returns false
				if !callback(content) {
					break
				}
			}
		}
	}

	return nil
}

// IsAPIKeySet checks if the OpenAI API key is set
func (c *OpenAIClient) IsAPIKeySet() bool {
	return c.APIKey != ""
}
