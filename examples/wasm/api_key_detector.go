package main

import (
	"regexp"
	"unsafe"
)

// Patterns for common API keys
var apiKeyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)aws[_\-]?(?:access[_\-]?)?key[_\-]?id[_\-]?=\s*["']?([a-zA-Z0-9]{20})["']?`),
	regexp.MustCompile(`(?i)aws[_\-]?(?:secret[_\-]?)?access[_\-]?key[_\-]?=\s*["']?([a-zA-Z0-9/+]{40})["']?`),
	regexp.MustCompile(`(?i)stripe[_\-]?(?:api[_\-]?)?key[_\-]?=\s*["']?(sk|pk)_(?:test|live)_([a-zA-Z0-9]{24,34})["']?`),
	regexp.MustCompile(`(?i)github[_\-]?(?:api[_\-]?)?token[_\-]?=\s*["']?([a-zA-Z0-9]{40})["']?`),
	regexp.MustCompile(`(?i)google[_\-]?(?:api[_\-]?)?key[_\-]?=\s*["']?([a-zA-Z0-9\-_]{39})["']?`),
	regexp.MustCompile(`(?i)firebase[_\-]?key[_\-]?=\s*["']?([a-zA-Z0-9\-_]{39})["']?`),
	regexp.MustCompile(`(?i)slack[_\-]?(?:api[_\-]?)?token[_\-]?=\s*["']?(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{32})["']?`),
	regexp.MustCompile(`(?i)mailchimp[_\-]?(?:api[_\-]?)?key[_\-]?=\s*["']?([0-9a-f]{32}-us[0-9]{1,2})["']?`),
	regexp.MustCompile(`(?i)twilio[_\-]?(?:api[_\-]?)?key[_\-]?=\s*["']?(SK[0-9a-fA-F]{32})["']?`),
	regexp.MustCompile(`(?i)twilio[_\-]?(?:account[_\-]?)?sid[_\-]?=\s*["']?(AC[0-9a-fA-F]{32})["']?`),
	regexp.MustCompile(`(?i)sendgrid[_\-]?(?:api[_\-]?)?key[_\-]?=\s*["']?(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})["']?`),
}

//export alloc
func alloc(size int) unsafe.Pointer {
	buf := make([]byte, size)
	return unsafe.Pointer(&buf[0])
}

// readString reads a string from WebAssembly memory
func readString(ptr unsafe.Pointer, len int) string {
	return string(unsafe.Slice((*byte)(ptr), len))
}

// scanForAPIKeys scans content for API keys
func scanForAPIKeys(content string) (bool, string) {
	for _, pattern := range apiKeyPatterns {
		matches := pattern.FindStringSubmatch(content)
		if len(matches) > 0 {
			// Found an API key
			apiKey := matches[0]

			// Potential API key type
			keyType := "Unknown"
			if pattern.String() == apiKeyPatterns[0].String() {
				keyType = "AWS Access Key ID"
			} else if pattern.String() == apiKeyPatterns[1].String() {
				keyType = "AWS Secret Access Key"
			} else if pattern.String() == apiKeyPatterns[2].String() {
				keyType = "Stripe API Key"
			} else if pattern.String() == apiKeyPatterns[3].String() {
				keyType = "GitHub Token"
			} else if pattern.String() == apiKeyPatterns[4].String() {
				keyType = "Google API Key"
			} else if pattern.String() == apiKeyPatterns[5].String() {
				keyType = "Firebase Key"
			} else if pattern.String() == apiKeyPatterns[6].String() {
				keyType = "Slack API Token"
			} else if pattern.String() == apiKeyPatterns[7].String() {
				keyType = "Mailchimp API Key"
			} else if pattern.String() == apiKeyPatterns[8].String() {
				keyType = "Twilio API Key"
			} else if pattern.String() == apiKeyPatterns[9].String() {
				keyType = "Twilio Account SID"
			} else if pattern.String() == apiKeyPatterns[10].String() {
				keyType = "SendGrid API Key"
			}

			return true, "Potential " + keyType + " found: " + maskAPIKey(apiKey)
		}
	}

	return false, ""
}

// maskAPIKey masks the API key to avoid leaking sensitive data in reports
func maskAPIKey(key string) string {
	if len(key) <= 8 {
		return "********"
	}

	// Show first 4 and last 4 characters
	return key[:4] + "..." + key[len(key)-4:]
}

//export scan_url
func scan_url(urlPtr unsafe.Pointer, urlLen int) unsafe.Pointer {
	// Read content from WebAssembly memory
	content := readString(urlPtr, urlLen)

	// Scan for API keys
	found, result := scanForAPIKeys(content)
	if !found {
		return nil
	}

	// Allocate memory for the result string
	resultBuf := []byte(result + "\x00") // Add null terminator
	resultPtr := alloc(len(resultBuf))

	// Copy result to WebAssembly memory
	copy(unsafe.Slice((*byte)(resultPtr), len(resultBuf)), resultBuf)

	return resultPtr
}

func main() {
	// This function is required by TinyGo but not used by the WebAssembly module
}
