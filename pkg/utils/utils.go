package utils

import (
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// NormalizeURL normalizes a URL
func NormalizeURL(rawURL string) (string, error) {
	// Add scheme if missing
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "https://" + rawURL
	}

	// Parse URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %v", err)
	}

	// Validate URL
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme: %s", parsedURL.Scheme)
	}

	if parsedURL.Host == "" {
		return "", fmt.Errorf("missing host")
	}

	return parsedURL.String(), nil
}

// ParseURLsFromText extracts URLs from text
func ParseURLsFromText(text string) []string {
	// Regular expression to match URLs
	urlRegex := regexp.MustCompile(`(https?://[^\s"'<>()[\]{}]+)`)
	matches := urlRegex.FindAllString(text, -1)

	// Deduplicate URLs
	uniqueURLs := make(map[string]struct{})
	for _, match := range matches {
		uniqueURLs[match] = struct{}{}
	}

	// Convert map to slice
	var urls []string
	for url := range uniqueURLs {
		urls = append(urls, url)
	}

	return urls
}

// EnsureDirectory ensures that a directory exists
func EnsureDirectory(path string) error {
	return os.MkdirAll(path, 0755)
}

// FileExists checks if a file exists
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// SanitizeFilename sanitizes a filename
func SanitizeFilename(name string) string {
	// Replace invalid characters with underscores
	invalidChars := regexp.MustCompile(`[<>:"/\\|?*]`)
	return invalidChars.ReplaceAllString(name, "_")
}

// TruncateString truncates a string to the specified length
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}

	// Try to truncate at a space
	lastSpace := strings.LastIndex(s[:maxLen], " ")
	if lastSpace > 0 {
		return s[:lastSpace] + "..."
	}

	// If no space found, truncate at maxLen
	return s[:maxLen] + "..."
}
