package utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-yaml/yaml"
)

// LoadConfig loads configuration from a file and merges it with default values
func LoadConfig(path string, defaults interface{}) (interface{}, error) {
	// If no config file specified, return defaults
	if path == "" {
		return defaults, nil
	}

	// Read config file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading config file: %v", err)
	}

	// Make a copy of defaults to modify
	config := defaults

	// Determine file type based on extension
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".json":
		if err := json.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("error parsing JSON config: %v", err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &config); err != nil {
			return nil, fmt.Errorf("error parsing YAML config: %v", err)
		}
	default:
		return nil, fmt.Errorf("unsupported config file format: %s", ext)
	}

	return config, nil
}

// LoadURLsFromFile loads URLs from a file (one per line)
func LoadURLsFromFile(path string) ([]string, error) {
	// Read file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading URL file: %v", err)
	}

	// Split into lines
	lines := strings.Split(string(data), "\n")
	var urls []string

	// Process each line
	for _, line := range lines {
		// Trim whitespace
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Normalize URL
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			line = "http://" + line
		}

		urls = append(urls, line)
	}

	return urls, nil
}
