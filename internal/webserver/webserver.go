package webserver

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Server represents a HTTP web server
type Server struct {
	server   *http.Server
	dataDir  string
	quitChan chan bool
}

// NewServer creates a new web server
func NewServer(port int, dataDir string) (*Server, error) {
	// Create server directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("error creating data directory: %v", err)
	}

	// Create a file server handler
	fileServer := http.FileServer(http.Dir(dataDir))

	// Create server
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		Handler:      fileServer,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &Server{
		server:   server,
		dataDir:  dataDir,
		quitChan: make(chan bool),
	}, nil
}

// AddContentFile adds a file to the server
func (s *Server) AddContentFile(path, content string) error {
	// Create route directory
	routeDir := filepath.Dir(filepath.Join(s.dataDir, path))
	if err := os.MkdirAll(routeDir, 0755); err != nil {
		return fmt.Errorf("error creating directory: %v", err)
	}

	// Create file
	filePath := filepath.Join(s.dataDir, path)
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		return fmt.Errorf("error writing file: %v", err)
	}

	return nil
}

// Start starts the web server
func (s *Server) Start() error {
	// Start the server in a goroutine
	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Error starting server: %v\n", err)
		}
	}()

	fmt.Printf("Web server started at http://localhost%s\n", s.server.Addr)

	return nil
}

// Stop stops the web server
func (s *Server) Stop() {
	// Create a deadline for server shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shut down the server
	if err := s.server.Shutdown(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Error stopping server: %v\n", err)
	}

	// Signal that the server has stopped
	s.quitChan <- true
}

// Wait waits for the server to stop
func (s *Server) Wait() {
	<-s.quitChan
}

// CreateHTMLWrapper wraps content in a simple HTML document
func CreateHTMLWrapper(content string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LlamaSec Report</title>
    <style>
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
            line-height: 1.6;
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            color: #333;
        }
        h1, h2, h3, h4, h5, h6 { margin-top: 24px; }
        h1 { color: #2c3e50; }
        h3 { background-color: #f5f5f5; padding: 10px; border-radius: 5px; }
        pre {
            background: #f6f8fa;
            border-radius: 5px;
            padding: 16px;
            overflow: auto;
        }
        code { font-family: 'Courier New', monospace; }
        table {
            border-collapse: collapse;
            width: 100%%;
            margin-bottom: 20px;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: left;
        }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
        .high { color: #e74c3c; }
        .medium { color: #e67e22; }
        .low { color: #f1c40f; }
        .separator { border-top: 1px solid #eee; margin: 30px 0; }
    </style>
</head>
<body>
    <pre>%s</pre>
</body>
</html>`, content)
}

// AddReportServer adds a report server for LlamaSec
func AddReportServer(reportPath string, port int) (*Server, error) {
	// Create temporary directory for the server
	tempDir, err := os.MkdirTemp("", "llamasec-server")
	if err != nil {
		return nil, fmt.Errorf("error creating temporary directory: %v", err)
	}

	// Create server
	server, err := NewServer(port, tempDir)
	if err != nil {
		return nil, fmt.Errorf("error creating server: %v", err)
	}

	// Read report
	reportContent, err := os.ReadFile(reportPath)
	if err != nil {
		return nil, fmt.Errorf("error reading report: %v", err)
	}

	// Convert to HTML
	htmlContent := CreateHTMLWrapper(string(reportContent))

	// Add report file
	if err := server.AddContentFile("index.html", htmlContent); err != nil {
		return nil, fmt.Errorf("error adding report file: %v", err)
	}

	// Start server
	if err := server.Start(); err != nil {
		return nil, fmt.Errorf("error starting server: %v", err)
	}

	return server, nil
}
