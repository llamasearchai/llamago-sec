package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Server represents an HTTP server for serving reports
type Server struct {
	Port       int
	ReportPath string
	server     *http.Server
}

// NewServer creates a new server
func NewServer(reportPath string, port int) *Server {
	return &Server{
		Port:       port,
		ReportPath: reportPath,
	}
}

// ListenAndServe starts the server
func (s *Server) ListenAndServe() error {
	// Create file server
	reportDir := filepath.Dir(s.ReportPath)
	fileServer := http.FileServer(http.Dir(reportDir))

	// Create router
	mux := http.NewServeMux()

	// Register handlers
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Redirect to index page if path is "/"
		if r.URL.Path == "/" {
			reportFileName := filepath.Base(s.ReportPath)
			http.Redirect(w, r, "/"+reportFileName, http.StatusFound)
			return
		}

		// Serve file
		fileServer.ServeHTTP(w, r)
	})

	// Add a health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Add a version endpoint
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"LlamaSec","version":"1.0.0"}`))
	})

	// Verify report file exists
	if _, err := os.Stat(s.ReportPath); os.IsNotExist(err) {
		return fmt.Errorf("report file does not exist: %s", s.ReportPath)
	}

	// Create HTTP server
	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.Port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server
	log.Printf("Starting server on http://localhost:%d", s.Port)
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}

	return s.server.Shutdown(ctx)
}
