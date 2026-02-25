// Package ui provides the web-based user interface for Alcatraz.
package ui

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"
)

//go:embed web/*
var webFiles embed.FS

// AppState represents the current application state exposed to the UI.
type AppState struct {
	Active  bool   `json:"active"`
	DNS     string `json:"dns"`
	Mode    string `json:"mode"`
	Port    int    `json:"port"`
	Version string `json:"version"`
}

// Callbacks for the web UI to control the backend.
type Callbacks struct {
	OnToggle         func() bool                   // Toggle proxy, returns new active state
	OnSettingsChange func(key, value string) error // Change a setting
	GetState         func() AppState               // Get current state
	GetDomains       func() []string               // Get custom domain list
	AddDomain        func(domain string)           // Add a custom domain
	RemoveDomain     func(domain string)           // Remove a custom domain
}

// WebUI serves the embedded web interface and REST API.
type WebUI struct {
	port      int
	callbacks Callbacks
	server    *http.Server
	mu        sync.Mutex
}

// NewWebUI creates a new web UI server.
func NewWebUI(port int, cb Callbacks) *WebUI {
	return &WebUI{
		port:      port,
		callbacks: cb,
	}
}

// Start starts the web UI server.
func (w *WebUI) Start(ctx context.Context) error {
	mux := http.NewServeMux()

	// Serve embedded web files
	webFS, err := fs.Sub(webFiles, "web")
	if err != nil {
		return fmt.Errorf("failed to load web files: %w", err)
	}
	mux.Handle("/", http.FileServer(http.FS(webFS)))

	// API endpoints
	mux.HandleFunc("/api/status", w.handleStatus)
	mux.HandleFunc("/api/toggle", w.handleToggle)
	mux.HandleFunc("/api/settings", w.handleSettings)
	mux.HandleFunc("/api/domains", w.handleDomains)

	addr := fmt.Sprintf("127.0.0.1:%d", w.port)
	w.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	// Check if port is available
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("web UI port %d kullanımda: %w", w.port, err)
	}
	ln.Close()

	log.Printf("[Sansürsüz] Web UI: http://%s", addr)

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		w.server.Shutdown(shutCtx)
	}()

	if err := w.server.ListenAndServe(); err != http.ErrServerClosed {
		return err
	}
	return nil
}

// OpenInBrowser opens the web UI in the default browser.
func (w *WebUI) OpenInBrowser() {
	url := fmt.Sprintf("http://127.0.0.1:%d", w.port)
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}

	if err := cmd.Start(); err != nil {
		log.Printf("[Sansürsüz] Tarayıcı açılamadı: %v", err)
	}
}

// GET /api/status
func (w *WebUI) handleStatus(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state := w.callbacks.GetState()
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(state)
}

// POST /api/toggle
func (w *WebUI) handleToggle(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.mu.Lock()
	active := w.callbacks.OnToggle()
	w.mu.Unlock()

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]bool{"active": active})
}

// POST /api/settings
func (w *WebUI) handleSettings(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, "invalid json", http.StatusBadRequest)
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	for key, value := range body {
		if err := w.callbacks.OnSettingsChange(key, value); err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}
	}

	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]string{"status": "ok"})
}

// GET/POST /api/domains
func (w *WebUI) handleDomains(rw http.ResponseWriter, r *http.Request) {
	rw.Header().Set("Content-Type", "application/json")

	if r.Method == http.MethodGet {
		domains := w.callbacks.GetDomains()
		json.NewEncoder(rw).Encode(map[string][]string{"domains": domains})
		return
	}

	if r.Method == http.MethodPost {
		var body struct {
			Action string `json:"action"`
			Domain string `json:"domain"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(rw, "invalid json", http.StatusBadRequest)
			return
		}

		w.mu.Lock()
		defer w.mu.Unlock()

		switch body.Action {
		case "add":
			w.callbacks.AddDomain(body.Domain)
		case "remove":
			w.callbacks.RemoveDomain(body.Domain)
		default:
			http.Error(rw, "invalid action", http.StatusBadRequest)
			return
		}

		json.NewEncoder(rw).Encode(map[string]string{"status": "ok"})
		return
	}

	http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
}
