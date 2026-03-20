package authclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/gin-gonic/gin"
	"github.com/valyala/fasthttp"
)

var _ http.Handler = (*DiscoveryHandler)(nil)

// ErrNoFilePath is returned when Reload() is called on a handler created with NewDiscoveryHandler (no file path).
var ErrNoFilePath = errors.New("discovery handler: reload requires file-based handler")

// ErrEmptyPath is returned when NewDiscoveryHandlerFromFile is called with an empty path.
var ErrEmptyPath = errors.New("discovery handler: path cannot be empty")

// methodNotAllowedJSON is the pre-serialized 405 response body.
var methodNotAllowedJSON = []byte(`{"error":"method_not_allowed","error_description":"Only GET is supported"}`)

// DiscoveryHandler serves a pre-serialized ScopeManifest as JSON at a discovery endpoint.
// It is designed to sit behind BearerAuth and RequireScope middleware for access control.
//
// The manifest is serialized to JSON once at construction time and served on every request
// without per-request marshaling. Concurrent access is safe via sync.RWMutex.
type DiscoveryHandler struct {
	mu        sync.RWMutex
	jsonData  []byte
	filePath  string        // empty if created from in-memory manifest
	done      chan struct{} // closed by Close() to stop signal listener
	closeOnce sync.Once     // ensures Close() is idempotent
}

// NewDiscoveryHandler creates a DiscoveryHandler from a validated ScopeManifest.
// The manifest is pre-serialized to JSON for efficient serving.
// Panics if manifest is nil (fail-fast pattern, consistent with go-authclient conventions).
func NewDiscoveryHandler(manifest *ScopeManifest) *DiscoveryHandler {
	if manifest == nil {
		panic("NewDiscoveryHandler: manifest cannot be nil")
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		panic("NewDiscoveryHandler: failed to marshal manifest: " + err.Error())
	}
	return &DiscoveryHandler{
		jsonData: data,
		done:     make(chan struct{}),
	}
}

// ServeHTTP implements http.Handler. GET requests return the pre-serialized manifest JSON.
// Non-GET requests return 405 Method Not Allowed with an Allow: GET header.
func (h *DiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write(methodNotAllowedJSON)
		return
	}
	h.mu.RLock()
	data := h.jsonData
	h.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

// GinHandler returns a gin.HandlerFunc that serves the pre-serialized manifest JSON.
// Includes GET method enforcement for defense-in-depth (Gin routes are typically
// method-specific via r.GET, but this guards against r.Any() registration).
func (h *DiscoveryHandler) GinHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet {
			c.Header("Allow", "GET")
			c.Header("X-Content-Type-Options", "nosniff")
			c.Data(http.StatusMethodNotAllowed, "application/json", methodNotAllowedJSON)
			c.Abort()
			return
		}
		h.mu.RLock()
		data := h.jsonData
		h.mu.RUnlock()
		c.Header("Cache-Control", "no-store")
		c.Header("X-Content-Type-Options", "nosniff")
		c.Data(http.StatusOK, "application/json", data)
	}
}

// FastHTTPHandler returns a fasthttp.RequestHandler that serves the pre-serialized manifest JSON.
// Non-GET requests return 405 Method Not Allowed with an Allow: GET header.
func (h *DiscoveryHandler) FastHTTPHandler() fasthttp.RequestHandler {
	return func(ctx *fasthttp.RequestCtx) {
		if !ctx.IsGet() {
			ctx.Response.Header.Set("Allow", "GET")
			ctx.SetContentType("application/json")
			ctx.Response.Header.Set("X-Content-Type-Options", "nosniff")
			ctx.SetStatusCode(fasthttp.StatusMethodNotAllowed)
			ctx.SetBody(methodNotAllowedJSON)
			return
		}
		h.mu.RLock()
		data := h.jsonData
		h.mu.RUnlock()
		ctx.SetContentType("application/json")
		ctx.Response.Header.Set("Cache-Control", "no-store")
		ctx.Response.Header.Set("X-Content-Type-Options", "nosniff")
		ctx.SetStatusCode(fasthttp.StatusOK)
		ctx.SetBody(data)
	}
}

type discoveryConfig struct {
	reloadOnSignal bool
}

// DiscoveryOption configures a DiscoveryHandler created from a file.
type DiscoveryOption func(*discoveryConfig)

// WithReloadOnSignal enables automatic manifest reload when the process receives SIGHUP.
// Only effective for file-based handlers created with NewDiscoveryHandlerFromFile.
// Call Close() to stop the signal listener when the handler is no longer needed.
func WithReloadOnSignal() DiscoveryOption {
	return func(c *discoveryConfig) {
		c.reloadOnSignal = true
	}
}

// NewDiscoveryHandlerFromFile creates a DiscoveryHandler by loading a manifest from a YAML or JSON file.
// The file is loaded via LoadManifestFromFile (from discovery.go), validated, and pre-serialized to JSON.
// The file path is cleaned via filepath.Clean and stored for potential reload via Reload() or SIGHUP signal.
func NewDiscoveryHandlerFromFile(path string, opts ...DiscoveryOption) (*DiscoveryHandler, error) {
	if path == "" {
		return nil, ErrEmptyPath
	}
	path = filepath.Clean(path)

	var cfg discoveryConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	manifest, err := LoadManifestFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("discovery handler: %w", err)
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("discovery handler: marshal: %w", err)
	}

	h := &DiscoveryHandler{
		jsonData: data,
		filePath: path,
		done:     make(chan struct{}),
	}

	if cfg.reloadOnSignal {
		h.startSignalListener()
	}

	return h, nil
}

// Reload reloads the manifest from the original file path, re-validates, and replaces
// the pre-serialized JSON atomically. If reload fails, the previous manifest is preserved.
// Returns error if the handler was not created from a file or if loading/validation fails.
func (h *DiscoveryHandler) Reload() error {
	if h.filePath == "" {
		return ErrNoFilePath
	}

	manifest, err := LoadManifestFromFile(h.filePath)
	if err != nil {
		return fmt.Errorf("discovery handler: reload: %w", err)
	}

	data, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("discovery handler: reload marshal: %w", err)
	}

	h.mu.Lock()
	h.jsonData = data
	h.mu.Unlock()

	return nil
}

// Close stops the SIGHUP signal listener goroutine if active.
// Safe to call on any handler (no-op if no listener is active).
// Safe to call multiple times (idempotent).
func (h *DiscoveryHandler) Close() {
	h.closeOnce.Do(func() {
		close(h.done)
	})
}

func (h *DiscoveryHandler) startSignalListener() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-sigCh:
				if err := h.Reload(); err != nil {
					fmt.Fprintf(os.Stderr, "discovery handler: reload failed: %v\n", err)
				}
			case <-h.done:
				signal.Stop(sigCh)
				return
			}
		}
	}()
}
