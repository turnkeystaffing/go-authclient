package authclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

// --- Test Group 1: In-memory construction (AC1, AC6) ---

func TestNewDiscoveryHandler(t *testing.T) {
	t.Run("valid manifest creates handler with pre-serialized JSON", func(t *testing.T) {
		m := validManifest()
		h := NewDiscoveryHandler(m)
		require.NotNil(t, h)

		// Verify pre-serialized JSON matches json.Marshal of the manifest
		expected, err := json.Marshal(m)
		require.NoError(t, err)

		h.mu.RLock()
		actual := h.jsonData
		h.mu.RUnlock()
		assert.Equal(t, expected, actual)
	})

	t.Run("nil manifest panics", func(t *testing.T) {
		assert.PanicsWithValue(t, "NewDiscoveryHandler: manifest cannot be nil", func() {
			NewDiscoveryHandler(nil)
		})
	})

	t.Run("done channel is initialized", func(t *testing.T) {
		m := validManifest()
		h := NewDiscoveryHandler(m)
		require.NotNil(t, h.done)
	})

	t.Run("filePath is empty for in-memory handler", func(t *testing.T) {
		m := validManifest()
		h := NewDiscoveryHandler(m)
		assert.Empty(t, h.filePath)
	})
}

// --- Test Group 2: HTTP handler (AC3, AC10) ---

func TestDiscoveryHandler_ServeHTTP(t *testing.T) {
	m := validManifest()
	h := NewDiscoveryHandler(m)
	expectedJSON, err := json.Marshal(m)
	require.NoError(t, err)

	t.Run("GET returns 200 with correct JSON and security headers", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/scopes/discovery", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, expectedJSON, rec.Body.Bytes())
	})

	t.Run("POST returns 405 with Allow header", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/scopes/discovery", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
		assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

		var errResp map[string]string
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errResp))
		assert.Equal(t, "method_not_allowed", errResp["error"])
		assert.Equal(t, "Only GET is supported", errResp["error_description"])
	})

	t.Run("PUT returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/scopes/discovery", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
	})

	t.Run("DELETE returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/scopes/discovery", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
	})

	t.Run("HEAD returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/scopes/discovery", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
	})

	t.Run("PATCH returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/scopes/discovery", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
	})

	t.Run("OPTIONS returns 405", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodOptions, "/scopes/discovery", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
	})

	t.Run("response body unmarshals to valid ScopeManifest", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/scopes/discovery", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		var decoded ScopeManifest
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &decoded))
		assert.Equal(t, m.ServiceCode, decoded.ServiceCode)
		assert.Equal(t, m.Scopes, decoded.Scopes)
		assert.Equal(t, m.Templates, decoded.Templates)
	})
}

// --- Test Group 3: Gin handler (AC4) ---

func TestDiscoveryHandler_GinHandler(t *testing.T) {
	m := validManifest()
	h := NewDiscoveryHandler(m)
	expectedJSON, err := json.Marshal(m)
	require.NoError(t, err)

	t.Run("GET returns 200 with correct JSON and security headers", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/scopes/discovery", nil)

		handler := h.GinHandler()
		handler(c)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
		assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, expectedJSON, rec.Body.Bytes())
	})

	t.Run("POST returns 405 with Allow header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPost, "/scopes/discovery", nil)

		h.GinHandler()(c)

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		assert.True(t, c.IsAborted())

		var errResp map[string]string
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errResp))
		assert.Equal(t, "method_not_allowed", errResp["error"])
		assert.Equal(t, "Only GET is supported", errResp["error_description"])
	})

	t.Run("PUT returns 405", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodPut, "/scopes/discovery", nil)

		h.GinHandler()(c)

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
		assert.True(t, c.IsAborted())
	})

	t.Run("DELETE returns 405", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodDelete, "/scopes/discovery", nil)

		h.GinHandler()(c)

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
		assert.True(t, c.IsAborted())
	})

	t.Run("HEAD returns 405", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodHead, "/scopes/discovery", nil)

		h.GinHandler()(c)

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
		assert.True(t, c.IsAborted())
	})

	t.Run("OPTIONS returns 405", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodOptions, "/scopes/discovery", nil)

		h.GinHandler()(c)

		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.Equal(t, "GET", rec.Header().Get("Allow"))
		assert.True(t, c.IsAborted())
	})

	t.Run("response body round-trips to ScopeManifest", func(t *testing.T) {
		rec := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(rec)
		c.Request = httptest.NewRequest(http.MethodGet, "/scopes/discovery", nil)

		h.GinHandler()(c)

		var decoded ScopeManifest
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &decoded))
		assert.Equal(t, m.ServiceCode, decoded.ServiceCode)
	})
}

// --- Test Group 4: FastHTTP handler (AC5) ---

func TestDiscoveryHandler_FastHTTPHandler(t *testing.T) {
	m := validManifest()
	h := NewDiscoveryHandler(m)
	expectedJSON, err := json.Marshal(m)
	require.NoError(t, err)

	t.Run("GET returns 200 with correct JSON and security headers", func(t *testing.T) {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fasthttp.MethodGet)

		handler := h.FastHTTPHandler()
		handler(ctx)

		assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
		assert.Equal(t, "application/json", string(ctx.Response.Header.ContentType()))
		assert.Equal(t, "no-store", string(ctx.Response.Header.Peek("Cache-Control")))
		assert.Equal(t, "nosniff", string(ctx.Response.Header.Peek("X-Content-Type-Options")))
		assert.Equal(t, expectedJSON, ctx.Response.Body())
	})

	t.Run("POST returns 405 with Allow header", func(t *testing.T) {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fasthttp.MethodPost)

		h.FastHTTPHandler()(ctx)

		assert.Equal(t, fasthttp.StatusMethodNotAllowed, ctx.Response.StatusCode())
		assert.Equal(t, "GET", string(ctx.Response.Header.Peek("Allow")))
		assert.Equal(t, "application/json", string(ctx.Response.Header.ContentType()))

		var errResp map[string]string
		require.NoError(t, json.Unmarshal(ctx.Response.Body(), &errResp))
		assert.Equal(t, "method_not_allowed", errResp["error"])
		assert.Equal(t, "Only GET is supported", errResp["error_description"])
	})

	t.Run("PUT returns 405", func(t *testing.T) {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fasthttp.MethodPut)

		h.FastHTTPHandler()(ctx)

		assert.Equal(t, fasthttp.StatusMethodNotAllowed, ctx.Response.StatusCode())
		assert.Equal(t, "GET", string(ctx.Response.Header.Peek("Allow")))
	})

	t.Run("DELETE returns 405", func(t *testing.T) {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fasthttp.MethodDelete)

		h.FastHTTPHandler()(ctx)

		assert.Equal(t, fasthttp.StatusMethodNotAllowed, ctx.Response.StatusCode())
		assert.Equal(t, "GET", string(ctx.Response.Header.Peek("Allow")))
	})

	t.Run("HEAD returns 405", func(t *testing.T) {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fasthttp.MethodHead)

		h.FastHTTPHandler()(ctx)

		assert.Equal(t, fasthttp.StatusMethodNotAllowed, ctx.Response.StatusCode())
		assert.Equal(t, "GET", string(ctx.Response.Header.Peek("Allow")))
	})

	t.Run("OPTIONS returns 405", func(t *testing.T) {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod("OPTIONS")

		h.FastHTTPHandler()(ctx)

		assert.Equal(t, fasthttp.StatusMethodNotAllowed, ctx.Response.StatusCode())
		assert.Equal(t, "GET", string(ctx.Response.Header.Peek("Allow")))
	})

	t.Run("response body round-trips to ScopeManifest", func(t *testing.T) {
		ctx := &fasthttp.RequestCtx{}
		ctx.Request.Header.SetMethod(fasthttp.MethodGet)

		h.FastHTTPHandler()(ctx)

		var decoded ScopeManifest
		require.NoError(t, json.Unmarshal(ctx.Response.Body(), &decoded))
		assert.Equal(t, m.ServiceCode, decoded.ServiceCode)
	})
}

// writeManifestFile writes a ScopeManifest as YAML to a temp file and returns the path.
func writeManifestFile(t *testing.T, dir, name string, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))
	return path
}

const validYAML = "service_code: bgc\nscopes:\n  - name: bgc:contractors:read\n    description: Read contractors\n  - name: bgc:contractors:write\n    description: Write contractors\ntemplates:\n  - name: viewer\n    description: Read-only access\n    scopes:\n      - bgc:contractors:read\n"

const validJSON = `{"service_code":"bgc","scopes":[{"name":"bgc:contractors:read","description":"Read contractors"},{"name":"bgc:contractors:write","description":"Write contractors"}],"templates":[{"name":"viewer","description":"Read-only access","scopes":["bgc:contractors:read"]}]}`

// --- Test Group 5: File-based construction (AC2) ---

func TestNewDiscoveryHandlerFromFile(t *testing.T) {
	t.Run("valid YAML file", func(t *testing.T) {
		dir := t.TempDir()
		path := writeManifestFile(t, dir, "manifest.yaml", validYAML)

		h, err := NewDiscoveryHandlerFromFile(path)
		require.NoError(t, err)
		require.NotNil(t, h)
		defer h.Close()

		// Verify serves correct JSON via HTTP
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		var decoded ScopeManifest
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &decoded))
		assert.Equal(t, "bgc", decoded.ServiceCode)
		assert.Len(t, decoded.Scopes, 2)
	})

	t.Run("valid JSON file", func(t *testing.T) {
		dir := t.TempDir()
		path := writeManifestFile(t, dir, "manifest.json", validJSON)

		h, err := NewDiscoveryHandlerFromFile(path)
		require.NoError(t, err)
		require.NotNil(t, h)
		defer h.Close()

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		var decoded ScopeManifest
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &decoded))
		assert.Equal(t, "bgc", decoded.ServiceCode)
	})

	t.Run("empty path returns error", func(t *testing.T) {
		_, err := NewDiscoveryHandlerFromFile("")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrEmptyPath)
	})

	t.Run("non-existent file returns error", func(t *testing.T) {
		_, err := NewDiscoveryHandlerFromFile("/nonexistent/path/manifest.yaml")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "discovery handler")
	})

	t.Run("invalid manifest content returns validation error", func(t *testing.T) {
		dir := t.TempDir()
		path := writeManifestFile(t, dir, "bad.yaml", "service_code: bgc\nscopes: []\n")

		_, err := NewDiscoveryHandlerFromFile(path)
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrManifestInvalid))
	})

	t.Run("malformed YAML returns parse error", func(t *testing.T) {
		dir := t.TempDir()
		path := writeManifestFile(t, dir, "bad.yaml", ":::not valid yaml\n\t\t{broken")

		_, err := NewDiscoveryHandlerFromFile(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "discovery handler")
	})

	t.Run("stores file path for reload", func(t *testing.T) {
		dir := t.TempDir()
		path := writeManifestFile(t, dir, "manifest.yaml", validYAML)

		h, err := NewDiscoveryHandlerFromFile(path)
		require.NoError(t, err)
		defer h.Close()
		assert.Equal(t, path, h.filePath)
	})

	t.Run("cleans file path with filepath.Clean", func(t *testing.T) {
		dir := t.TempDir()
		writeManifestFile(t, dir, "manifest.yaml", validYAML)

		// Construct a path with redundant segments
		dirtyPath := filepath.Join(dir, ".", "manifest.yaml")
		h, err := NewDiscoveryHandlerFromFile(dirtyPath)
		require.NoError(t, err)
		defer h.Close()

		// The stored path should be cleaned
		assert.Equal(t, filepath.Clean(dirtyPath), h.filePath)
	})
}

// --- Test Group 6: Reload (AC8) ---

func TestDiscoveryHandler_Reload(t *testing.T) {
	t.Run("successful reload updates served JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := writeManifestFile(t, dir, "manifest.yaml", validYAML)

		h, err := NewDiscoveryHandlerFromFile(path)
		require.NoError(t, err)
		defer h.Close()

		// Verify initial response
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var initial ScopeManifest
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &initial))
		assert.Equal(t, "bgc", initial.ServiceCode)

		// Update file with different manifest
		newYAML := "service_code: newapp\nscopes:\n  - name: newapp:data:read\n    description: Read data\n"
		require.NoError(t, os.WriteFile(path, []byte(newYAML), 0644))

		// Reload
		require.NoError(t, h.Reload())

		// Verify updated response
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))
		var updated ScopeManifest
		require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &updated))
		assert.Equal(t, "newapp", updated.ServiceCode)
	})

	t.Run("failed reload preserves previous manifest", func(t *testing.T) {
		dir := t.TempDir()
		path := writeManifestFile(t, dir, "manifest.yaml", validYAML)

		h, err := NewDiscoveryHandlerFromFile(path)
		require.NoError(t, err)
		defer h.Close()

		// Write invalid content
		require.NoError(t, os.WriteFile(path, []byte("service_code: bgc\nscopes: []\n"), 0644))

		// Reload should fail
		err = h.Reload()
		require.Error(t, err)

		// Verify previous manifest still served
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		var preserved ScopeManifest
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preserved))
		assert.Equal(t, "bgc", preserved.ServiceCode)
		assert.Len(t, preserved.Scopes, 2)
	})

	t.Run("returns error for non-file-based handler", func(t *testing.T) {
		h := NewDiscoveryHandler(validManifest())
		err := h.Reload()
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrNoFilePath)
	})

	t.Run("reload after file deleted preserves previous manifest", func(t *testing.T) {
		dir := t.TempDir()
		path := writeManifestFile(t, dir, "manifest.yaml", validYAML)

		h, err := NewDiscoveryHandlerFromFile(path)
		require.NoError(t, err)
		defer h.Close()

		// Delete the file
		require.NoError(t, os.Remove(path))

		// Reload should fail with file-not-found error
		err = h.Reload()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "discovery handler: reload")

		// Previous manifest must still be served (last-known-good)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusOK, rec.Code)
		var preserved ScopeManifest
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preserved))
		assert.Equal(t, "bgc", preserved.ServiceCode)
		assert.Len(t, preserved.Scopes, 2)
	})
}

// --- Test Group 7: Close (AC9) ---

func TestDiscoveryHandler_Close(t *testing.T) {
	t.Run("close without signal listener is no-op", func(t *testing.T) {
		h := NewDiscoveryHandler(validManifest())
		assert.NotPanics(t, func() { h.Close() })
	})

	t.Run("double close is safe", func(t *testing.T) {
		h := NewDiscoveryHandler(validManifest())
		h.Close()
		assert.NotPanics(t, func() { h.Close() })
	})

	t.Run("close on file-based handler is safe", func(t *testing.T) {
		dir := t.TempDir()
		path := writeManifestFile(t, dir, "manifest.yaml", validYAML)
		h, err := NewDiscoveryHandlerFromFile(path)
		require.NoError(t, err)
		assert.NotPanics(t, func() { h.Close() })
		assert.NotPanics(t, func() { h.Close() }) // double close
	})

	t.Run("handler still serves correctly after Close", func(t *testing.T) {
		dir := t.TempDir()
		path := writeManifestFile(t, dir, "manifest.yaml", validYAML)
		h, err := NewDiscoveryHandlerFromFile(path, WithReloadOnSignal())
		require.NoError(t, err)

		h.Close()

		// Handler must still serve the pre-serialized manifest after Close
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusOK, rec.Code)
		var decoded ScopeManifest
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &decoded))
		assert.Equal(t, "bgc", decoded.ServiceCode)
	})

	t.Run("reload still works after Close", func(t *testing.T) {
		dir := t.TempDir()
		path := writeManifestFile(t, dir, "manifest.yaml", validYAML)
		h, err := NewDiscoveryHandlerFromFile(path, WithReloadOnSignal())
		require.NoError(t, err)

		h.Close()

		// Update file with new manifest
		newYAML := "service_code: afterclose\nscopes:\n  - name: afterclose:data:read\n    description: Read data\n"
		require.NoError(t, os.WriteFile(path, []byte(newYAML), 0644))

		// Manual reload should still succeed after Close
		require.NoError(t, h.Reload())

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		assert.Equal(t, http.StatusOK, rec.Code)
		var decoded ScopeManifest
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &decoded))
		assert.Equal(t, "afterclose", decoded.ServiceCode)
	})
}

// --- Test Group 8: WithReloadOnSignal option (AC7) ---

func TestNewDiscoveryHandlerFromFile_WithReloadOnSignal(t *testing.T) {
	dir := t.TempDir()
	path := writeManifestFile(t, dir, "manifest.yaml", validYAML)

	h, err := NewDiscoveryHandlerFromFile(path, WithReloadOnSignal())
	require.NoError(t, err)
	require.NotNil(t, h)

	// Verify handler works
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Close should stop signal listener without panic
	assert.NotPanics(t, func() { h.Close() })
}

// --- Test Group 9: Concurrent access (AC6) ---

func TestDiscoveryHandler_ConcurrentAccess(t *testing.T) {
	m := validManifest()
	h := NewDiscoveryHandler(m)
	expectedJSON, err := json.Marshal(m)
	require.NoError(t, err)

	const numGoroutines = 100
	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	errCh := make(chan error, numGoroutines)

	for range numGoroutines {
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				errCh <- errors.New("unexpected status code")
				return
			}
			if !bytes.Equal(expectedJSON, rec.Body.Bytes()) {
				errCh <- errors.New("response body mismatch")
				return
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// --- Test Group 10: Concurrent reload safety ---

func TestDiscoveryHandler_ReloadConcurrent(t *testing.T) {
	dir := t.TempDir()
	path := writeManifestFile(t, dir, "manifest.yaml", validYAML)

	h, err := NewDiscoveryHandlerFromFile(path)
	require.NoError(t, err)
	defer h.Close()

	const numReaders = 50
	const numReloads = 10
	var wg sync.WaitGroup
	wg.Add(numReaders + numReloads)

	// Launch readers
	for range numReaders {
		go func() {
			defer wg.Done()
			for range 20 {
				req := httptest.NewRequest(http.MethodGet, "/", nil)
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, req)
				if rec.Code != http.StatusOK {
					t.Error("unexpected status code during concurrent read")
					return
				}
				// Response must be valid JSON
				var decoded ScopeManifest
				if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
					t.Errorf("invalid JSON during concurrent read: %v", err)
					return
				}
			}
		}()
	}

	// Launch reloaders
	for range numReloads {
		go func() {
			defer wg.Done()
			_ = h.Reload() // May succeed or fail — either is OK for race test
		}()
	}

	wg.Wait()
}

// --- Test Group 11: SIGHUP reload (AC7) ---

func TestDiscoveryHandler_SignalReload(t *testing.T) {
	dir := t.TempDir()
	path := writeManifestFile(t, dir, "manifest.yaml", validYAML)

	h, err := NewDiscoveryHandlerFromFile(path, WithReloadOnSignal())
	require.NoError(t, err)
	defer h.Close()

	// Verify initial manifest
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	var initial ScopeManifest
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &initial))
	assert.Equal(t, "bgc", initial.ServiceCode)

	// Update file with new valid manifest
	newYAML := "service_code: updated\nscopes:\n  - name: updated:data:read\n    description: Read data\n"
	require.NoError(t, os.WriteFile(path, []byte(newYAML), 0644))

	// Send SIGHUP to self
	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGHUP))

	// Wait for signal handler to process (brief poll)
	assert.Eventually(t, func() bool {
		rec2 := httptest.NewRecorder()
		h.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/", nil))
		var decoded ScopeManifest
		if err := json.Unmarshal(rec2.Body.Bytes(), &decoded); err != nil {
			return false
		}
		return decoded.ServiceCode == "updated"
	}, 2*time.Second, 10*time.Millisecond, "manifest should be reloaded after SIGHUP")

	// Test failed reload: write invalid content, send SIGHUP, verify last-known-good preserved
	require.NoError(t, os.WriteFile(path, []byte("service_code: updated\nscopes: []\n"), 0644))
	require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGHUP))

	// Wait for signal handler to process the failed reload, then verify last-known-good
	// Note: stderr verification is not feasible without a data race since the signal listener
	// goroutine writes to os.Stderr concurrently. Capturing os.Stderr requires swapping a global
	// variable which races with the goroutine's fmt.Fprintf(os.Stderr, ...) call.
	assert.Eventually(t, func() bool {
		rec3 := httptest.NewRecorder()
		h.ServeHTTP(rec3, httptest.NewRequest(http.MethodGet, "/", nil))
		var preserved ScopeManifest
		if err := json.Unmarshal(rec3.Body.Bytes(), &preserved); err != nil {
			return false
		}
		return preserved.ServiceCode == "updated"
	}, 2*time.Second, 10*time.Millisecond, "previous manifest should be preserved after failed reload")
}

// --- Test Group 12: JSON output fidelity (AC11) ---

func TestDiscoveryHandler_JSONOutput(t *testing.T) {
	t.Run("full manifest with all field types", func(t *testing.T) {
		m := &ScopeManifest{
			ServiceCode: "myapp",
			Scopes: []ScopeDefinition{
				{Name: "myapp:users:read", Description: "Read users", Category: "users"},
				{Name: "myapp:users:write", Description: "Write users"},
			},
			Templates: []TemplateDefinition{
				{
					Name:        "viewer",
					Description: "Read-only access",
					Scopes:      []string{"myapp:users:read"},
				},
				{
					Name:     "admin",
					Scopes:   []string{"myapp:users:read", "myapp:users:write"},
					Replaces: "old_admin",
				},
			},
		}
		h := NewDiscoveryHandler(m)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		// Verify byte-exact match with json.Marshal
		expected, err := json.Marshal(m)
		require.NoError(t, err)
		assert.Equal(t, expected, rec.Body.Bytes())

		// Verify all fields present
		var raw map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
		assert.Contains(t, raw, "service_code")
		assert.Contains(t, raw, "scopes")
		assert.Contains(t, raw, "templates")
	})

	t.Run("omitempty fields absent when empty", func(t *testing.T) {
		m := &ScopeManifest{
			ServiceCode: "myapp",
			Scopes: []ScopeDefinition{
				{Name: "myapp:data:read", Description: "Read data"},
			},
		}
		h := NewDiscoveryHandler(m)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		body := rec.Body.String()
		// category is omitempty and not set — should not appear
		assert.NotContains(t, body, "category")
		// templates is omitempty and nil — should not appear
		assert.NotContains(t, body, "templates")
	})

	t.Run("minimal manifest produces valid JSON", func(t *testing.T) {
		m := &ScopeManifest{
			ServiceCode: "min",
			Scopes: []ScopeDefinition{
				{Name: "min:read", Description: "Read"},
			},
		}
		h := NewDiscoveryHandler(m)

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		// Must be valid JSON
		assert.True(t, json.Valid(rec.Body.Bytes()))

		// Round-trip
		var decoded ScopeManifest
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &decoded))
		assert.Equal(t, "min", decoded.ServiceCode)
		assert.Len(t, decoded.Scopes, 1)
		assert.Empty(t, decoded.Templates)
	})

	t.Run("JSON output matches json.Marshal exactly", func(t *testing.T) {
		m := validManifest()
		expected, err := json.Marshal(m)
		require.NoError(t, err)

		h := NewDiscoveryHandler(m)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		assert.Equal(t, expected, rec.Body.Bytes(), "response body must match json.Marshal byte-for-byte")
	})
}

// --- Benchmarks (AC11) ---

func BenchmarkDiscoveryHandler_ServeHTTP(b *testing.B) {
	b.Run("small manifest", func(b *testing.B) {
		h := NewDiscoveryHandler(validManifest())
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
		}
	})

	b.Run("large manifest (100 scopes)", func(b *testing.B) {
		scopes := make([]ScopeDefinition, 100)
		for i := range scopes {
			scopes[i] = ScopeDefinition{
				Name:        fmt.Sprintf("svc:resource_%d:read", i),
				Description: "Test scope",
			}
		}
		m := &ScopeManifest{
			ServiceCode: "svc",
			Scopes:      scopes,
		}
		h := NewDiscoveryHandler(m)
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		b.ReportAllocs()
		b.ResetTimer()
		for range b.N {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
		}
	})
}
