package authclient

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

func TestInstrumentedDiscoveryHandler_GET(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	manifest := &ScopeManifest{
		ServiceCode: "test-svc",
		Scopes:      []ScopeDefinition{{Name: "read", Description: "Read access"}},
	}
	inner := NewDiscoveryHandler(manifest)
	defer inner.Close()

	handler := NewInstrumentedDiscoveryHandler(inner, WithMeterProvider(mp))

	req := httptest.NewRequest(http.MethodGet, "/.well-known/scope-manifest", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.discovery.requests.total", 1,
		attribute.String("method", "GET"),
		attribute.String("status", "200"),
	)
}

func TestInstrumentedDiscoveryHandler_MethodNotAllowed(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	manifest := &ScopeManifest{
		ServiceCode: "test-svc",
		Scopes:      []ScopeDefinition{{Name: "read", Description: "Read access"}},
	}
	inner := NewDiscoveryHandler(manifest)
	defer inner.Close()

	handler := NewInstrumentedDiscoveryHandler(inner, WithMeterProvider(mp))

	req := httptest.NewRequest(http.MethodPost, "/.well-known/scope-manifest", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.discovery.requests.total", 1,
		attribute.String("method", "other"),
		attribute.String("status", "405"),
	)
}

func TestInstrumentedDiscoveryHandler_NilInnerPanics(t *testing.T) {
	assert.PanicsWithValue(t, "authclient.NewInstrumentedDiscoveryHandler: handler cannot be nil", func() {
		NewInstrumentedDiscoveryHandler(nil)
	})
}

func TestInstrumentedDiscoveryHandler_ReloadCounter(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	manifest := &ScopeManifest{
		ServiceCode: "test-svc",
		Scopes:      []ScopeDefinition{{Name: "read", Description: "Read access"}},
	}
	// In-memory handler (no file path) — Reload returns ErrNoFilePath
	inner := NewDiscoveryHandler(manifest)
	defer inner.Close()

	handler := NewInstrumentedDiscoveryHandler(inner, WithMeterProvider(mp))

	err := handler.Reload()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoFilePath)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.discovery.reload.total", 1,
		attribute.String("result", "error"),
	)
}
