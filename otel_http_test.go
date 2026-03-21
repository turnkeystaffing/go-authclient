package authclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

func TestInstrumentedHTTPBearerAuth_Success(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "test"}, nil
		},
	}

	handler := InstrumentedHTTPBearerAuth(validator, []InstrumentationOption{WithMeterProvider(mp)})
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	handler(next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "success"),
		attribute.String("framework", "net_http"),
	)
}

func TestInstrumentedHTTPBearerAuth_MissingHeader(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			t.Fatal("validator should not be called")
			return nil, nil
		},
	}

	handler := InstrumentedHTTPBearerAuth(validator, []InstrumentationOption{WithMeterProvider(mp)})
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next should not be called")
	})

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rec := httptest.NewRecorder()

	handler(next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "rejected"),
		attribute.String("reason", "missing_header"),
		attribute.String("framework", "net_http"),
	)
}

func TestInstrumentedHTTPBearerAuth_InvalidFormat(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, nil
		},
	}

	handler := InstrumentedHTTPBearerAuth(validator, []InstrumentationOption{WithMeterProvider(mp)})
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Basic abc123")
	rec := httptest.NewRecorder()

	handler(next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "rejected"),
		attribute.String("reason", "invalid_format"),
		attribute.String("framework", "net_http"),
	)
}

func TestInstrumentedHTTPBearerAuth_ValidationFailed(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenInvalid
		},
	}

	handler := InstrumentedHTTPBearerAuth(validator, []InstrumentationOption{WithMeterProvider(mp)})
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()

	handler(next).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "rejected"),
		attribute.String("reason", "validation_failed"),
		attribute.String("framework", "net_http"),
	)
}

func TestInstrumentedHTTPBearerAuth_NilValidatorPanics(t *testing.T) {
	assert.PanicsWithValue(t, "InstrumentedHTTPBearerAuth: validator cannot be nil", func() {
		InstrumentedHTTPBearerAuth(nil, nil)
	})
}

func TestClassifyHTTPAuthRejection(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{"missing_header", nil, "missing_header"},
		{"invalid_format", map[string]string{"Authorization": "Basic abc"}, "invalid_format"},
		{"empty_token", map[string]string{"Authorization": "Bearer "}, "empty_token"},
		{"validation_failed", map[string]string{"Authorization": "Bearer some-token"}, "validation_failed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			assert.Equal(t, tt.expected, classifyHTTPAuthRejection(req))
		})
	}
}

func TestInstrumentedHTTPBearerAuth_WithCustomErrorHandler(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	var customCalled bool
	customHandler := func(w http.ResponseWriter, _ *http.Request, statusCode int, _, _ string) {
		customCalled = true
		w.WriteHeader(statusCode)
	}

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenInvalid
		},
	}

	handler := InstrumentedHTTPBearerAuth(validator,
		[]InstrumentationOption{WithMeterProvider(mp)},
		WithHTTPErrorHandler(customHandler),
	)
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	rec := httptest.NewRecorder()

	handler(next).ServeHTTP(rec, req)

	require.True(t, customCalled, "custom error handler should be called")

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "rejected"),
		attribute.String("framework", "net_http"),
	)
}
