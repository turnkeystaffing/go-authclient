package authclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestInstrumentedGinBearerAuth_Success(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "test", Scopes: []string{"svc:data:read"}}, nil
		},
	}

	r := gin.New()
	r.Use(InstrumentedGinBearerAuth(validator, []InstrumentationOption{WithMeterProvider(mp)}))
	r.GET("/api", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "success"),
		attribute.String("framework", "gin"),
	)
}

func TestInstrumentedGinBearerAuth_MissingHeader(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			t.Fatal("validator should not be called")
			return nil, nil
		},
	}

	r := gin.New()
	r.Use(InstrumentedGinBearerAuth(validator, []InstrumentationOption{WithMeterProvider(mp)}))
	r.GET("/api", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "rejected"),
		attribute.String("reason", "missing_header"),
		attribute.String("framework", "gin"),
	)
}

func TestInstrumentedGinBearerAuth_ValidationFailed(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenInvalid
		},
	}

	r := gin.New()
	r.Use(InstrumentedGinBearerAuth(validator, []InstrumentationOption{WithMeterProvider(mp)}))
	r.GET("/api", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "rejected"),
		attribute.String("reason", "validation_failed"),
		attribute.String("framework", "gin"),
	)
}

func TestInstrumentedGinBearerAuth_NilValidatorPanics(t *testing.T) {
	assert.PanicsWithValue(t, "InstrumentedGinBearerAuth: validator cannot be nil", func() {
		InstrumentedGinBearerAuth(nil, nil)
	})
}

func TestInstrumentedGinRequireScope_Pass(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "test", Scopes: []string{"svc:data:read", "svc:data:write"}}, nil
		},
	}

	r := gin.New()
	r.Use(GinBearerAuth(validator))
	r.Use(InstrumentedGinRequireScope("svc:data:read", []InstrumentationOption{WithMeterProvider(mp)}))
	r.GET("/api", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.scope.total", 1,
		attribute.String("result", "pass"),
		attribute.String("scope", "svc:data:read"),
		attribute.String("framework", "gin"),
	)
}

func TestInstrumentedGinRequireScope_Denied(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "test", Scopes: []string{"svc:data:read"}}, nil
		},
	}

	r := gin.New()
	r.Use(GinBearerAuth(validator))
	r.Use(InstrumentedGinRequireScope("svc:admin:manage", []InstrumentationOption{WithMeterProvider(mp)}))
	r.GET("/api", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.scope.total", 1,
		attribute.String("result", "denied"),
		attribute.String("scope", "svc:admin:manage"),
		attribute.String("framework", "gin"),
	)
}

func TestInstrumentedGinRequireScope_NilScopePanics(t *testing.T) {
	assert.PanicsWithValue(t, "InstrumentedGinRequireScope: scope cannot be empty", func() {
		InstrumentedGinRequireScope("", nil)
	})
}

func TestInstrumentedGinBearerAuth_CustomClaimsKey(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "test"}, nil
		},
	}

	customKey := "custom_claims"

	r := gin.New()
	r.Use(InstrumentedGinBearerAuth(validator,
		[]InstrumentationOption{WithMeterProvider(mp)},
		WithGinClaimsKey(customKey),
	))
	r.GET("/api", func(c *gin.Context) {
		// Verify claims are stored under custom key
		_, exists := c.Get(customKey)
		require.True(t, exists)
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "success"),
		attribute.String("framework", "gin"),
	)
}
