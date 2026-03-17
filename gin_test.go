package authclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

// parseGinErrorResponse parses the error response body from httptest.ResponseRecorder.
func parseGinErrorResponse(t *testing.T, rec *httptest.ResponseRecorder) errorResponse {
	t.Helper()
	var resp errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

// newGinTestContext creates a gin test context with a fresh recorder and request.
func newGinTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	return c, w
}

// --- GinBearerAuth Tests ---

func TestGinBearerAuth_MissingAuthHeader(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Missing authorization header", resp.ErrorDescription)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

func TestGinBearerAuth_InvalidFormat(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	c.Request.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Invalid authorization header format", resp.ErrorDescription)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_request"`)
}

func TestGinBearerAuth_EmptyToken(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	c.Request.Header.Set("Authorization", "Bearer ")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Empty bearer token", resp.ErrorDescription)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_request"`)
}

func TestGinBearerAuth_OversizedToken(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator)

	bigToken := strings.Repeat("a", MaxBearerTokenLength+1)
	c, w := newGinTestContext()
	c.Request.Header.Set("Authorization", "Bearer "+bigToken)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Bearer token exceeds maximum length", resp.ErrorDescription)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_request"`)
}

func TestGinBearerAuth_ValidToken_ClaimsInGinAndRequestContext(t *testing.T) {
	expectedClaims := &Claims{
		ClientID: "test-client-uuid",
		Scopes:   []string{"read", "write"},
	}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "valid-token-123", token)
			return expectedClaims, nil
		},
	}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	c.Request.Header.Set("Authorization", "Bearer valid-token-123")

	handlerCalled := false
	// Use gin engine to properly chain middleware
	router := gin.New()
	router.Use(mw)
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		// Verify gin context retrieval
		val, exists := c.Get("auth_claims")
		assert.True(t, exists)
		ginClaims := val.(*Claims)
		assert.Equal(t, expectedClaims, ginClaims)

		// Verify request context retrieval
		ctxClaims, ok := ClaimsFromContext(c.Request.Context())
		assert.True(t, ok)
		assert.Same(t, ginClaims, ctxClaims, "gin context and request context should hold same pointer")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token-123")
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinBearerAuth_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenInvalid
		},
	}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	c.Request.Header.Set("Authorization", "Bearer bad-token")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
	assert.Equal(t, "Token validation failed", resp.ErrorDescription)
}

func TestGinBearerAuth_ValidatorReturnsNilClaimsNilError(t *testing.T) {
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, nil
		},
	}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	c.Request.Header.Set("Authorization", "Bearer some-token")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestGinBearerAuth_CustomErrorHandler(t *testing.T) {
	validator := &mockTokenValidator{}
	customCalled := false
	var receivedCode int
	var receivedErrCode, receivedErrDesc string
	mw := GinBearerAuth(validator, WithGinErrorHandler(func(c *gin.Context, statusCode int, errCode, errDesc string) {
		customCalled = true
		receivedCode = statusCode
		receivedErrCode = errCode
		receivedErrDesc = errDesc
		c.AbortWithStatusJSON(statusCode, gin.H{"custom": errCode + ": " + errDesc})
	}))

	c, w := newGinTestContext()
	mw(c)

	assert.True(t, customCalled)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, http.StatusUnauthorized, receivedCode)
	assert.Equal(t, "invalid_request", receivedErrCode)
	assert.Equal(t, "Missing authorization header", receivedErrDesc)
}

func TestGinBearerAuth_CustomClaimsKey(t *testing.T) {
	claims := &Claims{ClientID: "custom-key"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}
	mw := GinBearerAuth(validator, WithGinClaimsKey("my_claims"))

	router := gin.New()
	router.Use(mw)

	handlerCalled := false
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		val, exists := c.Get("my_claims")
		assert.True(t, exists)
		ginClaims := val.(*Claims)
		assert.Equal(t, claims, ginClaims)

		// F2 fix: verify request context also has claims (context bridge)
		ctxClaims, ok := ClaimsFromContext(c.Request.Context())
		assert.True(t, ok, "ClaimsFromContext must find claims even with custom gin key")
		assert.Same(t, ginClaims, ctxClaims, "gin context and request context must hold same pointer")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer token")
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
}

func TestGinBearerAuth_NilValidatorPanics(t *testing.T) {
	assert.PanicsWithValue(t, "GinBearerAuth: validator cannot be nil", func() {
		GinBearerAuth(nil)
	})
}

func TestGinBearerAuth_EmptyClaimsKeyPanics(t *testing.T) {
	assert.PanicsWithValue(t, "WithGinClaimsKey: key cannot be empty", func() {
		WithGinClaimsKey("")
	})
}

func TestGinBearerAuth_NilErrorHandlerUsesDefault(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator, WithGinErrorHandler(nil))

	c, w := newGinTestContext()
	mw(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

func TestGinBearerAuth_ContentTypeJSON(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	mw(c)

	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

func TestGinBearerAuth_WWWAuthenticateHeader_401(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	mw(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")
	assert.Contains(t, wwwAuth, `realm="api"`)
	assert.Contains(t, wwwAuth, `error="invalid_request"`)
}

func TestGinBearerAuth_ErrorResponseJSON(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	mw(c)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	assert.Len(t, raw, 2)
	assert.Contains(t, raw, "error")
	assert.Contains(t, raw, "error_description")
	assert.Equal(t, "invalid_request", raw["error"])
}

func TestGinBearerAuth_LowercaseBearer(t *testing.T) {
	claims := &Claims{ClientID: "case-test"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(GinBearerAuth(validator))
	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "bearer my-token")
	router.ServeHTTP(w, req)

	assert.True(t, called, "lowercase 'bearer' should be accepted per RFC 6750/2617")
}

func TestGinBearerAuth_UppercaseBearer(t *testing.T) {
	claims := &Claims{ClientID: "case-test"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(GinBearerAuth(validator))
	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "BEARER my-token")
	router.ServeHTTP(w, req)

	assert.True(t, called, "uppercase 'BEARER' should be accepted per RFC 6750/2617")
}

func TestGinBearerAuth_MixedCaseBearer(t *testing.T) {
	claims := &Claims{ClientID: "mixed-case"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(GinBearerAuth(validator))
	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "BeArEr my-token")
	router.ServeHTTP(w, req)

	assert.True(t, called, "mixed case 'BeArEr' should be accepted per RFC 6750/2617")
}

func TestGinBearerAuth_TokenWhitespaceTrimmed(t *testing.T) {
	claims := &Claims{ClientID: "trim-test"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token, "token should be trimmed of whitespace")
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(GinBearerAuth(validator))
	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer  my-token ")
	router.ServeHTTP(w, req)

	assert.True(t, called)
}

func TestGinBearerAuth_ShortAuthHeader(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	c.Request.Header.Set("Authorization", "Bear")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Invalid authorization header format", resp.ErrorDescription)
}

func TestGinBearerAuth_ValidatorReceivesRequestContext(t *testing.T) {
	type testCtxKey struct{}
	var receivedCtx context.Context
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(ctx context.Context, _ string) (*Claims, error) {
			receivedCtx = ctx
			return &Claims{ClientID: "ctx-test"}, nil
		},
	}

	router := gin.New()
	router.Use(GinBearerAuth(validator))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), testCtxKey{}, "marker"))
	req.Header.Set("Authorization", "Bearer token")
	router.ServeHTTP(w, req)

	require.NotNil(t, receivedCtx, "validator should receive request context")
	assert.Equal(t, "marker", receivedCtx.Value(testCtxKey{}))
}

func TestGinBearerAuth_IsAbortedAfterError(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator)

	c, _ := newGinTestContext()
	mw(c)

	assert.True(t, c.IsAborted(), "c.IsAborted() must be true after error response")
}

func TestGinBearerAuth_CustomErrorHandlerWithoutAbort_ChainStops(t *testing.T) {
	validator := &mockTokenValidator{}
	// Custom error handler that does NOT call c.Abort()
	mw := GinBearerAuth(validator, WithGinErrorHandler(func(c *gin.Context, statusCode int, errCode, errDesc string) {
		c.JSON(statusCode, gin.H{"err": errCode})
		// Intentionally NOT calling c.Abort()
	}))

	router := gin.New()
	router.Use(mw)

	protectedCalled := false
	router.GET("/test", func(_ *gin.Context) { protectedCalled = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.False(t, protectedCalled, "protected handler must NOT execute when auth fails, even if custom error handler doesn't call c.Abort()")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- GinRequireScope Tests ---

func TestGinRequireScope_ScopePresent(t *testing.T) {
	claims := &Claims{Scopes: []string{"read", "write"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireScope("read"))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinRequireScope_ScopeMissing(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireScope("admin"))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusForbidden, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required scope: admin", resp.ErrorDescription)
}

func TestGinRequireScope_NoClaims(t *testing.T) {
	router := gin.New()
	router.Use(GinRequireScope("read"))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
	assert.Equal(t, "Missing authentication context", resp.ErrorDescription)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="invalid_token"`)
}

func TestGinRequireScope_EmptyScopePanics(t *testing.T) {
	assert.PanicsWithValue(t, "GinRequireScope: scope cannot be empty", func() {
		GinRequireScope("")
	})
}

func TestGinRequireScope_SpecialCharScope(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireScope("audit:read/write"))

	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "audit:read/write")
}

func TestGinRequireScope_CustomClaimsKey(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("my_claims", claims)
		c.Next()
	})
	router.Use(GinRequireScope("read", WithGinScopeClaimsKey("my_claims")))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
}

func TestGinRequireScope_CustomErrorHandler(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	customCalled := false
	var receivedErrCode, receivedErrDesc string
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireScope("admin", WithGinScopeErrorHandler(func(c *gin.Context, statusCode int, errCode, errDesc string) {
		customCalled = true
		receivedErrCode = errCode
		receivedErrDesc = errDesc
		c.AbortWithStatusJSON(statusCode, gin.H{"custom": errCode + ": " + errDesc})
	})))

	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, customCalled)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "insufficient_scope", receivedErrCode)
	assert.Equal(t, "Required scope: admin", receivedErrDesc)
}

func TestGinRequireScope_WWWAuthenticateHeader_403(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireScope("admin"))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="insufficient_scope"`)
}

// --- GinRequireAnyScope Tests ---

func TestGinRequireAnyScope_AnyMatch(t *testing.T) {
	claims := &Claims{Scopes: []string{"read", "write"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireAnyScope([]string{"admin", "write"}))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
}

func TestGinRequireAnyScope_NoneMatch(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireAnyScope([]string{"admin", "write"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required one of scopes: admin, write", resp.ErrorDescription)
}

func TestGinRequireAnyScope_NoClaims(t *testing.T) {
	router := gin.New()
	router.Use(GinRequireAnyScope([]string{"read"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestGinRequireAnyScope_EmptyScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "GinRequireAnyScope: scopes cannot be empty", func() {
		GinRequireAnyScope([]string{})
	})
}

func TestGinRequireAnyScope_NilScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "GinRequireAnyScope: scopes cannot be empty", func() {
		GinRequireAnyScope(nil)
	})
}

func TestGinRequireAnyScope_DefensiveScopesCopy(t *testing.T) {
	claims := &Claims{Scopes: []string{"admin"}}

	scopes := []string{"admin", "write"}
	mw := GinRequireAnyScope(scopes)

	// Mutate original slice after middleware creation
	scopes[0] = "MUTATED"

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(mw)

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called, "middleware should use defensively-copied scopes, not mutated original")
}

func TestGinRequireAnyScope_CustomErrorHandler(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	customCalled := false
	var receivedErrCode, receivedErrDesc string
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireAnyScope([]string{"admin", "write"}, WithGinScopeErrorHandler(func(c *gin.Context, statusCode int, errCode, errDesc string) {
		customCalled = true
		receivedErrCode = errCode
		receivedErrDesc = errDesc
		c.AbortWithStatusJSON(statusCode, gin.H{"custom": errCode})
	})))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, customCalled)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "insufficient_scope", receivedErrCode)
	assert.Equal(t, "Required one of scopes: admin, write", receivedErrDesc)
}

func TestGinRequireAnyScope_WWWAuthenticateHeader_403(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireAnyScope([]string{"admin", "write"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="insufficient_scope"`)
	assert.Contains(t, wwwAuth, "admin, write")
}

func TestGinScopeErrorHandler_NilUsesDefault(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireScope("admin", WithGinScopeErrorHandler(nil)))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "insufficient_scope", resp.Error)
}

func TestGinScopeClaimsKey_EmptyPanics(t *testing.T) {
	assert.PanicsWithValue(t, "WithGinScopeClaimsKey: key cannot be empty", func() {
		WithGinScopeClaimsKey("")
	})
}

// --- GinNoopAuth Tests ---

func TestGinNoopAuth_InjectsClaims(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "noop-client",
		Scopes:   []string{"read", "write"},
	}

	router := gin.New()
	router.Use(GinNoopAuth(defaultClaims))

	router.GET("/test", func(c *gin.Context) {
		// gin context path
		val, exists := c.Get("auth_claims")
		assert.True(t, exists)
		ginClaims := val.(*Claims)
		assert.Equal(t, "noop-client", ginClaims.ClientID)
		assert.Equal(t, []string{"read", "write"}, ginClaims.Scopes)

		// request context path
		ctxClaims, ok := ClaimsFromContext(c.Request.Context())
		assert.True(t, ok)
		assert.Same(t, ginClaims, ctxClaims)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
}

func TestGinNoopAuth_DeepCopy(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "original",
		Scopes:   []string{"read"},
	}
	noopMw := GinNoopAuth(defaultClaims)

	router := gin.New()
	router.Use(noopMw)

	requestNum := 0
	router.GET("/test", func(c *gin.Context) {
		requestNum++
		val, _ := c.Get("auth_claims")
		claims := val.(*Claims)
		if requestNum == 1 {
			claims.Scopes = append(claims.Scopes, "mutated")
			claims.ClientID = "mutated"
		} else {
			assert.Equal(t, "original", claims.ClientID)
			assert.Equal(t, []string{"read"}, claims.Scopes)
		}
	})

	// First request: mutate claims
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w1, req1)

	// Second request: should get clean copy
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w2, req2)

	// Original unchanged
	assert.Equal(t, "original", defaultClaims.ClientID)
	assert.Equal(t, []string{"read"}, defaultClaims.Scopes)
}

func TestGinNoopAuth_NilDefaultClaimsPanics(t *testing.T) {
	assert.PanicsWithValue(t, "GinNoopAuth: defaultClaims cannot be nil", func() {
		GinNoopAuth(nil)
	})
}

func TestGinNoopAuth_ConcurrentDeepCopy(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "concurrent-client",
		Scopes:   []string{"read", "write"},
	}

	// Single router — concurrent requests hit the same handler chain.
	router := gin.New()
	router.Use(GinNoopAuth(defaultClaims))
	router.GET("/test", func(c *gin.Context) {
		val, _ := c.Get("auth_claims")
		claims := val.(*Claims)
		claims.Scopes = append(claims.Scopes, "mutated")
		claims.ClientID = "mutated"
	})

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			router.ServeHTTP(w, req)
		}()
	}

	wg.Wait()

	assert.Equal(t, "concurrent-client", defaultClaims.ClientID)
	assert.Equal(t, []string{"read", "write"}, defaultClaims.Scopes)
}

func TestGinNoopAuth_DeepCopyNumericDates(t *testing.T) {
	expTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nbfTime := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)
	iatTime := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)
	defaultClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "test-subject",
			ID:        "test-jti",
			ExpiresAt: jwt.NewNumericDate(expTime),
			NotBefore: jwt.NewNumericDate(nbfTime),
			IssuedAt:  jwt.NewNumericDate(iatTime),
		},
		ClientID: "date-client",
	}

	router := gin.New()
	router.Use(GinNoopAuth(defaultClaims))
	router.GET("/test", func(c *gin.Context) {
		val, _ := c.Get("auth_claims")
		claims := val.(*Claims)

		require.NotNil(t, claims.ExpiresAt)
		require.NotNil(t, claims.NotBefore)
		require.NotNil(t, claims.IssuedAt)

		assert.NotSame(t, defaultClaims.ExpiresAt, claims.ExpiresAt)
		assert.NotSame(t, defaultClaims.NotBefore, claims.NotBefore)
		assert.NotSame(t, defaultClaims.IssuedAt, claims.IssuedAt)

		assert.Equal(t, expTime.Unix(), claims.ExpiresAt.Unix())
		assert.Equal(t, nbfTime.Unix(), claims.NotBefore.Unix())
		assert.Equal(t, iatTime.Unix(), claims.IssuedAt.Unix())

		// F7 fix: verify RegisteredClaims string fields survive deep copy
		assert.Equal(t, "test-issuer", claims.Issuer)
		assert.Equal(t, "test-subject", claims.Subject)
		assert.Equal(t, "test-jti", claims.ID)

		claims.ExpiresAt = jwt.NewNumericDate(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, expTime.Unix(), defaultClaims.ExpiresAt.Unix())
}

// --- GinNoopScope Tests ---

func TestGinNoopScope_PassesThrough(t *testing.T) {
	router := gin.New()
	router.Use(GinNoopScope())

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
}

// --- Middleware Chain Tests ---

func TestGinMiddlewareChain_BearerAuth_RequireScope(t *testing.T) {
	claims := &Claims{ClientID: "chain-client", Scopes: []string{"read", "write"}}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(GinBearerAuth(validator))
	router.Use(GinRequireScope("read"))

	handlerCalled := false
	router.GET("/test", func(_ *gin.Context) { handlerCalled = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinMiddlewareChain_BearerAuth_RequireScope_Denied(t *testing.T) {
	claims := &Claims{ClientID: "chain-client", Scopes: []string{"read"}}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(GinBearerAuth(validator))
	router.Use(GinRequireScope("admin"))

	handlerCalled := false
	router.GET("/test", func(_ *gin.Context) { handlerCalled = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.False(t, handlerCalled)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestGinMiddlewareChain_BearerAuth_RequireAnyScope(t *testing.T) {
	claims := &Claims{ClientID: "chain-client", Scopes: []string{"read", "write"}}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(GinBearerAuth(validator))
	router.Use(GinRequireAnyScope([]string{"admin", "write"}))

	handlerCalled := false
	router.GET("/test", func(_ *gin.Context) { handlerCalled = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinMiddlewareChain_NoopAuth_RequireScope(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "noop-chain",
		Scopes:   []string{"read", "admin"},
	}

	router := gin.New()
	router.Use(GinNoopAuth(defaultClaims))
	router.Use(GinRequireScope("admin"))

	handlerCalled := false
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		ctxClaims, ok := ClaimsFromContext(c.Request.Context())
		assert.True(t, ok)
		assert.Equal(t, "noop-chain", ctxClaims.ClientID)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinMiddlewareChain_NoopAuth_NoopScope(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "noop-full",
		Scopes:   []string{"dev"},
	}

	router := gin.New()
	router.Use(GinNoopAuth(defaultClaims))
	router.Use(GinNoopScope())

	handlerCalled := false
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		ctxClaims, ok := ClaimsFromContext(c.Request.Context())
		assert.True(t, ok)
		assert.Equal(t, "noop-full", ctxClaims.ClientID)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- QA-Generated Tests (Step 7) ---

func TestGinBearerAuth_MaxLengthTokenAccepted(t *testing.T) {
	exactToken := strings.Repeat("a", MaxBearerTokenLength)
	claims := &Claims{ClientID: "boundary-test"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Len(t, token, MaxBearerTokenLength)
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(GinBearerAuth(validator))
	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+exactToken)
	router.ServeHTTP(w, req)

	assert.True(t, called, "token at exact MaxBearerTokenLength should be accepted")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinBearerAuth_WhitespaceOnlyTokenEmpty(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	c.Request.Header.Set("Authorization", "Bearer    ")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Empty bearer token", resp.ErrorDescription)
}

func TestGinBearerAuth_WWWAuthenticateHeader_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenInvalid
		},
	}
	mw := GinBearerAuth(validator)

	c, w := newGinTestContext()
	c.Request.Header.Set("Authorization", "Bearer bad-token")
	mw(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="invalid_token"`)
	assert.Contains(t, wwwAuth, `error_description="Token validation failed"`)
}

func TestGinRequireScope_WrongTypeInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", "not-a-claims-pointer")
		c.Next()
	})
	router.Use(GinRequireScope("read"))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
	assert.Equal(t, "Missing authentication context", resp.ErrorDescription)
}

func TestGinRequireScope_NilClaimsInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", (*Claims)(nil))
		c.Next()
	})
	router.Use(GinRequireScope("read"))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestGinRequireAnyScope_WrongTypeInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", 42)
		c.Next()
	})
	router.Use(GinRequireAnyScope([]string{"read"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestGinRequireAnyScope_NilClaimsInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", (*Claims)(nil))
		c.Next()
	})
	router.Use(GinRequireAnyScope([]string{"read"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestGinRequireAnyScope_CustomClaimsKey(t *testing.T) {
	claims := &Claims{Scopes: []string{"admin"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("custom_key", claims)
		c.Next()
	})
	router.Use(GinRequireAnyScope([]string{"admin", "write"}, WithGinScopeClaimsKey("custom_key")))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinNoopAuth_DeepCopyAudience(t *testing.T) {
	defaultClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"aud1", "aud2"},
		},
		ClientID: "audience-test",
	}
	noopMw := GinNoopAuth(defaultClaims)

	router := gin.New()
	router.Use(noopMw)

	requestNum := 0
	router.GET("/test", func(c *gin.Context) {
		requestNum++
		val, _ := c.Get("auth_claims")
		claims := val.(*Claims)
		if requestNum == 1 {
			// Mutate audience on first request
			claims.Audience = append(claims.Audience, "mutated")
		} else {
			// Second request should have clean copy
			assert.Equal(t, jwt.ClaimStrings{"aud1", "aud2"}, claims.Audience)
		}
	})

	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w1, req1)

	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w2, req2)

	// Original unchanged
	assert.Equal(t, jwt.ClaimStrings{"aud1", "aud2"}, defaultClaims.Audience)
}

func TestGinNoopAuth_ScopeKeyMismatch_Returns401(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "mismatch-test",
		Scopes:   []string{"read"},
	}

	router := gin.New()
	router.Use(GinNoopAuth(defaultClaims))
	// GinNoopAuth stores under "auth_claims", but scope looks under "custom_key"
	router.Use(GinRequireScope("read", WithGinScopeClaimsKey("custom_key")))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.False(t, called, "handler must NOT execute when claims key mismatches")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

// --- GinRequireScopeWildcard Tests ---

func TestGinRequireScopeWildcard_WildcardMatch(t *testing.T) {
	claims := &Claims{Scopes: []string{"bgc:contractors:*"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireScopeWildcard("bgc:contractors:read"))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinRequireScopeWildcard_ScopeMissing(t *testing.T) {
	claims := &Claims{Scopes: []string{"bgc:contractors:*"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireScopeWildcard("acct:invoices:read"))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required scope: acct:invoices:read", resp.ErrorDescription)
}

func TestGinRequireScopeWildcard_NoClaims(t *testing.T) {
	router := gin.New()
	router.Use(GinRequireScopeWildcard("read"))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestGinRequireScopeWildcard_EmptyScopePanics(t *testing.T) {
	assert.PanicsWithValue(t, "GinRequireScopeWildcard: scope cannot be empty", func() {
		GinRequireScopeWildcard("")
	})
}

func TestGinRequireScopeWildcard_WWWAuthenticateHeader_403(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireScopeWildcard("admin"))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="insufficient_scope"`)
}

// --- GinRequireAnyScopeWildcard Tests ---

func TestGinRequireAnyScopeWildcard_WildcardMatch(t *testing.T) {
	claims := &Claims{Scopes: []string{"bgc:*"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireAnyScopeWildcard([]string{"acct:invoices:read", "bgc:contractors:read"}))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
}

func TestGinRequireAnyScopeWildcard_NoneMatch(t *testing.T) {
	claims := &Claims{Scopes: []string{"acct:expenses:read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireAnyScopeWildcard([]string{"admin", "write"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required one of scopes: admin, write", resp.ErrorDescription)
}

func TestGinRequireAnyScopeWildcard_NoClaims(t *testing.T) {
	router := gin.New()
	router.Use(GinRequireAnyScopeWildcard([]string{"read"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGinRequireAnyScopeWildcard_EmptyScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "GinRequireAnyScopeWildcard: scopes cannot be empty", func() {
		GinRequireAnyScopeWildcard([]string{})
	})
}

func TestGinRequireAnyScopeWildcard_NilScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "GinRequireAnyScopeWildcard: scopes cannot be empty", func() {
		GinRequireAnyScopeWildcard(nil)
	})
}

func TestGinRequireAnyScopeWildcard_DefensiveScopesCopy(t *testing.T) {
	claims := &Claims{Scopes: []string{"admin:*"}}

	scopes := []string{"admin:read", "write"}
	mw := GinRequireAnyScopeWildcard(scopes)

	// Mutate original slice after middleware creation
	scopes[0] = "MUTATED"

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(mw)

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called, "middleware should use defensively-copied scopes")
}

func TestGinRequireAnyScopeWildcard_WWWAuthenticateHeader_403(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireAnyScopeWildcard([]string{"admin", "write"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="insufficient_scope"`)
	assert.Contains(t, wwwAuth, "admin, write")
}

func TestGinRequireScopeWildcard_CustomErrorHandler(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	customCalled := false
	var receivedErrCode, receivedErrDesc string
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireScopeWildcard("admin", WithGinScopeErrorHandler(func(c *gin.Context, statusCode int, errCode, errDesc string) {
		customCalled = true
		receivedErrCode = errCode
		receivedErrDesc = errDesc
		c.AbortWithStatusJSON(statusCode, gin.H{"custom": errCode + ": " + errDesc})
	})))

	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, customCalled)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "insufficient_scope", receivedErrCode)
	assert.Equal(t, "Required scope: admin", receivedErrDesc)
}

func TestGinRequireAnyScopeWildcard_CustomErrorHandler(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}

	customCalled := false
	var receivedErrCode, receivedErrDesc string
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(GinRequireAnyScopeWildcard([]string{"admin", "write"}, WithGinScopeErrorHandler(func(c *gin.Context, statusCode int, errCode, errDesc string) {
		customCalled = true
		receivedErrCode = errCode
		receivedErrDesc = errDesc
		c.AbortWithStatusJSON(statusCode, gin.H{"custom": errCode})
	})))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, customCalled)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, "insufficient_scope", receivedErrCode)
	assert.Equal(t, "Required one of scopes: admin, write", receivedErrDesc)
}

func TestGinRequireScopeWildcard_CustomClaimsKey(t *testing.T) {
	claims := &Claims{Scopes: []string{"bgc:contractors:*"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("custom_key", claims)
		c.Next()
	})
	router.Use(GinRequireScopeWildcard("bgc:contractors:read", WithGinScopeClaimsKey("custom_key")))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinRequireAnyScopeWildcard_CustomClaimsKey(t *testing.T) {
	claims := &Claims{Scopes: []string{"bgc:*"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("custom_key", claims)
		c.Next()
	})
	router.Use(GinRequireAnyScopeWildcard([]string{"bgc:contractors:read"}, WithGinScopeClaimsKey("custom_key")))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Wildcard Middleware Edge Case Tests ---

func TestGinRequireScopeWildcard_WrongTypeInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", "not-a-claims-pointer")
		c.Next()
	})
	router.Use(GinRequireScopeWildcard("read"))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
	assert.Equal(t, "Missing authentication context", resp.ErrorDescription)
}

func TestGinRequireScopeWildcard_NilClaimsInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", (*Claims)(nil))
		c.Next()
	})
	router.Use(GinRequireScopeWildcard("read"))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestGinRequireAnyScopeWildcard_WrongTypeInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", 42)
		c.Next()
	})
	router.Use(GinRequireAnyScopeWildcard([]string{"read"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestGinRequireAnyScopeWildcard_NilClaimsInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", (*Claims)(nil))
		c.Next()
	})
	router.Use(GinRequireAnyScopeWildcard([]string{"read"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

// --- Helper / Edge Case Tests ---

func TestGinDefaultErrorHandler_EmptyDescription(t *testing.T) {
	c, w := newGinTestContext()
	ginDefaultErrorHandler(c, http.StatusUnauthorized, "invalid_request", "")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error_description=""`)
}

func TestGinBearerAuth_POSTMethodRejected(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := GinBearerAuth(validator)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/test", nil)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseGinErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
}
