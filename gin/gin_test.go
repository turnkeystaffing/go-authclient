package authgin

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

	"github.com/turnkeystaffing/go-authclient"
)

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	os.Exit(m.Run())
}

// mockValidator implements authclient.TokenValidator with a func field for test control.
type mockValidator struct {
	ValidateTokenFunc func(ctx context.Context, token string) (*authclient.Claims, error)
}

func (m *mockValidator) ValidateToken(ctx context.Context, token string) (*authclient.Claims, error) {
	return m.ValidateTokenFunc(ctx, token)
}

// parseErrorResponse parses the error response body from httptest.ResponseRecorder.
func parseErrorResponse(t *testing.T, rec *httptest.ResponseRecorder) errorResponse {
	t.Helper()
	var resp errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

// newTestContext creates a gin test context with a fresh recorder and request.
func newTestContext() (*gin.Context, *httptest.ResponseRecorder) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/test", nil)
	return c, w
}

// --- BearerAuth Tests ---

func TestBearerAuth_MissingAuthHeader(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator)

	c, w := newTestContext()
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Missing authorization header", resp.ErrorDescription)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

func TestBearerAuth_InvalidFormat(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator)

	c, w := newTestContext()
	c.Request.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Invalid authorization header format", resp.ErrorDescription)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_request"`)
}

func TestBearerAuth_EmptyToken(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator)

	c, w := newTestContext()
	c.Request.Header.Set("Authorization", "Bearer ")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Empty bearer token", resp.ErrorDescription)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_request"`)
}

func TestBearerAuth_OversizedToken(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator)

	bigToken := strings.Repeat("a", authclient.MaxBearerTokenLength+1)
	c, w := newTestContext()
	c.Request.Header.Set("Authorization", "Bearer "+bigToken)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Bearer token exceeds maximum length", resp.ErrorDescription)
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_request"`)
}

func TestBearerAuth_ValidToken_ClaimsInGinAndRequestContext(t *testing.T) {
	expectedClaims := &authclient.Claims{
		ClientID: "test-client-uuid",
		Scopes:   []string{"read", "write"},
	}
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*authclient.Claims, error) {
			assert.Equal(t, "valid-token-123", token)
			return expectedClaims, nil
		},
	}
	mw := BearerAuth(validator)

	c, w := newTestContext()
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
		ginClaims := val.(*authclient.Claims)
		assert.Equal(t, expectedClaims, ginClaims)

		// Verify request context retrieval
		ctxClaims, ok := authclient.ClaimsFromContext(c.Request.Context())
		assert.True(t, ok)
		assert.Same(t, ginClaims, ctxClaims, "gin context and request context should hold same pointer")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token-123")
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBearerAuth_InvalidToken(t *testing.T) {
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*authclient.Claims, error) {
			return nil, authclient.ErrTokenInvalid
		},
	}
	mw := BearerAuth(validator)

	c, w := newTestContext()
	c.Request.Header.Set("Authorization", "Bearer bad-token")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
	assert.Equal(t, "Token validation failed", resp.ErrorDescription)
}

func TestBearerAuth_ValidatorReturnsNilClaimsNilError(t *testing.T) {
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*authclient.Claims, error) {
			return nil, nil
		},
	}
	mw := BearerAuth(validator)

	c, w := newTestContext()
	c.Request.Header.Set("Authorization", "Bearer some-token")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestBearerAuth_CustomErrorHandler(t *testing.T) {
	validator := &mockValidator{}
	customCalled := false
	var receivedCode int
	var receivedErrCode, receivedErrDesc string
	mw := BearerAuth(validator, WithErrorHandler(func(c *gin.Context, statusCode int, errCode, errDesc string) {
		customCalled = true
		receivedCode = statusCode
		receivedErrCode = errCode
		receivedErrDesc = errDesc
		c.AbortWithStatusJSON(statusCode, gin.H{"custom": errCode + ": " + errDesc})
	}))

	c, w := newTestContext()
	mw(c)

	assert.True(t, customCalled)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, http.StatusUnauthorized, receivedCode)
	assert.Equal(t, "invalid_request", receivedErrCode)
	assert.Equal(t, "Missing authorization header", receivedErrDesc)
}

func TestBearerAuth_CustomClaimsKey(t *testing.T) {
	claims := &authclient.Claims{ClientID: "custom-key"}
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*authclient.Claims, error) {
			return claims, nil
		},
	}
	mw := BearerAuth(validator, WithClaimsKey("my_claims"))

	router := gin.New()
	router.Use(mw)

	handlerCalled := false
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		val, exists := c.Get("my_claims")
		assert.True(t, exists)
		ginClaims := val.(*authclient.Claims)
		assert.Equal(t, claims, ginClaims)

		// F2 fix: verify request context also has claims (context bridge)
		ctxClaims, ok := authclient.ClaimsFromContext(c.Request.Context())
		assert.True(t, ok, "ClaimsFromContext must find claims even with custom gin key")
		assert.Same(t, ginClaims, ctxClaims, "gin context and request context must hold same pointer")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer token")
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
}

func TestBearerAuth_NilValidatorPanics(t *testing.T) {
	assert.PanicsWithValue(t, "BearerAuth: validator cannot be nil", func() {
		BearerAuth(nil)
	})
}

func TestBearerAuth_EmptyClaimsKeyPanics(t *testing.T) {
	assert.PanicsWithValue(t, "WithClaimsKey: key cannot be empty", func() {
		WithClaimsKey("")
	})
}

func TestBearerAuth_NilErrorHandlerUsesDefault(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator, WithErrorHandler(nil))

	c, w := newTestContext()
	mw(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

func TestBearerAuth_ContentTypeJSON(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator)

	c, w := newTestContext()
	mw(c)

	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

func TestBearerAuth_WWWAuthenticateHeader_401(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator)

	c, w := newTestContext()
	mw(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")
	assert.Contains(t, wwwAuth, `realm="api"`)
	assert.Contains(t, wwwAuth, `error="invalid_request"`)
}

func TestBearerAuth_ErrorResponseJSON(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator)

	c, w := newTestContext()
	mw(c)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	assert.Len(t, raw, 2)
	assert.Contains(t, raw, "error")
	assert.Contains(t, raw, "error_description")
	assert.Equal(t, "invalid_request", raw["error"])
}

func TestBearerAuth_LowercaseBearer(t *testing.T) {
	claims := &authclient.Claims{ClientID: "case-test"}
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*authclient.Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(BearerAuth(validator))
	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "bearer my-token")
	router.ServeHTTP(w, req)

	assert.True(t, called, "lowercase 'bearer' should be accepted per RFC 6750/2617")
}

func TestBearerAuth_UppercaseBearer(t *testing.T) {
	claims := &authclient.Claims{ClientID: "case-test"}
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*authclient.Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(BearerAuth(validator))
	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "BEARER my-token")
	router.ServeHTTP(w, req)

	assert.True(t, called, "uppercase 'BEARER' should be accepted per RFC 6750/2617")
}

func TestBearerAuth_MixedCaseBearer(t *testing.T) {
	claims := &authclient.Claims{ClientID: "mixed-case"}
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*authclient.Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(BearerAuth(validator))
	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "BeArEr my-token")
	router.ServeHTTP(w, req)

	assert.True(t, called, "mixed case 'BeArEr' should be accepted per RFC 6750/2617")
}

func TestBearerAuth_TokenWhitespaceTrimmed(t *testing.T) {
	claims := &authclient.Claims{ClientID: "trim-test"}
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*authclient.Claims, error) {
			assert.Equal(t, "my-token", token, "token should be trimmed of whitespace")
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(BearerAuth(validator))
	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer  my-token ")
	router.ServeHTTP(w, req)

	assert.True(t, called)
}

func TestBearerAuth_ShortAuthHeader(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator)

	c, w := newTestContext()
	c.Request.Header.Set("Authorization", "Bear")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Invalid authorization header format", resp.ErrorDescription)
}

func TestBearerAuth_ValidatorReceivesRequestContext(t *testing.T) {
	type testCtxKey struct{}
	var receivedCtx context.Context
	validator := &mockValidator{
		ValidateTokenFunc: func(ctx context.Context, _ string) (*authclient.Claims, error) {
			receivedCtx = ctx
			return &authclient.Claims{ClientID: "ctx-test"}, nil
		},
	}

	router := gin.New()
	router.Use(BearerAuth(validator))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req = req.WithContext(context.WithValue(req.Context(), testCtxKey{}, "marker"))
	req.Header.Set("Authorization", "Bearer token")
	router.ServeHTTP(w, req)

	require.NotNil(t, receivedCtx, "validator should receive request context")
	assert.Equal(t, "marker", receivedCtx.Value(testCtxKey{}))
}

func TestBearerAuth_IsAbortedAfterError(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator)

	c, _ := newTestContext()
	mw(c)

	assert.True(t, c.IsAborted(), "c.IsAborted() must be true after error response")
}

func TestBearerAuth_CustomErrorHandlerWithoutAbort_ChainStops(t *testing.T) {
	validator := &mockValidator{}
	// Custom error handler that does NOT call c.Abort()
	mw := BearerAuth(validator, WithErrorHandler(func(c *gin.Context, statusCode int, errCode, errDesc string) {
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

// --- RequireScope Tests ---

func TestRequireScope_ScopePresent(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"read", "write"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(RequireScope("read"))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequireScope_ScopeMissing(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(RequireScope("admin"))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusForbidden, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required scope: admin", resp.ErrorDescription)
}

func TestRequireScope_NoClaims(t *testing.T) {
	router := gin.New()
	router.Use(RequireScope("read"))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
	assert.Equal(t, "Missing authentication context", resp.ErrorDescription)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="invalid_token"`)
}

func TestRequireScope_EmptyScopePanics(t *testing.T) {
	assert.PanicsWithValue(t, "RequireScope: scope cannot be empty", func() {
		RequireScope("")
	})
}

func TestRequireScope_SpecialCharScope(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(RequireScope("audit:read/write"))

	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "audit:read/write")
}

func TestRequireScope_CustomClaimsKey(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("my_claims", claims)
		c.Next()
	})
	router.Use(RequireScope("read", WithScopeClaimsKey("my_claims")))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
}

func TestRequireScope_CustomErrorHandler(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"read"}}

	customCalled := false
	var receivedErrCode, receivedErrDesc string
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(RequireScope("admin", WithScopeErrorHandler(func(c *gin.Context, statusCode int, errCode, errDesc string) {
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

func TestRequireScope_WWWAuthenticateHeader_403(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(RequireScope("admin"))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="insufficient_scope"`)
}

// --- RequireAnyScope Tests ---

func TestRequireAnyScope_AnyMatch(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"read", "write"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(RequireAnyScope([]string{"admin", "write"}))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
}

func TestRequireAnyScope_NoneMatch(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(RequireAnyScope([]string{"admin", "write"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required one of scopes: admin, write", resp.ErrorDescription)
}

func TestRequireAnyScope_NoClaims(t *testing.T) {
	router := gin.New()
	router.Use(RequireAnyScope([]string{"read"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestRequireAnyScope_EmptyScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "RequireAnyScope: scopes cannot be empty", func() {
		RequireAnyScope([]string{})
	})
}

func TestRequireAnyScope_NilScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "RequireAnyScope: scopes cannot be empty", func() {
		RequireAnyScope(nil)
	})
}

func TestRequireAnyScope_DefensiveScopesCopy(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"admin"}}

	scopes := []string{"admin", "write"}
	mw := RequireAnyScope(scopes)

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

func TestRequireAnyScope_CustomErrorHandler(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"read"}}

	customCalled := false
	var receivedErrCode, receivedErrDesc string
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(RequireAnyScope([]string{"admin", "write"}, WithScopeErrorHandler(func(c *gin.Context, statusCode int, errCode, errDesc string) {
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

func TestRequireAnyScope_WWWAuthenticateHeader_403(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(RequireAnyScope([]string{"admin", "write"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="insufficient_scope"`)
	assert.Contains(t, wwwAuth, "admin, write")
}

func TestScopeErrorHandler_NilUsesDefault(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"read"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", claims)
		c.Next()
	})
	router.Use(RequireScope("admin", WithScopeErrorHandler(nil)))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "insufficient_scope", resp.Error)
}

func TestScopeClaimsKey_EmptyPanics(t *testing.T) {
	assert.PanicsWithValue(t, "WithScopeClaimsKey: key cannot be empty", func() {
		WithScopeClaimsKey("")
	})
}

// --- NoopAuth Tests ---

func TestNoopAuth_InjectsClaims(t *testing.T) {
	defaultClaims := &authclient.Claims{
		ClientID: "noop-client",
		Scopes:   []string{"read", "write"},
	}

	router := gin.New()
	router.Use(NoopAuth(defaultClaims))

	router.GET("/test", func(c *gin.Context) {
		// gin context path
		val, exists := c.Get("auth_claims")
		assert.True(t, exists)
		ginClaims := val.(*authclient.Claims)
		assert.Equal(t, "noop-client", ginClaims.ClientID)
		assert.Equal(t, []string{"read", "write"}, ginClaims.Scopes)

		// request context path
		ctxClaims, ok := authclient.ClaimsFromContext(c.Request.Context())
		assert.True(t, ok)
		assert.Same(t, ginClaims, ctxClaims)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)
}

func TestNoopAuth_DeepCopy(t *testing.T) {
	defaultClaims := &authclient.Claims{
		ClientID: "original",
		Scopes:   []string{"read"},
	}
	noopMw := NoopAuth(defaultClaims)

	router := gin.New()
	router.Use(noopMw)

	requestNum := 0
	router.GET("/test", func(c *gin.Context) {
		requestNum++
		val, _ := c.Get("auth_claims")
		claims := val.(*authclient.Claims)
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

func TestNoopAuth_NilDefaultClaimsPanics(t *testing.T) {
	assert.PanicsWithValue(t, "NoopAuth: defaultClaims cannot be nil", func() {
		NoopAuth(nil)
	})
}

func TestNoopAuth_ConcurrentDeepCopy(t *testing.T) {
	defaultClaims := &authclient.Claims{
		ClientID: "concurrent-client",
		Scopes:   []string{"read", "write"},
	}

	// Single router — concurrent requests hit the same handler chain.
	router := gin.New()
	router.Use(NoopAuth(defaultClaims))
	router.GET("/test", func(c *gin.Context) {
		val, _ := c.Get("auth_claims")
		claims := val.(*authclient.Claims)
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

func TestNoopAuth_DeepCopyNumericDates(t *testing.T) {
	expTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nbfTime := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)
	iatTime := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)
	defaultClaims := &authclient.Claims{
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
	router.Use(NoopAuth(defaultClaims))
	router.GET("/test", func(c *gin.Context) {
		val, _ := c.Get("auth_claims")
		claims := val.(*authclient.Claims)

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

// --- NoopScope Tests ---

func TestNoopScope_PassesThrough(t *testing.T) {
	router := gin.New()
	router.Use(NoopScope())

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
}

// --- Middleware Chain Tests ---

func TestMiddlewareChain_BearerAuth_RequireScope(t *testing.T) {
	claims := &authclient.Claims{ClientID: "chain-client", Scopes: []string{"read", "write"}}
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*authclient.Claims, error) {
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(BearerAuth(validator))
	router.Use(RequireScope("read"))

	handlerCalled := false
	router.GET("/test", func(_ *gin.Context) { handlerCalled = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddlewareChain_BearerAuth_RequireScope_Denied(t *testing.T) {
	claims := &authclient.Claims{ClientID: "chain-client", Scopes: []string{"read"}}
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*authclient.Claims, error) {
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(BearerAuth(validator))
	router.Use(RequireScope("admin"))

	handlerCalled := false
	router.GET("/test", func(_ *gin.Context) { handlerCalled = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.False(t, handlerCalled)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestMiddlewareChain_BearerAuth_RequireAnyScope(t *testing.T) {
	claims := &authclient.Claims{ClientID: "chain-client", Scopes: []string{"read", "write"}}
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*authclient.Claims, error) {
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(BearerAuth(validator))
	router.Use(RequireAnyScope([]string{"admin", "write"}))

	handlerCalled := false
	router.GET("/test", func(_ *gin.Context) { handlerCalled = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddlewareChain_NoopAuth_RequireScope(t *testing.T) {
	defaultClaims := &authclient.Claims{
		ClientID: "noop-chain",
		Scopes:   []string{"read", "admin"},
	}

	router := gin.New()
	router.Use(NoopAuth(defaultClaims))
	router.Use(RequireScope("admin"))

	handlerCalled := false
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		ctxClaims, ok := authclient.ClaimsFromContext(c.Request.Context())
		assert.True(t, ok)
		assert.Equal(t, "noop-chain", ctxClaims.ClientID)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMiddlewareChain_NoopAuth_NoopScope(t *testing.T) {
	defaultClaims := &authclient.Claims{
		ClientID: "noop-full",
		Scopes:   []string{"dev"},
	}

	router := gin.New()
	router.Use(NoopAuth(defaultClaims))
	router.Use(NoopScope())

	handlerCalled := false
	router.GET("/test", func(c *gin.Context) {
		handlerCalled = true
		ctxClaims, ok := authclient.ClaimsFromContext(c.Request.Context())
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

func TestBearerAuth_MaxLengthTokenAccepted(t *testing.T) {
	exactToken := strings.Repeat("a", authclient.MaxBearerTokenLength)
	claims := &authclient.Claims{ClientID: "boundary-test"}
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*authclient.Claims, error) {
			assert.Len(t, token, authclient.MaxBearerTokenLength)
			return claims, nil
		},
	}

	router := gin.New()
	router.Use(BearerAuth(validator))
	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+exactToken)
	router.ServeHTTP(w, req)

	assert.True(t, called, "token at exact MaxBearerTokenLength should be accepted")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBearerAuth_WhitespaceOnlyTokenEmpty(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator)

	c, w := newTestContext()
	c.Request.Header.Set("Authorization", "Bearer    ")
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Empty bearer token", resp.ErrorDescription)
}

func TestBearerAuth_WWWAuthenticateHeader_InvalidToken(t *testing.T) {
	validator := &mockValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*authclient.Claims, error) {
			return nil, authclient.ErrTokenInvalid
		},
	}
	mw := BearerAuth(validator)

	c, w := newTestContext()
	c.Request.Header.Set("Authorization", "Bearer bad-token")
	mw(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="invalid_token"`)
	assert.Contains(t, wwwAuth, `error_description="Token validation failed"`)
}

func TestRequireScope_WrongTypeInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", "not-a-claims-pointer")
		c.Next()
	})
	router.Use(RequireScope("read"))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
	assert.Equal(t, "Missing authentication context", resp.ErrorDescription)
}

func TestRequireScope_NilClaimsInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", (*authclient.Claims)(nil))
		c.Next()
	})
	router.Use(RequireScope("read"))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestRequireAnyScope_WrongTypeInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", 42)
		c.Next()
	})
	router.Use(RequireAnyScope([]string{"read"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestRequireAnyScope_NilClaimsInContext(t *testing.T) {
	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("auth_claims", (*authclient.Claims)(nil))
		c.Next()
	})
	router.Use(RequireAnyScope([]string{"read"}))
	router.GET("/test", func(_ *gin.Context) {})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestRequireAnyScope_CustomClaimsKey(t *testing.T) {
	claims := &authclient.Claims{Scopes: []string{"admin"}}

	router := gin.New()
	router.Use(func(c *gin.Context) {
		c.Set("custom_key", claims)
		c.Next()
	})
	router.Use(RequireAnyScope([]string{"admin", "write"}, WithScopeClaimsKey("custom_key")))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestNoopAuth_DeepCopyAudience(t *testing.T) {
	defaultClaims := &authclient.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"aud1", "aud2"},
		},
		ClientID: "audience-test",
	}
	noopMw := NoopAuth(defaultClaims)

	router := gin.New()
	router.Use(noopMw)

	requestNum := 0
	router.GET("/test", func(c *gin.Context) {
		requestNum++
		val, _ := c.Get("auth_claims")
		claims := val.(*authclient.Claims)
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

func TestNoopAuth_ScopeKeyMismatch_Returns401(t *testing.T) {
	defaultClaims := &authclient.Claims{
		ClientID: "mismatch-test",
		Scopes:   []string{"read"},
	}

	router := gin.New()
	router.Use(NoopAuth(defaultClaims))
	// NoopAuth stores under "auth_claims", but scope looks under "custom_key"
	router.Use(RequireScope("read", WithScopeClaimsKey("custom_key")))

	called := false
	router.GET("/test", func(_ *gin.Context) { called = true })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.False(t, called, "handler must NOT execute when claims key mismatches")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_token", resp.Error)
}

// --- Helper / Edge Case Tests ---

func TestDefaultErrorHandler_EmptyDescription(t *testing.T) {
	c, w := newTestContext()
	defaultErrorHandler(c, http.StatusUnauthorized, "invalid_request", "")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	wwwAuth := w.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error_description=""`)
}

func TestBearerAuth_POSTMethodRejected(t *testing.T) {
	validator := &mockValidator{}
	mw := BearerAuth(validator)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/test", nil)
	mw(c)

	assert.True(t, c.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	resp := parseErrorResponse(t, w)
	assert.Equal(t, "invalid_request", resp.Error)
}

// --- escapeQuotedString Tests ---

func TestEscapeQuotedString(t *testing.T) {
	assert.Equal(t, "simple", escapeQuotedString("simple"))
	assert.Equal(t, `with\"quote`, escapeQuotedString(`with"quote`))
	assert.Equal(t, `with\\backslash`, escapeQuotedString(`with\backslash`))
	assert.Equal(t, `both\"and\\`, escapeQuotedString(`both"and\`))
	assert.Equal(t, "", escapeQuotedString(""))
}
