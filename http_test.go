package authclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// helper to parse error response body from httptest.ResponseRecorder.
func parseHTTPErrorResponse(t *testing.T, rec *httptest.ResponseRecorder) errorResponse {
	t.Helper()
	var resp errorResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

// --- HTTPBearerAuth Tests ---

func TestHTTPBearerAuth_MissingAuthHeader(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Missing authorization header", resp.ErrorDescription)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestHTTPBearerAuth_InvalidFormat(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Invalid authorization header format", resp.ErrorDescription)
}

func TestHTTPBearerAuth_EmptyToken(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer ")
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Empty bearer token", resp.ErrorDescription)
}

func TestHTTPBearerAuth_OversizedToken(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := HTTPBearerAuth(validator)

	bigToken := strings.Repeat("a", MaxBearerTokenLength+1)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+bigToken)
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Bearer token exceeds maximum length", resp.ErrorDescription)
}

func TestHTTPBearerAuth_MaxLengthTokenAccepted(t *testing.T) {
	claims := &Claims{ClientID: "max-len"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}
	mw := HTTPBearerAuth(validator)

	exactToken := strings.Repeat("a", MaxBearerTokenLength)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+exactToken)
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHTTPBearerAuth_ValidToken(t *testing.T) {
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
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token-123")
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		claims, ok := ClaimsFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, expectedClaims, claims)
	})).ServeHTTP(rec, req)

	assert.True(t, called)
}

func TestHTTPBearerAuth_ClaimsRetrievableViaContext(t *testing.T) {
	expectedClaims := &Claims{
		ClientID: "ctx-client",
		Scopes:   []string{"admin"},
	}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return expectedClaims, nil
		},
	}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		assert.True(t, ok)
		assert.Same(t, expectedClaims, claims)
	})).ServeHTTP(rec, req)
}

func TestHTTPBearerAuth_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenInvalid
		},
	}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "invalid_token", resp.Error)
	assert.Equal(t, "Token validation failed", resp.ErrorDescription)
}

func TestHTTPBearerAuth_ValidatorReturnsNilClaimsNilError(t *testing.T) {
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, nil
		},
	}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer some-token")
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestHTTPBearerAuth_CustomErrorHandler(t *testing.T) {
	validator := &mockTokenValidator{}
	customCalled := false
	mw := HTTPBearerAuth(validator, WithHTTPErrorHandler(func(w http.ResponseWriter, _ *http.Request, statusCode int, errCode, errDesc string) {
		customCalled = true
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(errCode + ": " + errDesc))
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	assert.True(t, customCalled)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "invalid_request: Missing authorization header", rec.Body.String())
}

func TestHTTPBearerAuth_NilErrorHandlerUsesDefault(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := HTTPBearerAuth(validator, WithHTTPErrorHandler(nil))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestHTTPBearerAuth_NilValidatorPanics(t *testing.T) {
	assert.PanicsWithValue(t, "HTTPBearerAuth: validator cannot be nil", func() {
		HTTPBearerAuth(nil)
	})
}

func TestHTTPBearerAuth_ContentTypeJSON(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

func TestHTTPBearerAuth_WWWAuthenticateHeader_401(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "Bearer")
	assert.Contains(t, wwwAuth, `realm="api"`)
	assert.Contains(t, wwwAuth, `error="invalid_request"`)
}

func TestHTTPBearerAuth_WWWAuthenticateHeader_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenInvalid
		},
	}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="invalid_token"`)
}

func TestHTTPBearerAuth_ErrorResponseJSON(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	assert.Len(t, raw, 2)
	assert.Contains(t, raw, "error")
	assert.Contains(t, raw, "error_description")
	assert.Equal(t, "invalid_request", raw["error"])
	assert.IsType(t, "", raw["error_description"])
}

func TestHTTPBearerAuth_LowercaseBearer(t *testing.T) {
	claims := &Claims{ClientID: "case-test"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "bearer my-token")
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.True(t, called, "lowercase 'bearer' should be accepted per RFC 6750/2617")
}

func TestHTTPBearerAuth_UppercaseBearer(t *testing.T) {
	claims := &Claims{ClientID: "case-test"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "BEARER my-token")
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.True(t, called, "uppercase 'BEARER' should be accepted per RFC 6750/2617")
}

func TestHTTPBearerAuth_MixedCaseBearer(t *testing.T) {
	claims := &Claims{ClientID: "mixed-case"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "BeArEr my-token")
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.True(t, called, "mixed case 'BeArEr' should be accepted per RFC 6750/2617")
}

func TestHTTPBearerAuth_TokenWhitespaceTrimmed(t *testing.T) {
	claims := &Claims{ClientID: "trim-test"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token, "token should be trimmed of whitespace")
			return claims, nil
		},
	}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer  my-token ")
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.True(t, called)
}

func TestHTTPBearerAuth_WhitespaceOnlyTokenEmpty(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer    ")
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Empty bearer token", resp.ErrorDescription)
}

func TestHTTPBearerAuth_ShortAuthHeader(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bear")
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Invalid authorization header format", resp.ErrorDescription)
}

func TestHTTPBearerAuth_ValidatorReceivesRequestContext(t *testing.T) {
	type testCtxKey struct{}
	var receivedCtx context.Context
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(ctx context.Context, _ string) (*Claims, error) {
			receivedCtx = ctx
			return &Claims{ClientID: "ctx-test"}, nil
		},
	}
	mw := HTTPBearerAuth(validator)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(context.WithValue(req.Context(), testCtxKey{}, "marker"))
	req.Header.Set("Authorization", "Bearer token")
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	require.NotNil(t, receivedCtx, "validator should receive request context")
	assert.Equal(t, "marker", receivedCtx.Value(testCtxKey{}), "validator should receive the exact request context")
}

// --- HTTPRequireScope Tests ---

func TestHTTPRequireScope_ScopePresent(t *testing.T) {
	claims := &Claims{Scopes: []string{"read", "write"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	called := false
	HTTPRequireScope("read")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.True(t, called)
}

func TestHTTPRequireScope_ScopeMissing(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	called := false
	HTTPRequireScope("admin")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required scope: admin", resp.ErrorDescription)
}

func TestHTTPRequireScope_NoClaims(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	called := false
	HTTPRequireScope("read")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "invalid_token", resp.Error)
	assert.Equal(t, "Missing authentication context", resp.ErrorDescription)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="invalid_token"`)
}

func TestHTTPRequireScope_EmptyScopePanics(t *testing.T) {
	assert.PanicsWithValue(t, "HTTPRequireScope: scope cannot be empty", func() {
		HTTPRequireScope("")
	})
}

func TestHTTPRequireScope_WWWAuthenticateHeader_403(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	HTTPRequireScope("admin")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="insufficient_scope"`)
}

func TestHTTPRequireScope_SpecialCharScope(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	HTTPRequireScope("audit:read/write")(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, "audit:read/write")
}

func TestHTTPRequireScope_QuotedStringEscaping(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	// Scope with quote and backslash to exercise escapeQuotedString
	HTTPRequireScope(`scope"with\special`)(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `scope\"with\\special`)
}

func TestHTTPRequireScope_CustomErrorHandler(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	customCalled := false
	scope := HTTPRequireScope("admin", WithHTTPScopeErrorHandler(func(w http.ResponseWriter, _ *http.Request, statusCode int, errCode, errDesc string) {
		customCalled = true
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(errCode + ": " + errDesc))
	}))

	scope(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	assert.True(t, customCalled)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "insufficient_scope: Required scope: admin", rec.Body.String())
}

func TestHTTPScopeErrorHandler_NilUsesDefault(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	scope := HTTPRequireScope("admin", WithHTTPScopeErrorHandler(nil))
	scope(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "insufficient_scope", resp.Error)
}

// --- HTTPRequireAnyScope Tests ---

func TestHTTPRequireAnyScope_AnyMatch(t *testing.T) {
	claims := &Claims{Scopes: []string{"read", "write"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	called := false
	HTTPRequireAnyScope([]string{"admin", "write"})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.True(t, called)
}

func TestHTTPRequireAnyScope_NoneMatch(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	called := false
	HTTPRequireAnyScope([]string{"admin", "write"})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required one of scopes: admin, write", resp.ErrorDescription)
}

func TestHTTPRequireAnyScope_NoClaims(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	called := false
	HTTPRequireAnyScope([]string{"read"})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestHTTPRequireAnyScope_EmptyScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "HTTPRequireAnyScope: scopes cannot be empty", func() {
		HTTPRequireAnyScope([]string{})
	})
}

func TestHTTPRequireAnyScope_NilScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "HTTPRequireAnyScope: scopes cannot be empty", func() {
		HTTPRequireAnyScope(nil)
	})
}

func TestHTTPRequireAnyScope_DefensiveScopesCopy(t *testing.T) {
	claims := &Claims{Scopes: []string{"admin"}}
	ctx := ContextWithClaims(context.Background(), claims)

	scopes := []string{"admin", "write"}
	mw := HTTPRequireAnyScope(scopes)

	// Mutate original slice element after middleware creation.
	// copy() creates an independent backing array, so element mutation
	// and append on the original cannot affect the middleware's copy.
	scopes[0] = "MUTATED"

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.True(t, called, "middleware should use defensively-copied scopes, not mutated original")
}

func TestHTTPRequireAnyScope_CustomErrorHandler(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	customCalled := false
	scope := HTTPRequireAnyScope([]string{"admin", "write"}, WithHTTPScopeErrorHandler(func(w http.ResponseWriter, _ *http.Request, statusCode int, errCode, errDesc string) {
		customCalled = true
		w.WriteHeader(statusCode)
		_, _ = w.Write([]byte(errCode + ": " + errDesc))
	}))

	scope(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	assert.True(t, customCalled)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Equal(t, "insufficient_scope: Required one of scopes: admin, write", rec.Body.String())
}

func TestHTTPRequireAnyScope_WWWAuthenticateHeader_403(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	HTTPRequireAnyScope([]string{"admin", "write"})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})).ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	wwwAuth := rec.Header().Get("WWW-Authenticate")
	assert.Contains(t, wwwAuth, `error="insufficient_scope"`)
	assert.Contains(t, wwwAuth, "admin, write")
}

// --- HTTPNoopAuth Tests ---

func TestHTTPNoopAuth_InjectsClaims(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "noop-client",
		Scopes:   []string{"read", "write"},
	}
	mw := HTTPNoopAuth(defaultClaims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, "noop-client", claims.ClientID)
		assert.Equal(t, []string{"read", "write"}, claims.Scopes)
	})).ServeHTTP(rec, req)
}

func TestHTTPNoopAuth_DeepCopy(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "original",
		Scopes:   []string{"read"},
	}
	mw := HTTPNoopAuth(defaultClaims)

	// First request: mutate the returned claims
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		claims, _ := ClaimsFromContext(r.Context())
		claims.Scopes = append(claims.Scopes, "mutated")
		claims.ClientID = "mutated"
	})).ServeHTTP(rec1, req1)

	// Second request: should get clean copy, not mutated
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		claims, _ := ClaimsFromContext(r.Context())
		assert.Equal(t, "original", claims.ClientID)
		assert.Equal(t, []string{"read"}, claims.Scopes)
	})).ServeHTTP(rec2, req2)

	// Original unchanged
	assert.Equal(t, "original", defaultClaims.ClientID)
	assert.Equal(t, []string{"read"}, defaultClaims.Scopes)
}

func TestHTTPNoopAuth_NilDefaultClaimsPanics(t *testing.T) {
	assert.PanicsWithValue(t, "HTTPNoopAuth: defaultClaims cannot be nil", func() {
		HTTPNoopAuth(nil)
	})
}

func TestHTTPNoopAuth_ConcurrentDeepCopy(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "concurrent-client",
		Scopes:   []string{"read", "write"},
	}
	mw := HTTPNoopAuth(defaultClaims)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				claims, _ := ClaimsFromContext(r.Context())
				claims.Scopes = append(claims.Scopes, "mutated")
				claims.ClientID = "mutated"
			})).ServeHTTP(rec, req)
		}()
	}

	wg.Wait()

	assert.Equal(t, "concurrent-client", defaultClaims.ClientID)
	assert.Equal(t, []string{"read", "write"}, defaultClaims.Scopes)
}

func TestHTTPNoopAuth_DeepCopyAudience(t *testing.T) {
	defaultClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"aud1", "aud2"},
		},
		ClientID: "aud-client",
	}
	mw := HTTPNoopAuth(defaultClaims)

	// First request: mutate audience
	rec1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		claims, _ := ClaimsFromContext(r.Context())
		claims.Audience = append(claims.Audience, "mutated")
	})).ServeHTTP(rec1, req1)

	// Second request: should get clean copy
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		claims, _ := ClaimsFromContext(r.Context())
		assert.Equal(t, jwt.ClaimStrings{"aud1", "aud2"}, claims.Audience)
	})).ServeHTTP(rec2, req2)

	assert.Equal(t, jwt.ClaimStrings{"aud1", "aud2"}, defaultClaims.Audience)
}

func TestHTTPNoopAuth_DeepCopyNumericDates(t *testing.T) {
	expTime := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nbfTime := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)
	iatTime := time.Date(2026, 1, 1, 11, 0, 0, 0, time.UTC)
	defaultClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expTime),
			NotBefore: jwt.NewNumericDate(nbfTime),
			IssuedAt:  jwt.NewNumericDate(iatTime),
		},
		ClientID: "date-client",
	}
	mw := HTTPNoopAuth(defaultClaims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		claims, _ := ClaimsFromContext(r.Context())

		require.NotNil(t, claims.ExpiresAt)
		require.NotNil(t, claims.NotBefore)
		require.NotNil(t, claims.IssuedAt)

		assert.NotSame(t, defaultClaims.ExpiresAt, claims.ExpiresAt)
		assert.NotSame(t, defaultClaims.NotBefore, claims.NotBefore)
		assert.NotSame(t, defaultClaims.IssuedAt, claims.IssuedAt)

		assert.Equal(t, expTime.Unix(), claims.ExpiresAt.Unix())
		assert.Equal(t, nbfTime.Unix(), claims.NotBefore.Unix())
		assert.Equal(t, iatTime.Unix(), claims.IssuedAt.Unix())

		claims.ExpiresAt = jwt.NewNumericDate(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	})).ServeHTTP(rec, req)

	assert.Equal(t, expTime.Unix(), defaultClaims.ExpiresAt.Unix())
}

// --- HTTPNoopScope Tests ---

func TestHTTPNoopScope_PassesThrough(t *testing.T) {
	mw := HTTPNoopScope()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	called := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.True(t, called)
}

func TestHTTPNoopScope_ReturnsExactHandler(t *testing.T) {
	mw := HTTPNoopScope()
	called := false
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })

	wrapped := mw(handler)
	require.NotNil(t, wrapped)

	// Verify identity: NoopScope returns the exact same handler, not a wrapper.
	// http.HandlerFunc is a function type (not a pointer), so we compare via formatting.
	assert.Equal(t, fmt.Sprintf("%p", handler), fmt.Sprintf("%p", wrapped), "NoopScope should return the exact same handler object")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	wrapped.ServeHTTP(rec, req)
	assert.True(t, called)
}

// --- Middleware Chain Tests ---

func TestHTTPMiddlewareChain_BearerAuth_RequireScope(t *testing.T) {
	claims := &Claims{ClientID: "chain-client", Scopes: []string{"read", "write"}}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}

	auth := HTTPBearerAuth(validator)
	scope := HTTPRequireScope("read")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	handlerCalled := false
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { handlerCalled = true })

	auth(scope(handler)).ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHTTPMiddlewareChain_BearerAuth_RequireScope_Denied(t *testing.T) {
	claims := &Claims{ClientID: "chain-client", Scopes: []string{"read"}}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}

	auth := HTTPBearerAuth(validator)
	scope := HTTPRequireScope("admin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	handlerCalled := false
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { handlerCalled = true })

	auth(scope(handler)).ServeHTTP(rec, req)

	assert.False(t, handlerCalled)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestHTTPMiddlewareChain_BearerAuth_RequireAnyScope(t *testing.T) {
	claims := &Claims{ClientID: "chain-client", Scopes: []string{"read", "write"}}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}

	auth := HTTPBearerAuth(validator)
	scope := HTTPRequireAnyScope([]string{"admin", "write"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	handlerCalled := false
	handler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { handlerCalled = true })

	auth(scope(handler)).ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHTTPMiddlewareChain_NoopAuth_RequireScope(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "noop-chain",
		Scopes:   []string{"read", "admin"},
	}

	auth := HTTPNoopAuth(defaultClaims)
	scope := HTTPRequireScope("admin")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handlerCalled := false
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		claims, ok := ClaimsFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, "noop-chain", claims.ClientID)
	})

	auth(scope(handler)).ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHTTPMiddlewareChain_NoopAuth_RequireAnyScope(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "noop-any-chain",
		Scopes:   []string{"read", "write"},
	}

	auth := HTTPNoopAuth(defaultClaims)
	scope := HTTPRequireAnyScope([]string{"admin", "write"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handlerCalled := false
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		claims, ok := ClaimsFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, "noop-any-chain", claims.ClientID)
	})

	auth(scope(handler)).ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHTTPMiddlewareChain_NoopAuth_NoopScope(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "noop-full",
		Scopes:   []string{"dev"},
	}

	auth := HTTPNoopAuth(defaultClaims)
	scope := HTTPNoopScope()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	handlerCalled := false
	handler := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		claims, ok := ClaimsFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, "noop-full", claims.ClientID)
	})

	auth(scope(handler)).ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHTTPNoopAuth_IgnoresAuthorizationHeader(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "noop-ignore",
		Scopes:   []string{"read"},
	}
	mw := HTTPNoopAuth(defaultClaims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-should-be-ignored")

	handlerCalled := false
	mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		claims, ok := ClaimsFromContext(r.Context())
		assert.True(t, ok)
		assert.Equal(t, "noop-ignore", claims.ClientID)
	})).ServeHTTP(rec, req)

	assert.True(t, handlerCalled)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestHTTPRequireAnyScope_SingleScope(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req = req.WithContext(ctx)

	called := false
	HTTPRequireAnyScope([]string{"admin"})(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) { called = true })).ServeHTTP(rec, req)

	assert.False(t, called)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	resp := parseHTTPErrorResponse(t, rec)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required one of scopes: admin", resp.ErrorDescription)
}
