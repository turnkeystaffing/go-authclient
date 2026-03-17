package authclient

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
)

// helper to create a fasthttp.RequestCtx with an Authorization header.
func newRequestCtx(authHeader string) *fasthttp.RequestCtx {
	ctx := &fasthttp.RequestCtx{}
	if authHeader != "" {
		ctx.Request.Header.Set("Authorization", authHeader)
	}
	return ctx
}

// helper to parse error response body.
func parseErrorResponse(t *testing.T, ctx *fasthttp.RequestCtx) errorResponse {
	t.Helper()
	var resp errorResponse
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &resp))
	return resp
}

// --- BearerAuth Tests ---

func TestFastHTTPBearerAuth_MissingAuthHeader(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("")
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Missing authorization header", resp.ErrorDescription)
	assert.Equal(t, "application/json", string(ctx.Response.Header.ContentType()))
}

func TestFastHTTPBearerAuth_InvalidFormat(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("Basic dXNlcjpwYXNz")
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Invalid authorization header format", resp.ErrorDescription)
}

func TestFastHTTPBearerAuth_EmptyToken(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("Bearer ")
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Empty bearer token", resp.ErrorDescription)
}

func TestFastHTTPBearerAuth_ValidToken(t *testing.T) {
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
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("Bearer valid-token-123")
	called := false
	mw(func(c *fasthttp.RequestCtx) {
		called = true
		// Verify claims stored in UserValue
		claims := c.UserValue(DefaultClaimsKey).(*Claims)
		assert.Equal(t, expectedClaims, claims)
		// Verify client_id stored as string
		clientUUID := c.UserValue(DefaultClientIDKey).(string)
		assert.Equal(t, "test-client-uuid", clientUUID)
	})(ctx)

	assert.True(t, called)
}

func TestFastHTTPBearerAuth_ValidToken_ContextBridge(t *testing.T) {
	expectedClaims := &Claims{
		ClientID: "bridge-client",
		Scopes:   []string{"admin"},
	}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return expectedClaims, nil
		},
	}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("Bearer some-token")
	mw(func(c *fasthttp.RequestCtx) {
		// Verify enriched context stored in UserValue
		enrichedCtx := c.UserValue(DefaultContextKey).(context.Context)
		claims, ok := ClaimsFromContext(enrichedCtx)
		assert.True(t, ok)
		assert.Equal(t, expectedClaims, claims)
	})(ctx)
}

func TestFastHTTPBearerAuth_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenInvalid
		},
	}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("Bearer bad-token")
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "invalid_token", resp.Error)
	assert.Equal(t, "Token validation failed", resp.ErrorDescription)
}

func TestFastHTTPBearerAuth_NilValidatorPanics(t *testing.T) {
	assert.PanicsWithValue(t, "FastHTTPBearerAuth: validator cannot be nil", func() {
		FastHTTPBearerAuth(nil)
	})
}

func TestFastHTTPBearerAuth_CustomClaimsKey(t *testing.T) {
	claims := &Claims{ClientID: "custom-key-client"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}
	mw := FastHTTPBearerAuth(validator, WithClaimsKey("my_claims"))

	ctx := newRequestCtx("Bearer token")
	mw(func(c *fasthttp.RequestCtx) {
		assert.Nil(t, c.UserValue(DefaultClaimsKey))
		assert.Equal(t, claims, c.UserValue("my_claims").(*Claims))
	})(ctx)
}

func TestFastHTTPBearerAuth_CustomClientIDKey(t *testing.T) {
	claims := &Claims{ClientID: "custom-uuid"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}
	mw := FastHTTPBearerAuth(validator, WithClientIDKey("my_uuid"))

	ctx := newRequestCtx("Bearer token")
	mw(func(c *fasthttp.RequestCtx) {
		assert.Nil(t, c.UserValue(DefaultClientIDKey))
		assert.Equal(t, "custom-uuid", c.UserValue("my_uuid").(string))
	})(ctx)
}

func TestFastHTTPBearerAuth_CustomContextKey(t *testing.T) {
	claims := &Claims{ClientID: "ctx-client"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}
	mw := FastHTTPBearerAuth(validator, WithContextKey("my_context"))

	ctx := newRequestCtx("Bearer token")
	mw(func(c *fasthttp.RequestCtx) {
		assert.Nil(t, c.UserValue(DefaultContextKey))
		enrichedCtx := c.UserValue("my_context").(context.Context)
		got, ok := ClaimsFromContext(enrichedCtx)
		assert.True(t, ok)
		assert.Equal(t, claims, got)
	})(ctx)
}

func TestFastHTTPBearerAuth_CustomErrorHandler(t *testing.T) {
	validator := &mockTokenValidator{}
	customCalled := false
	mw := FastHTTPBearerAuth(validator, WithErrorHandler(func(ctx *fasthttp.RequestCtx, statusCode int, errCode, errDesc string) {
		customCalled = true
		ctx.SetStatusCode(statusCode)
		ctx.SetBodyString(errCode + ": " + errDesc)
	}))

	ctx := newRequestCtx("")
	mw(func(_ *fasthttp.RequestCtx) {})(ctx)

	assert.True(t, customCalled)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	assert.Equal(t, "invalid_request: Missing authorization header", string(ctx.Response.Body()))
}

func TestFastHTTPBearerAuth_NilErrorHandlerUsesDefault(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := FastHTTPBearerAuth(validator, WithErrorHandler(nil))

	ctx := newRequestCtx("")
	mw(func(_ *fasthttp.RequestCtx) {})(ctx)

	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	assert.Equal(t, "application/json", string(ctx.Response.Header.ContentType()))
}

func TestFastHTTPBearerAuth_LowercaseBearer(t *testing.T) {
	claims := &Claims{ClientID: "case-test"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("bearer my-token")
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called, "lowercase 'bearer' should be accepted per RFC 6750/2617")
}

func TestFastHTTPBearerAuth_UppercaseBearer(t *testing.T) {
	claims := &Claims{ClientID: "case-test"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("BEARER my-token")
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called, "uppercase 'BEARER' should be accepted per RFC 6750/2617")
}

func TestFastHTTPBearerAuth_EmptyClaimsKeyPanics(t *testing.T) {
	assert.PanicsWithValue(t, "WithClaimsKey: key cannot be empty", func() {
		WithClaimsKey("")
	})
}

func TestFastHTTPBearerAuth_EmptyClientIDKeyPanics(t *testing.T) {
	assert.PanicsWithValue(t, "WithClientIDKey: key cannot be empty", func() {
		WithClientIDKey("")
	})
}

func TestFastHTTPBearerAuth_EmptyContextKeyPanics(t *testing.T) {
	assert.PanicsWithValue(t, "WithContextKey: key cannot be empty", func() {
		WithContextKey("")
	})
}

func TestFastHTTPBearerAuth_ErrorResponseJSON(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("")
	mw(func(_ *fasthttp.RequestCtx) {})(ctx)

	// Verify exact JSON structure
	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(ctx.Response.Body(), &raw))
	assert.Len(t, raw, 2)
	assert.Contains(t, raw, "error")
	assert.Contains(t, raw, "error_description")
}

// --- RequireScope Tests ---

func TestFastHTTPRequireScope_ScopePresent(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"read", "write"}})

	called := false
	FastHTTPRequireScope("read")(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called)
}

func TestFastHTTPRequireScope_ScopeMissing(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"read"}})

	called := false
	FastHTTPRequireScope("admin")(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required scope: admin", resp.ErrorDescription)
}

func TestFastHTTPRequireScope_NoClaims(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}

	called := false
	FastHTTPRequireScope("read")(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "invalid_token", resp.Error)
	assert.Equal(t, "Missing authentication context", resp.ErrorDescription)
}

func TestFastHTTPRequireScope_EmptyScopePanics(t *testing.T) {
	assert.PanicsWithValue(t, "FastHTTPRequireScope: scope cannot be empty", func() {
		FastHTTPRequireScope("")
	})
}

func TestFastHTTPRequireScope_WrongTypeInUserValue(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, "not-a-claims-pointer")

	called := false
	FastHTTPRequireScope("read")(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestFastHTTPRequireScope_CustomClaimsKey(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("custom_claims", &Claims{Scopes: []string{"admin"}})

	called := false
	FastHTTPRequireScope("admin", WithScopeClaimsKey("custom_claims"))(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called)
}

// --- RequireAnyScope Tests ---

func TestFastHTTPRequireAnyScope_AnyMatch(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"read", "write"}})

	called := false
	FastHTTPRequireAnyScope([]string{"admin", "write"})(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called)
}

func TestFastHTTPRequireAnyScope_NoneMatch(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"read"}})

	called := false
	FastHTTPRequireAnyScope([]string{"admin", "write"})(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required one of scopes: admin, write", resp.ErrorDescription)
}

func TestFastHTTPRequireAnyScope_NoClaims(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}

	called := false
	FastHTTPRequireAnyScope([]string{"read"})(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestFastHTTPRequireAnyScope_EmptyScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "FastHTTPRequireAnyScope: scopes cannot be empty", func() {
		FastHTTPRequireAnyScope([]string{})
	})
}

func TestFastHTTPRequireAnyScope_NilScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "FastHTTPRequireAnyScope: scopes cannot be empty", func() {
		FastHTTPRequireAnyScope(nil)
	})
}

// --- RequireScopeWildcard Tests ---

func TestFastHTTPRequireScopeWildcard_WildcardMatch(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"bgc:contractors:*"}})

	called := false
	FastHTTPRequireScopeWildcard("bgc:contractors:read")(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called)
}

func TestFastHTTPRequireScopeWildcard_ScopeMissing(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"bgc:contractors:*"}})

	called := false
	FastHTTPRequireScopeWildcard("acct:invoices:read")(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required scope: acct:invoices:read", resp.ErrorDescription)
}

func TestFastHTTPRequireScopeWildcard_NoClaims(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}

	called := false
	FastHTTPRequireScopeWildcard("read")(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestFastHTTPRequireScopeWildcard_EmptyScopePanics(t *testing.T) {
	assert.PanicsWithValue(t, "FastHTTPRequireScopeWildcard: scope cannot be empty", func() {
		FastHTTPRequireScopeWildcard("")
	})
}

func TestFastHTTPRequireScopeWildcard_WWWAuthenticateHeader_403(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"read"}})

	FastHTTPRequireScopeWildcard("admin")(func(_ *fasthttp.RequestCtx) {})(ctx)

	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	wwwAuth := string(ctx.Response.Header.Peek("WWW-Authenticate"))
	assert.Contains(t, wwwAuth, `error="insufficient_scope"`)
	assert.Contains(t, wwwAuth, "Required scope: admin")
}

// --- RequireAnyScopeWildcard Tests ---

func TestFastHTTPRequireAnyScopeWildcard_WildcardMatch(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"bgc:*"}})

	called := false
	FastHTTPRequireAnyScopeWildcard([]string{"acct:invoices:read", "bgc:contractors:read"})(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called)
}

func TestFastHTTPRequireAnyScopeWildcard_NoneMatch(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"acct:expenses:read"}})

	called := false
	FastHTTPRequireAnyScopeWildcard([]string{"admin", "write"})(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "insufficient_scope", resp.Error)
	assert.Equal(t, "Required one of scopes: admin, write", resp.ErrorDescription)
}

func TestFastHTTPRequireAnyScopeWildcard_NoClaims(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}

	called := false
	FastHTTPRequireAnyScopeWildcard([]string{"read"})(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
}

func TestFastHTTPRequireAnyScopeWildcard_EmptyScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "FastHTTPRequireAnyScopeWildcard: scopes cannot be empty", func() {
		FastHTTPRequireAnyScopeWildcard([]string{})
	})
}

func TestFastHTTPRequireAnyScopeWildcard_NilScopesPanics(t *testing.T) {
	assert.PanicsWithValue(t, "FastHTTPRequireAnyScopeWildcard: scopes cannot be empty", func() {
		FastHTTPRequireAnyScopeWildcard(nil)
	})
}

func TestFastHTTPRequireAnyScopeWildcard_DefensiveScopesCopy(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"admin:*"}})

	scopes := []string{"admin:read", "write"}
	mw := FastHTTPRequireAnyScopeWildcard(scopes)

	// Mutate original slice after middleware creation
	scopes[0] = "MUTATED"

	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called, "middleware should use defensively-copied scopes")
}

// --- NoopAuth Tests ---

func TestFastHTTPNoopAuth_InjectsClaims(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "noop-client",
		Scopes:   []string{"read", "write"},
	}
	mw := FastHTTPNoopAuth(defaultClaims)

	ctx := &fasthttp.RequestCtx{}
	mw(func(c *fasthttp.RequestCtx) {
		claims := c.UserValue(DefaultClaimsKey).(*Claims)
		assert.Equal(t, "noop-client", claims.ClientID)
		assert.Equal(t, []string{"read", "write"}, claims.Scopes)
		assert.Equal(t, "noop-client", c.UserValue(DefaultClientIDKey).(string))
	})(ctx)
}

func TestFastHTTPNoopAuth_DeepCopy(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "original",
		Scopes:   []string{"read"},
	}
	mw := FastHTTPNoopAuth(defaultClaims)

	// First request: mutate the returned claims
	ctx1 := &fasthttp.RequestCtx{}
	mw(func(c *fasthttp.RequestCtx) {
		claims := c.UserValue(DefaultClaimsKey).(*Claims)
		claims.Scopes = append(claims.Scopes, "mutated")
		claims.ClientID = "mutated"
	})(ctx1)

	// Second request: should get clean copy, not mutated
	ctx2 := &fasthttp.RequestCtx{}
	mw(func(c *fasthttp.RequestCtx) {
		claims := c.UserValue(DefaultClaimsKey).(*Claims)
		assert.Equal(t, "original", claims.ClientID)
		assert.Equal(t, []string{"read"}, claims.Scopes)
	})(ctx2)

	// Original unchanged
	assert.Equal(t, "original", defaultClaims.ClientID)
	assert.Equal(t, []string{"read"}, defaultClaims.Scopes)
}

func TestFastHTTPNoopAuth_ContextBridge(t *testing.T) {
	defaultClaims := &Claims{ClientID: "ctx-noop"}
	mw := FastHTTPNoopAuth(defaultClaims)

	ctx := &fasthttp.RequestCtx{}
	mw(func(c *fasthttp.RequestCtx) {
		enrichedCtx := c.UserValue(DefaultContextKey).(context.Context)
		claims, ok := ClaimsFromContext(enrichedCtx)
		assert.True(t, ok)
		assert.Equal(t, "ctx-noop", claims.ClientID)
	})(ctx)
}

func TestFastHTTPNoopAuth_NilDefaultClaimsPanics(t *testing.T) {
	assert.PanicsWithValue(t, "FastHTTPNoopAuth: defaultClaims cannot be nil", func() {
		FastHTTPNoopAuth(nil)
	})
}

// --- NoopScope Tests ---

func TestFastHTTPNoopScope_PassesThrough(t *testing.T) {
	mw := FastHTTPNoopScope()

	ctx := &fasthttp.RequestCtx{}
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called)
}

func TestFastHTTPNoopAuth_ConcurrentDeepCopy(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "concurrent-client",
		Scopes:   []string{"read", "write"},
	}
	mw := FastHTTPNoopAuth(defaultClaims)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			ctx := &fasthttp.RequestCtx{}
			mw(func(c *fasthttp.RequestCtx) {
				claims := c.UserValue(DefaultClaimsKey).(*Claims)
				// Mutate the copy — must not affect other goroutines or the original.
				claims.Scopes = append(claims.Scopes, "mutated")
				claims.ClientID = "mutated"
			})(ctx)
		}()
	}

	wg.Wait()

	// Original must be unchanged after concurrent mutations.
	assert.Equal(t, "concurrent-client", defaultClaims.ClientID)
	assert.Equal(t, []string{"read", "write"}, defaultClaims.Scopes)
}

// --- QA: Coverage Gap Tests ---

func TestFastHTTPRequireAnyScope_CustomClaimsKey(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue("custom_claims", &Claims{Scopes: []string{"admin", "write"}})

	called := false
	FastHTTPRequireAnyScope([]string{"write", "delete"}, WithScopeClaimsKey("custom_claims"))(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called)
}

func TestFastHTTPBearerAuth_ValidatorReturnsNilClaimsNilError(t *testing.T) {
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, nil // Edge case: nil claims with no error
		},
	}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("Bearer some-token")
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	// Nil claims should be treated as a validation failure, not passed through
	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "invalid_token", resp.Error)
}

func TestFastHTTPBearerAuth_ShortAuthHeader(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("Bear")
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Invalid authorization header format", resp.ErrorDescription)
}

func TestFastHTTPBearerAuth_AllCustomOptionsCombined(t *testing.T) {
	claims := &Claims{ClientID: "combo-client", Scopes: []string{"admin"}}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}
	mw := FastHTTPBearerAuth(validator,
		WithClaimsKey("my_claims"),
		WithClientIDKey("my_uuid"),
		WithContextKey("my_ctx"),
	)

	ctx := newRequestCtx("Bearer token")
	mw(func(c *fasthttp.RequestCtx) {
		// Custom keys should have values
		assert.Equal(t, claims, c.UserValue("my_claims").(*Claims))
		assert.Equal(t, "combo-client", c.UserValue("my_uuid").(string))
		enrichedCtx := c.UserValue("my_ctx").(context.Context)
		got, ok := ClaimsFromContext(enrichedCtx)
		assert.True(t, ok)
		assert.Equal(t, claims, got)

		// Default keys should be nil
		assert.Nil(t, c.UserValue(DefaultClaimsKey))
		assert.Nil(t, c.UserValue(DefaultClientIDKey))
		assert.Nil(t, c.UserValue(DefaultContextKey))
	})(ctx)
}

func TestFastHTTPBearerAuth_MiddlewareChain(t *testing.T) {
	claims := &Claims{ClientID: "chain-client", Scopes: []string{"read", "write"}}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}

	auth := FastHTTPBearerAuth(validator)
	scope := FastHTTPRequireScope("read")

	handlerCalled := false
	handler := func(_ *fasthttp.RequestCtx) { handlerCalled = true }

	// Chain: auth -> scope -> handler
	ctx := newRequestCtx("Bearer valid-token")
	auth(scope(handler))(ctx)

	assert.True(t, handlerCalled)
	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())
}

func TestFastHTTPBearerAuth_MiddlewareChain_ScopeDenied(t *testing.T) {
	claims := &Claims{ClientID: "chain-client", Scopes: []string{"read"}}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}

	auth := FastHTTPBearerAuth(validator)
	scope := FastHTTPRequireScope("admin")

	handlerCalled := false
	handler := func(_ *fasthttp.RequestCtx) { handlerCalled = true }

	ctx := newRequestCtx("Bearer valid-token")
	auth(scope(handler))(ctx)

	assert.False(t, handlerCalled)
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestFastHTTPNoopAuth_DeepCopyAudience(t *testing.T) {
	defaultClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"aud1", "aud2"},
		},
		ClientID: "aud-client",
	}
	mw := FastHTTPNoopAuth(defaultClaims)

	// First request: mutate audience
	ctx1 := &fasthttp.RequestCtx{}
	mw(func(c *fasthttp.RequestCtx) {
		claims := c.UserValue(DefaultClaimsKey).(*Claims)
		claims.Audience = append(claims.Audience, "mutated")
	})(ctx1)

	// Second request: should get clean copy
	ctx2 := &fasthttp.RequestCtx{}
	mw(func(c *fasthttp.RequestCtx) {
		claims := c.UserValue(DefaultClaimsKey).(*Claims)
		assert.Equal(t, jwt.ClaimStrings{"aud1", "aud2"}, claims.Audience)
	})(ctx2)

	// Original unchanged
	assert.Equal(t, jwt.ClaimStrings{"aud1", "aud2"}, defaultClaims.Audience)
}

func TestFastHTTPNoopAuth_DeepCopyNumericDates(t *testing.T) {
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
	mw := FastHTTPNoopAuth(defaultClaims)

	ctx := &fasthttp.RequestCtx{}
	mw(func(c *fasthttp.RequestCtx) {
		claims := c.UserValue(DefaultClaimsKey).(*Claims)

		// Verify dates are copied (not same pointer)
		require.NotNil(t, claims.ExpiresAt)
		require.NotNil(t, claims.NotBefore)
		require.NotNil(t, claims.IssuedAt)

		// Pointers must be different (deep copy, not shared)
		assert.NotSame(t, defaultClaims.ExpiresAt, claims.ExpiresAt)
		assert.NotSame(t, defaultClaims.NotBefore, claims.NotBefore)
		assert.NotSame(t, defaultClaims.IssuedAt, claims.IssuedAt)

		// Values should match
		assert.Equal(t, expTime.Unix(), claims.ExpiresAt.Unix())
		assert.Equal(t, nbfTime.Unix(), claims.NotBefore.Unix())
		assert.Equal(t, iatTime.Unix(), claims.IssuedAt.Unix())

		// Mutate copied dates — should not affect original
		claims.ExpiresAt = jwt.NewNumericDate(time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC))
	})(ctx)

	// Original unchanged
	assert.Equal(t, expTime.Unix(), defaultClaims.ExpiresAt.Unix())
}

func TestFastHTTPBearerAuth_MixedCaseBearer(t *testing.T) {
	claims := &Claims{ClientID: "mixed-case"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token)
			return claims, nil
		},
	}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("BeArEr my-token")
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called, "mixed case 'BeArEr' should be accepted per RFC 6750/2617")
}

// --- Security Fix Tests ---

func TestFastHTTPBearerAuth_WWWAuthenticateHeader_401(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("")
	mw(func(_ *fasthttp.RequestCtx) {})(ctx)

	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	wwwAuth := string(ctx.Response.Header.Peek("WWW-Authenticate"))
	assert.Contains(t, wwwAuth, "Bearer")
	assert.Contains(t, wwwAuth, `realm="api"`)
	assert.Contains(t, wwwAuth, `error="invalid_request"`)
}

func TestFastHTTPBearerAuth_WWWAuthenticateHeader_InvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenInvalid
		},
	}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("Bearer bad-token")
	mw(func(_ *fasthttp.RequestCtx) {})(ctx)

	wwwAuth := string(ctx.Response.Header.Peek("WWW-Authenticate"))
	assert.Contains(t, wwwAuth, `error="invalid_token"`)
}

func TestFastHTTPRequireScope_WWWAuthenticateHeader_403(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"read"}})

	FastHTTPRequireScope("admin")(func(_ *fasthttp.RequestCtx) {})(ctx)

	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	wwwAuth := string(ctx.Response.Header.Peek("WWW-Authenticate"))
	assert.Contains(t, wwwAuth, `error="insufficient_scope"`)
}

func TestFastHTTPBearerAuth_OversizedToken(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := FastHTTPBearerAuth(validator)

	// Create a token larger than maxBearerTokenLength (4096)
	bigToken := strings.Repeat("a", 4097)
	ctx := newRequestCtx("Bearer " + bigToken)
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Bearer token exceeds maximum length", resp.ErrorDescription)
}

func TestFastHTTPBearerAuth_MaxLengthTokenAccepted(t *testing.T) {
	claims := &Claims{ClientID: "max-len"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return claims, nil
		},
	}
	mw := FastHTTPBearerAuth(validator)

	// Exactly maxBearerTokenLength should be accepted
	exactToken := strings.Repeat("a", 4096)
	ctx := newRequestCtx("Bearer " + exactToken)
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called)
}

func TestFastHTTPBearerAuth_TokenWhitespaceTrimmed(t *testing.T) {
	claims := &Claims{ClientID: "trim-test"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, token string) (*Claims, error) {
			assert.Equal(t, "my-token", token, "token should be trimmed of whitespace")
			return claims, nil
		},
	}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("Bearer  my-token ")
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.True(t, called)
}

func TestFastHTTPBearerAuth_WhitespaceOnlyTokenEmpty(t *testing.T) {
	validator := &mockTokenValidator{}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("Bearer    ")
	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	assert.False(t, called)
	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "invalid_request", resp.Error)
	assert.Equal(t, "Empty bearer token", resp.ErrorDescription)
}

// --- Adversarial Fix Tests ---

func TestFastHTTPRequireScope_CustomErrorHandler(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"read"}})

	customCalled := false
	scope := FastHTTPRequireScope("admin", WithScopeErrorHandler(func(c *fasthttp.RequestCtx, statusCode int, errCode, errDesc string) {
		customCalled = true
		c.SetStatusCode(statusCode)
		c.SetBodyString(errCode + ": " + errDesc)
	}))

	scope(func(_ *fasthttp.RequestCtx) {})(ctx)

	assert.True(t, customCalled, "scope middleware should use custom error handler")
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, "insufficient_scope: Required scope: admin", string(ctx.Response.Body()))
}

func TestFastHTTPRequireAnyScope_CustomErrorHandler(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"read"}})

	customCalled := false
	scope := FastHTTPRequireAnyScope([]string{"admin", "write"}, WithScopeErrorHandler(func(c *fasthttp.RequestCtx, statusCode int, errCode, errDesc string) {
		customCalled = true
		c.SetStatusCode(statusCode)
		c.SetBodyString(errCode + ": " + errDesc)
	}))

	scope(func(_ *fasthttp.RequestCtx) {})(ctx)

	assert.True(t, customCalled, "any-scope middleware should use custom error handler")
	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
}

func TestFastHTTPRequireAnyScope_DefensiveScopesCopy(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"admin"}})

	scopes := []string{"admin", "write"}
	mw := FastHTTPRequireAnyScope(scopes)

	// Mutate original slice after middleware creation
	scopes[0] = "MUTATED"

	called := false
	mw(func(_ *fasthttp.RequestCtx) { called = true })(ctx)

	// Middleware should still check "admin" (from the defensive copy), not "MUTATED"
	assert.True(t, called, "middleware should use defensively-copied scopes, not mutated original")
}

func TestFastHTTPEscapeQuotedString(t *testing.T) {
	assert.Equal(t, "simple", escapeQuotedString("simple"))
	assert.Equal(t, `hello \"world\"`, escapeQuotedString(`hello "world"`))
	assert.Equal(t, `back\\slash`, escapeQuotedString(`back\slash`))
	// Input `\"` has both \ and " — each gets escaped independently
	assert.Equal(t, `both \\\"quote\\\"`, escapeQuotedString(`both \"quote\"`))
	assert.Equal(t, "", escapeQuotedString(""))
	// Single-character edge cases
	assert.Equal(t, `\\`, escapeQuotedString(`\`))
	assert.Equal(t, `\"`, escapeQuotedString(`"`))
	assert.Equal(t, `\\\"\\`, escapeQuotedString(`\"\`))
}

func TestFastHTTPScopeClaimsKeyEmptyPanics(t *testing.T) {
	assert.PanicsWithValue(t, "WithScopeClaimsKey: key cannot be empty", func() {
		WithScopeClaimsKey("")
	})
}

func TestFastHTTPBearerAuth_ValidatorReceivesRequestCtx(t *testing.T) {
	var receivedCtx context.Context
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(ctx context.Context, _ string) (*Claims, error) {
			receivedCtx = ctx
			return &Claims{ClientID: "ctx-test"}, nil
		},
	}
	mw := FastHTTPBearerAuth(validator)

	reqCtx := newRequestCtx("Bearer token")
	mw(func(_ *fasthttp.RequestCtx) {})(reqCtx)

	// The validator should receive the fasthttp.RequestCtx as context
	assert.Equal(t, reqCtx, receivedCtx, "validator should receive RequestCtx as context")
}

func TestFastHTTPBearerAuth_StoresExactClaimsPointer(t *testing.T) {
	expectedClaims := &Claims{ClientID: "pointer-test"}
	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return expectedClaims, nil
		},
	}
	mw := FastHTTPBearerAuth(validator)

	ctx := newRequestCtx("Bearer token")
	mw(func(c *fasthttp.RequestCtx) {
		claims := c.UserValue(DefaultClaimsKey).(*Claims)
		assert.Same(t, expectedClaims, claims, "BearerAuth should store exact pointer from validator")
	})(ctx)
}

func TestFastHTTPNoopScope_ReturnsExactHandler(t *testing.T) {
	mw := FastHTTPNoopScope()
	handler := func(_ *fasthttp.RequestCtx) {}

	// NoopScope should return the exact same handler pointer (zero wrapping)
	wrapped := mw(handler)
	assert.NotNil(t, wrapped)
	// Verify via invocation — both the original and wrapped should behave identically
	// (Go doesn't support direct function pointer comparison, so we verify via call)
	ctx := &fasthttp.RequestCtx{}
	called := false
	sentinel := func(_ *fasthttp.RequestCtx) { called = true }
	mw(sentinel)(ctx)
	assert.True(t, called)
}

func TestFastHTTPScopeErrorHandler_NilUsesDefault(t *testing.T) {
	ctx := &fasthttp.RequestCtx{}
	ctx.SetUserValue(DefaultClaimsKey, &Claims{Scopes: []string{"read"}})

	// WithScopeErrorHandler(nil) should fall back to default JSON handler
	scope := FastHTTPRequireScope("admin", WithScopeErrorHandler(nil))
	scope(func(_ *fasthttp.RequestCtx) {})(ctx)

	assert.Equal(t, fasthttp.StatusForbidden, ctx.Response.StatusCode())
	assert.Equal(t, "application/json", string(ctx.Response.Header.ContentType()))
	resp := parseErrorResponse(t, ctx)
	assert.Equal(t, "insufficient_scope", resp.Error)
}
