package authclient

import (
	"encoding/json"
	"strings"

	"github.com/valyala/fasthttp"
)

// Default UserValue keys for fasthttp middleware.
const (
	DefaultClaimsKey   = "auth_claims"
	DefaultClientIDKey = "client_id"
	DefaultContextKey  = "auth_context"
)

// fasthttpErrorHandler is the function signature for custom error response writers
// used by both BearerAuth and scope middleware.
type fasthttpErrorHandler func(ctx *fasthttp.RequestCtx, statusCode int, errCode, errDesc string)

// fasthttpConfig holds configuration for the BearerAuth middleware.
type fasthttpConfig struct {
	claimsKey    string
	clientIDKey  string
	contextKey   string
	errorHandler fasthttpErrorHandler
}

// FastHTTPOption configures the BearerAuth middleware.
type FastHTTPOption func(*fasthttpConfig)

// WithErrorHandler sets a custom error response handler with signature
// func(ctx *fasthttp.RequestCtx, statusCode int, errCode, errDesc string).
// If fn is nil, the default JSON RFC 6750 handler is used.
func WithErrorHandler(fn fasthttpErrorHandler) FastHTTPOption {
	return func(c *fasthttpConfig) {
		if fn != nil {
			c.errorHandler = fn
		}
	}
}

// WithClaimsKey sets the UserValue key for storing *Claims.
// Panics if key is empty.
func WithClaimsKey(key string) FastHTTPOption {
	if key == "" {
		panic("WithClaimsKey: key cannot be empty")
	}
	return func(c *fasthttpConfig) {
		c.claimsKey = key
	}
}

// WithClientIDKey sets the UserValue key for storing the client ID string.
// Panics if key is empty.
func WithClientIDKey(key string) FastHTTPOption {
	if key == "" {
		panic("WithClientIDKey: key cannot be empty")
	}
	return func(c *fasthttpConfig) {
		c.clientIDKey = key
	}
}

// WithContextKey sets the UserValue key for storing the enriched context.Context.
// Panics if key is empty.
func WithContextKey(key string) FastHTTPOption {
	if key == "" {
		panic("WithContextKey: key cannot be empty")
	}
	return func(c *fasthttpConfig) {
		c.contextKey = key
	}
}

// errorResponse is the RFC 6750 JSON error body.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// escapeQuotedString escapes `"` and `\` for use in HTTP quoted-string values
// per RFC 7230 Section 3.2.6. Ensures WWW-Authenticate header values are well-formed.
// Uses byte-level iteration since error codes and descriptions are ASCII-only.
func escapeQuotedString(s string) string {
	if !strings.ContainsAny(s, `"\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}

// defaultErrorHandler writes an RFC 6750 JSON error response.
// For 401 responses, sets WWW-Authenticate header per RFC 6750 Section 3.
// For 403 responses, sets WWW-Authenticate with error and scope info.
// The realm is hardcoded to "api"; use WithErrorHandler for custom realm values.
func defaultErrorHandler(ctx *fasthttp.RequestCtx, statusCode int, errCode, errDesc string) {
	ctx.Response.Header.SetContentType("application/json")
	if statusCode == fasthttp.StatusUnauthorized || statusCode == fasthttp.StatusForbidden {
		ctx.Response.Header.Set("WWW-Authenticate",
			`Bearer realm="api", error="`+escapeQuotedString(errCode)+`", error_description="`+escapeQuotedString(errDesc)+`"`)
	}
	ctx.SetStatusCode(statusCode)
	body, err := json.Marshal(errorResponse{
		Error:            errCode,
		ErrorDescription: errDesc,
	})
	if err != nil {
		// Fallback: write a valid JSON error manually if marshaling fails.
		ctx.SetBodyString(`{"error":"server_error","error_description":"Internal error"}`)
		return
	}
	ctx.SetBody(body)
}

// FastHTTPBearerAuth returns middleware that validates Bearer tokens from the
// Authorization header using the provided TokenValidator and stores the resulting
// *Claims in fasthttp.RequestCtx UserValues.
//
// Claims are stored under three keys (configurable via options):
//   - claimsKey (default "auth_claims"): *Claims pointer
//   - clientIDKey (default "client_id"): claims.ClientID as string (P7 deviation: stored as string per AC-1, consumers parse if needed)
//   - contextKey (default "auth_context"): context.Context with claims for service-layer bridging
//
// Panics if validator is nil (fail-fast at startup, not per-request).
func FastHTTPBearerAuth(validator TokenValidator, opts ...FastHTTPOption) func(fasthttp.RequestHandler) fasthttp.RequestHandler {
	if validator == nil {
		panic("FastHTTPBearerAuth: validator cannot be nil")
	}

	cfg := fasthttpConfig{
		claimsKey:    DefaultClaimsKey,
		clientIDKey:  DefaultClientIDKey,
		contextKey:   DefaultContextKey,
		errorHandler: defaultErrorHandler,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			authHeader := string(ctx.Request.Header.Peek("Authorization"))
			if authHeader == "" {
				cfg.errorHandler(ctx, fasthttp.StatusUnauthorized,
					"invalid_request", "Missing authorization header")
				return
			}

			if len(authHeader) < 7 || !strings.EqualFold(authHeader[:7], "Bearer ") {
				cfg.errorHandler(ctx, fasthttp.StatusUnauthorized,
					"invalid_request", "Invalid authorization header format")
				return
			}

			token := strings.TrimSpace(authHeader[7:])
			if token == "" {
				cfg.errorHandler(ctx, fasthttp.StatusUnauthorized,
					"invalid_request", "Empty bearer token")
				return
			}

			if len(token) > MaxBearerTokenLength {
				cfg.errorHandler(ctx, fasthttp.StatusUnauthorized,
					"invalid_request", "Bearer token exceeds maximum length")
				return
			}

			claims, err := validator.ValidateToken(ctx, token)
			if err != nil || claims == nil {
				cfg.errorHandler(ctx, fasthttp.StatusUnauthorized,
					"invalid_token", "Token validation failed")
				return
			}

			ctx.SetUserValue(cfg.claimsKey, claims)
			ctx.SetUserValue(cfg.clientIDKey, claims.ClientID)

			enrichedCtx := ContextWithClaims(ctx, claims)
			ctx.SetUserValue(cfg.contextKey, enrichedCtx)

			next(ctx)
		}
	}
}

// FastHTTPScopeOption configures scope middleware behavior.
type FastHTTPScopeOption func(*fasthttpScopeConfig)

type fasthttpScopeConfig struct {
	claimsKey    string
	errorHandler fasthttpErrorHandler
}

// WithScopeClaimsKey overrides the UserValue key for claims retrieval in scope middleware.
// Panics if key is empty.
func WithScopeClaimsKey(key string) FastHTTPScopeOption {
	if key == "" {
		panic("WithScopeClaimsKey: key cannot be empty")
	}
	return func(c *fasthttpScopeConfig) {
		c.claimsKey = key
	}
}

// WithScopeErrorHandler sets a custom error handler for scope middleware with signature
// func(ctx *fasthttp.RequestCtx, statusCode int, errCode, errDesc string).
// If fn is nil, the default RFC 6750 JSON handler is used.
func WithScopeErrorHandler(fn fasthttpErrorHandler) FastHTTPScopeOption {
	return func(c *fasthttpScopeConfig) {
		if fn != nil {
			c.errorHandler = fn
		}
	}
}

func newScopeConfig(opts []FastHTTPScopeOption) fasthttpScopeConfig {
	cfg := fasthttpScopeConfig{
		claimsKey:    DefaultClaimsKey,
		errorHandler: defaultErrorHandler,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return cfg
}

// FastHTTPRequireScope returns middleware that checks the authenticated request
// has the exact required scope. Must be applied after BearerAuth.
//
// Options allow overriding the claims key and error handler to match BearerAuth config.
//
// Returns 401 if no claims are found (BearerAuth not applied or failed).
// Returns 403 if the required scope is missing (fail-closed for empty scope).
func FastHTTPRequireScope(scope string, opts ...FastHTTPScopeOption) func(fasthttp.RequestHandler) fasthttp.RequestHandler {
	if scope == "" {
		panic("FastHTTPRequireScope: scope cannot be empty")
	}
	cfg := newScopeConfig(opts)

	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			claims, ok := ctx.UserValue(cfg.claimsKey).(*Claims)
			if !ok || claims == nil {
				cfg.errorHandler(ctx, fasthttp.StatusUnauthorized,
					"invalid_token", "Missing authentication context")
				return
			}

			if !HasScope(claims, scope) {
				cfg.errorHandler(ctx, fasthttp.StatusForbidden,
					"insufficient_scope", "Required scope: "+scope)
				return
			}

			next(ctx)
		}
	}
}

// FastHTTPRequireAnyScope returns middleware that checks the authenticated request
// has at least one of the required scopes. Must be applied after BearerAuth.
//
// Options allow overriding the claims key and error handler to match BearerAuth config.
// The scopes slice is defensively copied at middleware creation time.
//
// Returns 401 if no claims are found (BearerAuth not applied or failed).
// Returns 403 if none of the required scopes are present.
func FastHTTPRequireAnyScope(scopes []string, opts ...FastHTTPScopeOption) func(fasthttp.RequestHandler) fasthttp.RequestHandler {
	if len(scopes) == 0 {
		panic("FastHTTPRequireAnyScope: scopes cannot be empty")
	}
	cfg := newScopeConfig(opts)

	// Defensive copy to prevent shared-state mutation after middleware creation.
	scopesCopy := make([]string, len(scopes))
	copy(scopesCopy, scopes)
	scopesDesc := strings.Join(scopesCopy, ", ")

	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			claims, ok := ctx.UserValue(cfg.claimsKey).(*Claims)
			if !ok || claims == nil {
				cfg.errorHandler(ctx, fasthttp.StatusUnauthorized,
					"invalid_token", "Missing authentication context")
				return
			}

			if !HasAnyScope(claims, scopesCopy...) {
				cfg.errorHandler(ctx, fasthttp.StatusForbidden,
					"insufficient_scope", "Required one of scopes: "+scopesDesc)
				return
			}

			next(ctx)
		}
	}
}

// FastHTTPRequireScopeWildcard returns middleware that checks the authenticated request
// has a scope matching the required scope using wildcard matching.
// Must be applied after BearerAuth.
//
// Unlike FastHTTPRequireScope (exact match only), this supports wildcard patterns:
// a user with "bgc:*" will satisfy a requirement for "bgc:contractors:read".
//
// Returns 401 if no claims are found (BearerAuth not applied or failed).
// Returns 403 if the required scope is not matched.
func FastHTTPRequireScopeWildcard(scope string, opts ...FastHTTPScopeOption) func(fasthttp.RequestHandler) fasthttp.RequestHandler {
	if scope == "" {
		panic("FastHTTPRequireScopeWildcard: scope cannot be empty")
	}
	cfg := newScopeConfig(opts)

	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			claims, ok := ctx.UserValue(cfg.claimsKey).(*Claims)
			if !ok || claims == nil {
				cfg.errorHandler(ctx, fasthttp.StatusUnauthorized,
					"invalid_token", "Missing authentication context")
				return
			}

			if !HasScopeWildcard(claims, scope) {
				cfg.errorHandler(ctx, fasthttp.StatusForbidden,
					"insufficient_scope", "Required scope: "+scope)
				return
			}

			next(ctx)
		}
	}
}

// FastHTTPRequireAnyScopeWildcard returns middleware that checks the authenticated request
// has at least one scope matching any of the required scopes using wildcard matching.
// Must be applied after BearerAuth.
//
// The scopes slice is defensively copied at middleware creation time.
//
// Returns 401 if no claims are found (BearerAuth not applied or failed).
// Returns 403 if none of the required scopes are matched.
func FastHTTPRequireAnyScopeWildcard(scopes []string, opts ...FastHTTPScopeOption) func(fasthttp.RequestHandler) fasthttp.RequestHandler {
	if len(scopes) == 0 {
		panic("FastHTTPRequireAnyScopeWildcard: scopes cannot be empty")
	}
	cfg := newScopeConfig(opts)

	scopesCopy := make([]string, len(scopes))
	copy(scopesCopy, scopes)
	scopesDesc := strings.Join(scopesCopy, ", ")

	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			claims, ok := ctx.UserValue(cfg.claimsKey).(*Claims)
			if !ok || claims == nil {
				cfg.errorHandler(ctx, fasthttp.StatusUnauthorized,
					"invalid_token", "Missing authentication context")
				return
			}

			if !HasAnyScopeWildcard(claims, scopesCopy...) {
				cfg.errorHandler(ctx, fasthttp.StatusForbidden,
					"insufficient_scope", "Required one of scopes: "+scopesDesc)
				return
			}

			next(ctx)
		}
	}
}

// FastHTTPNoopAuth returns middleware that injects default claims without
// token validation. For development and testing only.
//
// Each request receives a deep copy of defaultClaims to prevent shared-state
// mutation across concurrent requests.
//
// Claims are stored under the default keys (DefaultClaimsKey, DefaultClientIDKey,
// DefaultContextKey). If BearerAuth is configured with custom keys via options,
// downstream middleware must also use matching custom keys.
//
// Panics if defaultClaims is nil (fail-fast at configuration time).
func FastHTTPNoopAuth(defaultClaims *Claims) func(fasthttp.RequestHandler) fasthttp.RequestHandler {
	if defaultClaims == nil {
		panic("FastHTTPNoopAuth: defaultClaims cannot be nil")
	}

	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return func(ctx *fasthttp.RequestCtx) {
			claims := defaultClaims.DeepCopy()

			ctx.SetUserValue(DefaultClaimsKey, claims)
			ctx.SetUserValue(DefaultClientIDKey, claims.ClientID)

			enrichedCtx := ContextWithClaims(ctx, claims)
			ctx.SetUserValue(DefaultContextKey, enrichedCtx)

			next(ctx)
		}
	}
}

// FastHTTPNoopScope returns scope middleware that always passes through.
// For development and testing only, paired with FastHTTPNoopAuth.
func FastHTTPNoopScope() func(fasthttp.RequestHandler) fasthttp.RequestHandler {
	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		return next
	}
}
