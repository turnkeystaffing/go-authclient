package authgin

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/turnkeystaffing/go-authclient"
)

// ginErrorHandler is the function signature for custom error response writers.
// Implementations should write an error response (e.g., c.JSON or c.AbortWithStatusJSON).
// The middleware calls c.Abort() after invoking the handler, so implementations
// need not call c.Abort() themselves (but doing so is harmless and idempotent).
type ginErrorHandler func(c *gin.Context, statusCode int, errCode, errDesc string)

// ginConfig holds configuration for the BearerAuth middleware.
type ginConfig struct {
	claimsKey    string
	errorHandler ginErrorHandler
}

// Option configures the BearerAuth middleware.
type Option func(*ginConfig)

// WithErrorHandler sets a custom error response handler.
// If fn is nil, the default JSON RFC 6750 handler is used.
func WithErrorHandler(fn ginErrorHandler) Option {
	return func(c *ginConfig) {
		if fn != nil {
			c.errorHandler = fn
		}
	}
}

// WithClaimsKey sets the gin context key for storing *Claims.
// Panics if key is empty.
func WithClaimsKey(key string) Option {
	if key == "" {
		panic("WithClaimsKey: key cannot be empty")
	}
	return func(c *ginConfig) {
		c.claimsKey = key
	}
}

// errorResponse is the RFC 6750 JSON error body.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// escapeQuotedString escapes `"` and `\` for use in HTTP quoted-string values
// per RFC 7230 Section 3.2.6. Uses byte-level iteration since error codes and
// descriptions are ASCII-only.
// Mirrors the parent package's escapeQuotedString (fasthttp.go).
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
// Sets WWW-Authenticate header on 401/403 per RFC 6750 Section 3.
// Header is set BEFORE AbortWithStatusJSON to ensure it is written.
func defaultErrorHandler(c *gin.Context, statusCode int, errCode, errDesc string) {
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		c.Header("WWW-Authenticate",
			`Bearer realm="api", error="`+escapeQuotedString(errCode)+`", error_description="`+escapeQuotedString(errDesc)+`"`)
	}
	c.AbortWithStatusJSON(statusCode, errorResponse{
		Error:            errCode,
		ErrorDescription: errDesc,
	})
}

// BearerAuth returns gin middleware that validates Bearer tokens from the
// Authorization header using the provided TokenValidator.
//
// Claims are stored in gin context via c.Set(claimsKey, claims) and in the
// request's context.Context via authclient.ContextWithClaims for service-layer access.
//
// Panics if validator is nil (fail-fast at startup).
func BearerAuth(validator authclient.TokenValidator, opts ...Option) gin.HandlerFunc {
	if validator == nil {
		panic("BearerAuth: validator cannot be nil")
	}

	cfg := ginConfig{
		claimsKey:    "auth_claims",
		errorHandler: defaultErrorHandler,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			cfg.errorHandler(c, http.StatusUnauthorized,
				"invalid_request", "Missing authorization header")
			c.Abort()
			return
		}

		if len(authHeader) < 7 || !strings.EqualFold(authHeader[:7], "Bearer ") {
			cfg.errorHandler(c, http.StatusUnauthorized,
				"invalid_request", "Invalid authorization header format")
			c.Abort()
			return
		}

		token := strings.TrimSpace(authHeader[7:])
		if token == "" {
			cfg.errorHandler(c, http.StatusUnauthorized,
				"invalid_request", "Empty bearer token")
			c.Abort()
			return
		}

		if len(token) > authclient.MaxBearerTokenLength {
			cfg.errorHandler(c, http.StatusUnauthorized,
				"invalid_request", "Bearer token exceeds maximum length")
			c.Abort()
			return
		}

		claims, err := validator.ValidateToken(c.Request.Context(), token)
		if err != nil || claims == nil {
			cfg.errorHandler(c, http.StatusUnauthorized,
				"invalid_token", "Token validation failed")
			c.Abort()
			return
		}

		c.Set(cfg.claimsKey, claims)
		enrichedCtx := authclient.ContextWithClaims(c.Request.Context(), claims)
		c.Request = c.Request.WithContext(enrichedCtx)
		c.Next()
	}
}

// ScopeOption configures scope middleware behavior.
type ScopeOption func(*scopeConfig)

type scopeConfig struct {
	claimsKey    string
	errorHandler ginErrorHandler
}

// WithScopeErrorHandler sets a custom error handler for scope middleware.
// If fn is nil, the default RFC 6750 JSON handler is used.
func WithScopeErrorHandler(fn ginErrorHandler) ScopeOption {
	return func(c *scopeConfig) {
		if fn != nil {
			c.errorHandler = fn
		}
	}
}

// WithScopeClaimsKey overrides the gin context key for claims retrieval in scope middleware.
// Panics if key is empty.
func WithScopeClaimsKey(key string) ScopeOption {
	if key == "" {
		panic("WithScopeClaimsKey: key cannot be empty")
	}
	return func(c *scopeConfig) {
		c.claimsKey = key
	}
}

// RequireScope returns gin middleware that checks the authenticated request
// has the exact required scope. Must be applied after BearerAuth.
//
// Returns 401 if no claims found, 403 if scope missing.
func RequireScope(scope string, opts ...ScopeOption) gin.HandlerFunc {
	if scope == "" {
		panic("RequireScope: scope cannot be empty")
	}
	cfg := scopeConfig{
		claimsKey:    "auth_claims",
		errorHandler: defaultErrorHandler,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(c *gin.Context) {
		val, exists := c.Get(cfg.claimsKey)
		if !exists {
			cfg.errorHandler(c, http.StatusUnauthorized,
				"invalid_token", "Missing authentication context")
			c.Abort()
			return
		}
		claims, ok := val.(*authclient.Claims)
		if !ok || claims == nil {
			cfg.errorHandler(c, http.StatusUnauthorized,
				"invalid_token", "Missing authentication context")
			c.Abort()
			return
		}

		if !authclient.HasScope(claims, scope) {
			cfg.errorHandler(c, http.StatusForbidden,
				"insufficient_scope", "Required scope: "+scope)
			c.Abort()
			return
		}

		c.Next()
	}
}

// RequireAnyScope returns gin middleware that checks the authenticated request
// has at least one of the required scopes. Must be applied after BearerAuth.
//
// The scopes slice is defensively copied at middleware creation time.
//
// Returns 401 if no claims found, 403 if none of the required scopes present.
func RequireAnyScope(scopes []string, opts ...ScopeOption) gin.HandlerFunc {
	if len(scopes) == 0 {
		panic("RequireAnyScope: scopes cannot be empty")
	}
	cfg := scopeConfig{
		claimsKey:    "auth_claims",
		errorHandler: defaultErrorHandler,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	scopesCopy := make([]string, len(scopes))
	copy(scopesCopy, scopes)
	scopesDesc := strings.Join(scopesCopy, ", ")

	return func(c *gin.Context) {
		val, exists := c.Get(cfg.claimsKey)
		if !exists {
			cfg.errorHandler(c, http.StatusUnauthorized,
				"invalid_token", "Missing authentication context")
			c.Abort()
			return
		}
		claims, ok := val.(*authclient.Claims)
		if !ok || claims == nil {
			cfg.errorHandler(c, http.StatusUnauthorized,
				"invalid_token", "Missing authentication context")
			c.Abort()
			return
		}

		if !authclient.HasAnyScope(claims, scopesCopy...) {
			cfg.errorHandler(c, http.StatusForbidden,
				"insufficient_scope", "Required one of scopes: "+scopesDesc)
			c.Abort()
			return
		}

		c.Next()
	}
}

// NoopAuth returns gin middleware that injects default claims without
// token validation. For development and testing only.
//
// Each request receives a deep copy of defaultClaims to prevent shared-state
// mutation across concurrent requests.
//
// Claims are stored under the default key "auth_claims". If BearerAuth is
// configured with a custom WithClaimsKey, scope middleware must use
// WithScopeClaimsKey matching BearerAuth's key, not NoopAuth's default.
// The request context path (authclient.ClaimsFromContext) is always available
// regardless of gin key configuration and is the recommended service-layer path.
//
// Panics if defaultClaims is nil (fail-fast at configuration time).
func NoopAuth(defaultClaims *authclient.Claims) gin.HandlerFunc {
	if defaultClaims == nil {
		panic("NoopAuth: defaultClaims cannot be nil")
	}

	return func(c *gin.Context) {
		claims := defaultClaims.DeepCopy()
		c.Set("auth_claims", claims)
		enrichedCtx := authclient.ContextWithClaims(c.Request.Context(), claims)
		c.Request = c.Request.WithContext(enrichedCtx)
		c.Next()
	}
}

// NoopScope returns gin middleware that always passes through.
// For development and testing only, paired with NoopAuth.
func NoopScope() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}
