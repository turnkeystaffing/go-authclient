package authclient

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// ginErrorHandler is the function signature for custom error response writers.
// Implementations should write an error response (e.g., c.JSON or c.AbortWithStatusJSON).
// The middleware calls c.Abort() after invoking the handler, so implementations
// need not call c.Abort() themselves (but doing so is harmless and idempotent).
type ginErrorHandler func(c *gin.Context, statusCode int, errCode, errDesc string)

// ginConfig holds configuration for the GinBearerAuth middleware.
type ginConfig struct {
	claimsKey    string
	errorHandler ginErrorHandler
}

// GinOption configures the GinBearerAuth middleware.
type GinOption func(*ginConfig)

// WithGinErrorHandler sets a custom error response handler.
// If fn is nil, the default JSON RFC 6750 handler is used.
func WithGinErrorHandler(fn ginErrorHandler) GinOption {
	return func(c *ginConfig) {
		if fn != nil {
			c.errorHandler = fn
		}
	}
}

// WithGinClaimsKey sets the gin context key for storing *Claims.
// Panics if key is empty.
func WithGinClaimsKey(key string) GinOption {
	if key == "" {
		panic("WithGinClaimsKey: key cannot be empty")
	}
	return func(c *ginConfig) {
		c.claimsKey = key
	}
}

// ginDefaultErrorHandler writes an RFC 6750 JSON error response.
// Sets WWW-Authenticate header on 401/403 per RFC 6750 Section 3.
// Header is set BEFORE AbortWithStatusJSON to ensure it is written.
func ginDefaultErrorHandler(c *gin.Context, statusCode int, errCode, errDesc string) {
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		c.Header("WWW-Authenticate",
			`Bearer realm="api", error="`+escapeQuotedString(errCode)+`", error_description="`+escapeQuotedString(errDesc)+`"`)
	}
	c.AbortWithStatusJSON(statusCode, errorResponse{
		Error:            errCode,
		ErrorDescription: errDesc,
	})
}

// GinBearerAuth returns gin middleware that validates Bearer tokens from the
// Authorization header using the provided TokenValidator.
//
// Claims are stored in gin context via c.Set(claimsKey, claims) and in the
// request's context.Context via ContextWithClaims for service-layer access.
//
// Panics if validator is nil (fail-fast at startup).
func GinBearerAuth(validator TokenValidator, opts ...GinOption) gin.HandlerFunc {
	if validator == nil {
		panic("GinBearerAuth: validator cannot be nil")
	}

	cfg := ginConfig{
		claimsKey:    "auth_claims",
		errorHandler: ginDefaultErrorHandler,
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

		if len(token) > MaxBearerTokenLength {
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
		enrichedCtx := ContextWithClaims(c.Request.Context(), claims)
		c.Request = c.Request.WithContext(enrichedCtx)
		c.Next()
	}
}

// GinScopeOption configures scope middleware behavior.
type GinScopeOption func(*ginScopeConfig)

type ginScopeConfig struct {
	claimsKey    string
	errorHandler ginErrorHandler
}

// WithGinScopeErrorHandler sets a custom error handler for scope middleware.
// If fn is nil, the default RFC 6750 JSON handler is used.
func WithGinScopeErrorHandler(fn ginErrorHandler) GinScopeOption {
	return func(c *ginScopeConfig) {
		if fn != nil {
			c.errorHandler = fn
		}
	}
}

// WithGinScopeClaimsKey overrides the gin context key for claims retrieval in scope middleware.
// Panics if key is empty.
func WithGinScopeClaimsKey(key string) GinScopeOption {
	if key == "" {
		panic("WithGinScopeClaimsKey: key cannot be empty")
	}
	return func(c *ginScopeConfig) {
		c.claimsKey = key
	}
}

// GinRequireScope returns gin middleware that checks the authenticated request
// has the exact required scope. Must be applied after GinBearerAuth.
//
// Returns 401 if no claims found, 403 if scope missing.
func GinRequireScope(scope string, opts ...GinScopeOption) gin.HandlerFunc {
	if scope == "" {
		panic("GinRequireScope: scope cannot be empty")
	}
	cfg := ginScopeConfig{
		claimsKey:    "auth_claims",
		errorHandler: ginDefaultErrorHandler,
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
		claims, ok := val.(*Claims)
		if !ok || claims == nil {
			cfg.errorHandler(c, http.StatusUnauthorized,
				"invalid_token", "Missing authentication context")
			c.Abort()
			return
		}

		if !HasScope(claims, scope) {
			cfg.errorHandler(c, http.StatusForbidden,
				"insufficient_scope", "Required scope: "+scope)
			c.Abort()
			return
		}

		c.Next()
	}
}

// GinRequireAnyScope returns gin middleware that checks the authenticated request
// has at least one of the required scopes. Must be applied after GinBearerAuth.
//
// The scopes slice is defensively copied at middleware creation time.
//
// Returns 401 if no claims found, 403 if none of the required scopes present.
func GinRequireAnyScope(scopes []string, opts ...GinScopeOption) gin.HandlerFunc {
	if len(scopes) == 0 {
		panic("GinRequireAnyScope: scopes cannot be empty")
	}
	cfg := ginScopeConfig{
		claimsKey:    "auth_claims",
		errorHandler: ginDefaultErrorHandler,
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
		claims, ok := val.(*Claims)
		if !ok || claims == nil {
			cfg.errorHandler(c, http.StatusUnauthorized,
				"invalid_token", "Missing authentication context")
			c.Abort()
			return
		}

		if !HasAnyScope(claims, scopesCopy...) {
			cfg.errorHandler(c, http.StatusForbidden,
				"insufficient_scope", "Required one of scopes: "+scopesDesc)
			c.Abort()
			return
		}

		c.Next()
	}
}

// GinNoopAuth returns gin middleware that injects default claims without
// token validation. For development and testing only.
//
// Each request receives a deep copy of defaultClaims to prevent shared-state
// mutation across concurrent requests.
//
// Claims are stored under the default key "auth_claims". If GinBearerAuth is
// configured with a custom WithGinClaimsKey, scope middleware must use
// WithGinScopeClaimsKey matching GinBearerAuth's key, not GinNoopAuth's default.
// The request context path (ClaimsFromContext) is always available
// regardless of gin key configuration and is the recommended service-layer path.
//
// Panics if defaultClaims is nil (fail-fast at configuration time).
func GinNoopAuth(defaultClaims *Claims) gin.HandlerFunc {
	if defaultClaims == nil {
		panic("GinNoopAuth: defaultClaims cannot be nil")
	}

	return func(c *gin.Context) {
		claims := defaultClaims.DeepCopy()
		c.Set("auth_claims", claims)
		enrichedCtx := ContextWithClaims(c.Request.Context(), claims)
		c.Request = c.Request.WithContext(enrichedCtx)
		c.Next()
	}
}

// GinNoopScope returns gin middleware that always passes through.
// For development and testing only, paired with GinNoopAuth.
func GinNoopScope() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}
