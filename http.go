package authclient

import (
	"encoding/json"
	"net/http"
	"strings"
)

// httpErrorHandler is the function signature for custom error response writers
// used by both BearerAuth and scope net/http middleware.
type httpErrorHandler func(w http.ResponseWriter, r *http.Request, statusCode int, errCode, errDesc string)

// httpConfig holds configuration for the HTTPBearerAuth middleware.
type httpConfig struct {
	errorHandler httpErrorHandler
}

// HTTPOption configures the HTTPBearerAuth middleware.
type HTTPOption func(*httpConfig)

// WithHTTPErrorHandler sets a custom error response handler with signature
// func(w http.ResponseWriter, r *http.Request, statusCode int, errCode, errDesc string).
// If fn is nil, the default JSON RFC 6750 handler is used.
func WithHTTPErrorHandler(fn httpErrorHandler) HTTPOption {
	return func(c *httpConfig) {
		if fn != nil {
			c.errorHandler = fn
		}
	}
}

// defaultHTTPErrorHandler writes an RFC 6750 JSON error response.
// For 401 responses, sets WWW-Authenticate header per RFC 6750 Section 3.
// For 403 responses, sets WWW-Authenticate with error and scope info.
func defaultHTTPErrorHandler(w http.ResponseWriter, _ *http.Request, statusCode int, errCode, errDesc string) {
	w.Header().Set("Content-Type", "application/json")
	if statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden {
		w.Header().Set("WWW-Authenticate",
			`Bearer realm="api", error="`+escapeQuotedString(errCode)+`", error_description="`+escapeQuotedString(errDesc)+`"`)
	}
	w.WriteHeader(statusCode)
	body, err := json.Marshal(errorResponse{
		Error:            errCode,
		ErrorDescription: errDesc,
	})
	if err != nil {
		_, _ = w.Write([]byte(`{"error":"server_error","error_description":"Internal error"}`))
		return
	}
	_, _ = w.Write(body)
}

// HTTPBearerAuth returns middleware that validates Bearer tokens from the
// Authorization header using the provided TokenValidator and stores the resulting
// *Claims in the request context via ContextWithClaims.
//
// Claims are retrievable downstream via ClaimsFromContext(r.Context()).
//
// Panics if validator is nil (fail-fast at startup, not per-request).
func HTTPBearerAuth(validator TokenValidator, opts ...HTTPOption) func(http.Handler) http.Handler {
	if validator == nil {
		panic("HTTPBearerAuth: validator cannot be nil")
	}

	cfg := httpConfig{
		errorHandler: defaultHTTPErrorHandler,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				cfg.errorHandler(w, r, http.StatusUnauthorized,
					"invalid_request", "Missing authorization header")
				return
			}

			if len(authHeader) < 7 || !strings.EqualFold(authHeader[:7], "Bearer ") {
				cfg.errorHandler(w, r, http.StatusUnauthorized,
					"invalid_request", "Invalid authorization header format")
				return
			}

			token := strings.TrimSpace(authHeader[7:])
			if token == "" {
				cfg.errorHandler(w, r, http.StatusUnauthorized,
					"invalid_request", "Empty bearer token")
				return
			}

			if len(token) > MaxBearerTokenLength {
				cfg.errorHandler(w, r, http.StatusUnauthorized,
					"invalid_request", "Bearer token exceeds maximum length")
				return
			}

			claims, err := validator.ValidateToken(r.Context(), token)
			if err != nil || claims == nil {
				cfg.errorHandler(w, r, http.StatusUnauthorized,
					"invalid_token", "Token validation failed")
				return
			}

			enrichedCtx := ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(enrichedCtx))
		})
	}
}

// HTTPScopeOption configures scope middleware behavior.
type HTTPScopeOption func(*httpScopeConfig)

type httpScopeConfig struct {
	errorHandler httpErrorHandler
}

// WithHTTPScopeErrorHandler sets a custom error handler for scope middleware.
// If fn is nil, the default RFC 6750 JSON handler is used.
func WithHTTPScopeErrorHandler(fn httpErrorHandler) HTTPScopeOption {
	return func(c *httpScopeConfig) {
		if fn != nil {
			c.errorHandler = fn
		}
	}
}

// HTTPRequireScope returns middleware that checks the authenticated request
// has the exact required scope. Must be applied after HTTPBearerAuth.
//
// Returns 401 if no claims are found (HTTPBearerAuth not applied or failed).
// Returns 403 if the required scope is missing.
func HTTPRequireScope(scope string, opts ...HTTPScopeOption) func(http.Handler) http.Handler {
	if scope == "" {
		panic("HTTPRequireScope: scope cannot be empty")
	}
	cfg := httpScopeConfig{errorHandler: defaultHTTPErrorHandler}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || claims == nil {
				cfg.errorHandler(w, r, http.StatusUnauthorized,
					"invalid_token", "Missing authentication context")
				return
			}

			if !HasScope(claims, scope) {
				cfg.errorHandler(w, r, http.StatusForbidden,
					"insufficient_scope", "Required scope: "+scope)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HTTPRequireAnyScope returns middleware that checks the authenticated request
// has at least one of the required scopes. Must be applied after HTTPBearerAuth.
//
// The scopes slice is defensively copied at middleware creation time.
//
// Returns 401 if no claims are found (HTTPBearerAuth not applied or failed).
// Returns 403 if none of the required scopes are present.
func HTTPRequireAnyScope(scopes []string, opts ...HTTPScopeOption) func(http.Handler) http.Handler {
	if len(scopes) == 0 {
		panic("HTTPRequireAnyScope: scopes cannot be empty")
	}
	cfg := httpScopeConfig{errorHandler: defaultHTTPErrorHandler}
	for _, opt := range opts {
		opt(&cfg)
	}

	scopesCopy := make([]string, len(scopes))
	copy(scopesCopy, scopes)
	scopesDesc := strings.Join(scopesCopy, ", ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || claims == nil {
				cfg.errorHandler(w, r, http.StatusUnauthorized,
					"invalid_token", "Missing authentication context")
				return
			}

			if !HasAnyScope(claims, scopesCopy...) {
				cfg.errorHandler(w, r, http.StatusForbidden,
					"insufficient_scope", "Required one of scopes: "+scopesDesc)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HTTPRequireScopeWildcard returns middleware that checks the authenticated request
// has a scope matching the required scope using wildcard matching.
// Must be applied after HTTPBearerAuth.
//
// Unlike HTTPRequireScope (exact match only), this supports wildcard patterns:
// a user with "bgc:*" will satisfy a requirement for "bgc:contractors:read".
//
// Returns 401 if no claims are found (HTTPBearerAuth not applied or failed).
// Returns 403 if the required scope is not matched.
func HTTPRequireScopeWildcard(scope string, opts ...HTTPScopeOption) func(http.Handler) http.Handler {
	if scope == "" {
		panic("HTTPRequireScopeWildcard: scope cannot be empty")
	}
	cfg := httpScopeConfig{errorHandler: defaultHTTPErrorHandler}
	for _, opt := range opts {
		opt(&cfg)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || claims == nil {
				cfg.errorHandler(w, r, http.StatusUnauthorized,
					"invalid_token", "Missing authentication context")
				return
			}

			if !HasScopeWildcard(claims, scope) {
				cfg.errorHandler(w, r, http.StatusForbidden,
					"insufficient_scope", "Required scope: "+scope)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HTTPRequireAnyScopeWildcard returns middleware that checks the authenticated request
// has at least one scope matching any of the required scopes using wildcard matching.
// Must be applied after HTTPBearerAuth.
//
// The scopes slice is defensively copied at middleware creation time.
//
// Returns 401 if no claims are found (HTTPBearerAuth not applied or failed).
// Returns 403 if none of the required scopes are matched.
func HTTPRequireAnyScopeWildcard(scopes []string, opts ...HTTPScopeOption) func(http.Handler) http.Handler {
	if len(scopes) == 0 {
		panic("HTTPRequireAnyScopeWildcard: scopes cannot be empty")
	}
	cfg := httpScopeConfig{errorHandler: defaultHTTPErrorHandler}
	for _, opt := range opts {
		opt(&cfg)
	}

	scopesCopy := make([]string, len(scopes))
	copy(scopesCopy, scopes)
	scopesDesc := strings.Join(scopesCopy, ", ")

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, ok := ClaimsFromContext(r.Context())
			if !ok || claims == nil {
				cfg.errorHandler(w, r, http.StatusUnauthorized,
					"invalid_token", "Missing authentication context")
				return
			}

			if !HasAnyScopeWildcard(claims, scopesCopy...) {
				cfg.errorHandler(w, r, http.StatusForbidden,
					"insufficient_scope", "Required one of scopes: "+scopesDesc)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HTTPNoopAuth returns middleware that injects default claims without
// token validation. For development and testing only.
//
// Each request receives a deep copy of defaultClaims to prevent shared-state
// mutation across concurrent requests.
//
// Panics if defaultClaims is nil (fail-fast at configuration time).
func HTTPNoopAuth(defaultClaims *Claims) func(http.Handler) http.Handler {
	if defaultClaims == nil {
		panic("HTTPNoopAuth: defaultClaims cannot be nil")
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := defaultClaims.DeepCopy()
			enrichedCtx := ContextWithClaims(r.Context(), claims)
			next.ServeHTTP(w, r.WithContext(enrichedCtx))
		})
	}
}

// HTTPNoopScope returns scope middleware that always passes through.
// For development and testing only, paired with HTTPNoopAuth.
func HTTPNoopScope() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return next
	}
}
