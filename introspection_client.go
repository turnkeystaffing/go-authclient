package authclient

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Compile-time interface assertions.
var (
	_ TokenValidator = (*IntrospectionClient)(nil)
	_ Introspector   = (*IntrospectionClient)(nil)
	_ io.Closer      = (*IntrospectionClient)(nil)
)

// IntrospectionClientConfig holds configuration for the introspection client.
type IntrospectionClientConfig struct {
	// IntrospectionURL is the RFC 7662 introspection endpoint URL (required).
	IntrospectionURL string
	// ClientID for HTTP Basic Auth to the introspection endpoint.
	ClientID string
	// ClientSecret for HTTP Basic Auth to the introspection endpoint.
	ClientSecret string
	// Cache provides Redis cache operations. When nil, caching is disabled (noop).
	Cache IntrospectionCache
	// CacheTTL is the maximum cache duration for introspection responses.
	CacheTTL time.Duration
	// FallbackValidator is an optional TokenValidator (typically JWKSValidator) to use
	// when the introspection endpoint is unreachable (network errors only).
	FallbackValidator TokenValidator
	// HTTPTimeout is the timeout for introspection HTTP requests. Defaults to 10s.
	HTTPTimeout time.Duration
	// OTelHTTPTransport enables OpenTelemetry instrumentation on outbound HTTP requests.
	// When true, the internal http.Client transport is wrapped with otelhttp.NewTransport(),
	// which auto-traces HTTP requests with standard http.client.* spans and injects
	// W3C traceparent headers. Defaults to false (no instrumentation overhead).
	OTelHTTPTransport bool
}

const (
	defaultIntrospectHTTPTimeout = 10 * time.Second
	maxResponseBodySize          = 1 << 20 // 1 MB
)

// IntrospectionClient validates tokens via a remote RFC 7662 introspection endpoint
// with optional Redis caching and JWKS fallback.
type IntrospectionClient struct {
	httpClient       *http.Client
	introspectionURL string
	clientID         string
	clientSecret     string
	cache            IntrospectionCache
	cacheTTL         time.Duration
	fallback         TokenValidator
	logger           *slog.Logger
}

// NewIntrospectionClient creates a new IntrospectionClient.
// Panics if logger is nil or IntrospectionURL is empty (programming errors).
func NewIntrospectionClient(cfg IntrospectionClientConfig, logger *slog.Logger) *IntrospectionClient {
	if logger == nil {
		panic("authclient.NewIntrospectionClient: logger cannot be nil")
	}
	if cfg.IntrospectionURL == "" {
		panic("authclient.NewIntrospectionClient: IntrospectionURL cannot be empty")
	}
	if cfg.ClientID == "" {
		panic("authclient.NewIntrospectionClient: ClientID cannot be empty")
	}
	if cfg.ClientSecret == "" {
		panic("authclient.NewIntrospectionClient: ClientSecret cannot be empty")
	}

	cache := cfg.Cache
	if cache == nil {
		cache = noopIntrospectionCache{}
	}

	httpTimeout := cfg.HTTPTimeout
	if httpTimeout <= 0 {
		httpTimeout = defaultIntrospectHTTPTimeout
	}

	if u, err := url.Parse(cfg.IntrospectionURL); err == nil && u.Scheme != "https" {
		logger.Warn("introspection endpoint is not HTTPS — credentials sent in plaintext",
			slog.String("scheme", u.Scheme),
			slog.String("endpoint", sanitizeURL(cfg.IntrospectionURL)),
		)
	}

	logger.Info("introspection client initialized",
		slog.String("endpoint", sanitizeURL(cfg.IntrospectionURL)),
		slog.Duration("cache_ttl", cfg.CacheTTL),
		slog.Bool("fallback_configured", cfg.FallbackValidator != nil),
	)

	httpClient := &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			// RFC 7662 introspection never requires redirects.
			// Reject all redirects to prevent credential leakage on 307/308.
			return errors.New("authclient: introspect: redirects are not allowed")
		},
	}
	if cfg.OTelHTTPTransport {
		// otelhttp.NewTransport(nil) wraps http.DefaultTransport per its contract.
		httpClient.Transport = otelhttp.NewTransport(httpClient.Transport)
	}

	return &IntrospectionClient{
		httpClient:       httpClient,
		introspectionURL: cfg.IntrospectionURL,
		clientID:         cfg.ClientID,
		clientSecret:     cfg.ClientSecret,
		cache:            cache,
		cacheTTL:         cfg.CacheTTL,
		fallback:         cfg.FallbackValidator,
		logger:           logger,
	}
}

// Introspect validates a token via the remote introspection endpoint with caching.
func (c *IntrospectionClient) Introspect(ctx context.Context, token string) (*IntrospectionResponse, error) {
	if len(token) > MaxBearerTokenLength {
		return nil, fmt.Errorf("authclient: introspect: %w", ErrTokenOversized)
	}

	key := c.cacheKey(token)

	// Check cache first.
	result, err := c.cache.Get(ctx, key)
	if err != nil {
		c.logger.Warn("failed to read introspection cache", slog.String("error", err.Error()))
	}
	if err == nil && result.Hit {
		var resp IntrospectionResponse
		if unmarshalErr := json.Unmarshal([]byte(result.Value), &resp); unmarshalErr != nil {
			c.logger.Warn("failed to unmarshal cached introspection response", slog.String("error", unmarshalErr.Error()))
		} else {
			// Check if cached entry has expired.
			if resp.Exp > 0 && time.Now().Unix() >= resp.Exp {
				if _, delErr := c.cache.Del(ctx, key); delErr != nil {
					c.logger.Warn("failed to delete expired introspection cache entry", slog.String("error", delErr.Error()))
				}
			} else {
				c.logger.Debug("introspection cache hit", slog.String("sub", resp.Sub))
				return &resp, nil
			}
		}
	}

	// Cache miss — call remote endpoint.
	resp, err := c.callIntrospect(ctx, token)
	if err != nil {
		return nil, err
	}

	// Inactive tokens: delete stale cache entry, do NOT cache.
	if !resp.Active {
		if _, delErr := c.cache.Del(ctx, key); delErr != nil {
			c.logger.Warn("failed to delete inactive token cache entry", slog.String("error", delErr.Error()))
		}
		return resp, nil
	}

	// Cache active response with TTL = min(configured, remaining token lifetime).
	// When CacheTTL is 0 (unconfigured), use the token's remaining lifetime.
	ttl := c.cacheTTL
	if resp.Exp > 0 {
		remaining := time.Until(time.Unix(resp.Exp, 0))
		if ttl <= 0 || remaining < ttl {
			ttl = remaining
		}
	}
	if ttl > 0 {
		data, _ := json.Marshal(resp)
		if setErr := c.cache.Set(ctx, key, string(data), ttl); setErr != nil {
			c.logger.Warn("failed to cache introspection response", slog.String("error", setErr.Error()))
		}
	}

	return resp, nil
}

// callIntrospect performs the HTTP POST to the introspection endpoint.
func (c *IntrospectionClient) callIntrospect(ctx context.Context, token string) (*IntrospectionResponse, error) {
	form := url.Values{}
	form.Set("token", token)
	form.Set("token_type_hint", "access_token")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.introspectionURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("authclient: introspect: create request: %w", ErrIntrospectionRejected)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		// Network/transport error — wrap with root sentinel (no server response).
		return nil, fmt.Errorf("authclient: introspect: %w", ErrIntrospectionFailed)
	}
	defer httpResp.Body.Close()

	body, err := io.ReadAll(http.MaxBytesReader(nil, httpResp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("authclient: introspect: read response: %w", ErrIntrospectionParse)
	}

	if httpResp.StatusCode != http.StatusOK {
		c.logger.Debug("introspection endpoint non-200 response",
			slog.Int("status", httpResp.StatusCode),
			slog.Int("body_length", len(body)),
		)
		return nil, fmt.Errorf("authclient: introspect: endpoint returned %d: %w",
			httpResp.StatusCode, ErrIntrospectionRejected)
	}

	if len(body) == 0 {
		return nil, fmt.Errorf("authclient: introspect: %w", ErrIntrospectionParse)
	}

	var resp IntrospectionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("authclient: introspect: %w", ErrIntrospectionParse)
	}

	return &resp, nil
}

// cacheKey returns a Redis-safe cache key for the given token.
func (c *IntrospectionClient) cacheKey(token string) string {
	hash := sha256.Sum256([]byte(token))
	return fmt.Sprintf("introspect:%x", hash)
}

// ValidateToken validates a token via introspection and returns Claims.
// Implements the TokenValidator interface.
func (c *IntrospectionClient) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	resp, err := c.Introspect(ctx, token)
	if err != nil {
		// Check if this is a network/connection error and fallback is configured.
		if c.fallback != nil && isNetworkError(err) {
			c.logger.Warn("introspection endpoint unreachable, falling back to JWKS validation",
				slog.String("endpoint", sanitizeURL(c.introspectionURL)),
			)
			return c.fallback.ValidateToken(ctx, token)
		}
		return nil, err
	}

	if !resp.Active {
		return nil, fmt.Errorf("authclient: validate token: %w", ErrTokenInactive)
	}

	return ClaimsFromIntrospection(resp), nil
}

// Close is a no-op that satisfies io.Closer for parity with JWKSValidator.
func (c *IntrospectionClient) Close() error {
	return nil
}

// ClaimsFromIntrospection converts an IntrospectionResponse to Claims.
// Panics if resp is nil (precondition: resp is always non-nil from ValidateToken call chain;
// external callers must validate).
//
// This function does NOT check resp.Active. Callers must verify the token is active
// before calling — ValidateToken does this internally, but direct callers of this
// function must check Active themselves. Negative Exp values are treated as "no expiry"
// (ExpiresAt will be nil), same as zero.
//
// Note: ClientID is mapped from resp.ClientID without validation. Unlike
// JWKSValidator.ValidateToken, this function does not reject empty ClientID.
//
// Security: Email and Username are passed through from the introspection response
// without sanitization or format validation. See Claims type documentation.
func ClaimsFromIntrospection(resp *IntrospectionResponse) *Claims {
	if resp == nil {
		panic("ClaimsFromIntrospection: resp must not be nil")
	}
	claims := &Claims{
		ClientID: resp.ClientID,
		Scopes:   resp.Scopes(),
		UserID:   resp.Sub,
		Email:    resp.Email,
		Username: resp.Username,
	}
	claims.Subject = resp.Sub
	if resp.Exp > 0 {
		claims.ExpiresAt = jwtNumericDate(resp.Exp)
	}
	return claims
}

// jwtNumericDate creates a jwt.NumericDate from a Unix timestamp.
func jwtNumericDate(unix int64) *jwt.NumericDate {
	return jwt.NewNumericDate(time.Unix(unix, 0))
}

// isNetworkError checks if the error indicates a network/transport failure
// (endpoint unreachable) vs a server response (HTTP error, bad body).
// Fallback is ONLY triggered for network errors, NOT for HTTP error responses.
//
// Classification relies on the error hierarchy:
//   - ErrIntrospectionFailed (root)     → network/transport error → fallback OK
//   - ErrIntrospectionRejected (wraps root) → server responded with HTTP error → no fallback
//   - ErrIntrospectionParse (wraps root)    → server responded, bad body → no fallback
func isNetworkError(err error) bool {
	if !errors.Is(err, ErrIntrospectionFailed) {
		return false
	}
	// Server responded (HTTP error or bad body) — not a network error.
	if errors.Is(err, ErrIntrospectionRejected) || errors.Is(err, ErrIntrospectionParse) {
		return false
	}
	return true
}
