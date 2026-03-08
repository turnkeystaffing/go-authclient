package authclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Compile-time interface assertions.
var (
	_ TokenProvider = (*OAuthTokenProvider)(nil)
	_ io.Closer     = (*OAuthTokenProvider)(nil)
	_ TokenProvider = (*StaticTokenProvider)(nil)
)

// OAuthTokenProviderConfig configures the OAuth client_credentials token provider.
type OAuthTokenProviderConfig struct {
	ClientID          string        // OAuth client ID (required)
	ClientSecret      string        // OAuth client secret (required)
	TokenURL          string        // Auth server token endpoint URL (required, must be http:// or https://)
	Scopes            string        // Space-separated OAuth scopes to request (optional)
	HTTPTimeout       time.Duration // HTTP request timeout (default: 10s)
	OTelHTTPTransport bool          // Enable OTel HTTP client instrumentation (default: false)
}

const (
	defaultTokenProviderHTTPTimeout = 10 * time.Second
	// maxExpiresIn is the maximum accepted expires_in value (1 year in seconds).
	// Prevents integer overflow in Duration multiplication and rejects unreasonably long-lived tokens.
	maxExpiresIn = 31536000
)

// DefaultOAuthTokenProviderConfig returns a config with sensible defaults.
// ClientID, ClientSecret, and TokenURL must be set by the caller.
func DefaultOAuthTokenProviderConfig() OAuthTokenProviderConfig {
	return OAuthTokenProviderConfig{
		HTTPTimeout: defaultTokenProviderHTTPTimeout,
	}
}

// Validate checks the config for errors.
// Zero/negative HTTPTimeout is clamped to 10s default.
func (c *OAuthTokenProviderConfig) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("authclient: token provider: client ID is required")
	}
	if c.ClientSecret == "" {
		return fmt.Errorf("authclient: token provider: client secret is required")
	}
	if c.TokenURL == "" {
		return fmt.Errorf("authclient: token provider: token URL is required")
	}

	parsed, err := url.Parse(c.TokenURL)
	if err != nil {
		return fmt.Errorf("authclient: token provider: invalid token URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("authclient: token provider: token URL scheme must be http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("authclient: token provider: token URL must include a host")
	}

	if c.HTTPTimeout <= 0 {
		c.HTTPTimeout = defaultTokenProviderHTTPTimeout
	}

	return nil
}

// oauthTokenProviderResponse is the wire format for OAuth 2.1 token response (RFC 6749 Section 5.1).
type oauthTokenProviderResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

// OAuthTokenProvider implements TokenProvider with in-memory caching, proactive refresh at 80% lifetime,
// and single-flight guard for async refresh. Thread-safe via sync.RWMutex.
type OAuthTokenProvider struct {
	client       *http.Client
	clientID     string
	clientSecret string
	tokenURL     string
	scopes       string
	httpTimeout  time.Duration
	log          *slog.Logger

	mu          sync.RWMutex
	accessToken string
	expiresAt   time.Time // absolute expiry
	refreshAt   time.Time // 80% of lifetime threshold
	refreshing  atomic.Bool
	closed      atomic.Bool

	// cancelRefresh cancels in-flight async refresh goroutines on Close().
	cancelRefresh context.CancelFunc
	refreshCtx    context.Context
}

// NewOAuthTokenProvider creates a new OAuth token provider implementing TokenProvider and io.Closer.
// Panics if logger is nil (fail-fast constructor pattern). Returns error for invalid config.
func NewOAuthTokenProvider(cfg OAuthTokenProviderConfig, logger *slog.Logger) (*OAuthTokenProvider, error) {
	if logger == nil {
		panic("authclient.NewOAuthTokenProvider: logger cannot be nil")
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	if strings.HasPrefix(cfg.TokenURL, "http://") {
		logger.Warn("authclient: token provider: token URL uses plaintext HTTP — credentials will be transmitted without TLS",
			"token_url", sanitizeURL(cfg.TokenURL))
	}

	// Redirect rejection via custom error (matching introspection_client.go pattern).
	// Intentionally differs from pkg/audit/token_cache.go which uses http.ErrUseLastResponse —
	// custom error causes client.Do() to fail immediately, preventing processing of redirect responses.
	httpClient := &http.Client{
		Timeout: cfg.HTTPTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("authclient: token provider: redirects are not allowed")
		},
	}
	if cfg.OTelHTTPTransport {
		// nil transport defaults to http.DefaultTransport per otelhttp contract
		httpClient.Transport = otelhttp.NewTransport(httpClient.Transport)
	}

	logger.Info("authclient: token provider initialized",
		"token_url", sanitizeURL(cfg.TokenURL),
		"otel_transport", cfg.OTelHTTPTransport)

	refreshCtx, cancelRefresh := context.WithCancel(context.Background())

	return &OAuthTokenProvider{
		client:        httpClient,
		clientID:      cfg.ClientID,
		clientSecret:  cfg.ClientSecret,
		tokenURL:      cfg.TokenURL,
		scopes:        cfg.Scopes,
		httpTimeout:   cfg.HTTPTimeout,
		log:           logger,
		refreshCtx:    refreshCtx,
		cancelRefresh: cancelRefresh,
	}, nil
}

// Token returns a valid Bearer token. Safe for concurrent use.
// Uses cached token when valid, proactive refresh at 80% lifetime,
// and synchronous fetch with double-checked locking when expired.
func (p *OAuthTokenProvider) Token(ctx context.Context) (string, error) {
	if p.closed.Load() {
		return "", ErrTokenProviderClosed
	}

	// Fast path: read lock — check cached token
	p.mu.RLock()
	token := p.accessToken
	now := time.Now()
	hasToken := token != ""
	expired := !now.Before(p.expiresAt)
	needsRefresh := hasToken && !expired && !now.Before(p.refreshAt)
	p.mu.RUnlock()

	// Valid token, not yet at refresh threshold
	if hasToken && !expired && !needsRefresh {
		return token, nil
	}

	// Valid token but past refresh threshold — trigger async refresh, return cached
	if hasToken && !expired && needsRefresh {
		p.triggerAsyncRefresh()
		return token, nil
	}

	// Expired or no token — synchronous fetch with double-checked locking.
	// The write lock is held during the HTTP call intentionally: this prevents
	// thundering herd (multiple goroutines fetching simultaneously when expired).
	// Concurrent callers block on the lock, then hit the re-check and return the
	// freshly cached token without making additional HTTP requests.
	p.mu.Lock()
	// Re-check: another goroutine may have fetched while we waited for write lock
	if p.accessToken != "" && time.Now().Before(p.expiresAt) {
		token = p.accessToken
		p.mu.Unlock()
		return token, nil
	}
	token, err := p.fetchToken(ctx)
	p.mu.Unlock()
	return token, err
}

// fetchToken performs the OAuth client_credentials grant and stores the result.
// MUST be called with p.mu write lock held.
func (p *OAuthTokenProvider) fetchToken(ctx context.Context) (string, error) {
	tokenResp, err := p.doTokenRequest(ctx)
	if err != nil {
		return "", err
	}
	p.storeTokenData(tokenResp)
	return tokenResp.AccessToken, nil
}

// doTokenRequest performs the HTTP POST to the token endpoint and validates the response.
// Lock-free — does NOT touch cache fields.
func (p *OAuthTokenProvider) doTokenRequest(ctx context.Context) (*oauthTokenProviderResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if p.scopes != "" {
		form.Set("scope", p.scopes)
	}
	body := form.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("authclient: token provider: request creation error: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// RFC 6749 Section 2.3.1: percent-encode client credentials before Basic Auth encoding.
	// This ensures ClientID/ClientSecret containing special characters (e.g., `:`) are handled correctly.
	encodedID := url.QueryEscape(p.clientID)
	encodedSecret := url.QueryEscape(p.clientSecret)
	credentials := base64.StdEncoding.EncodeToString([]byte(encodedID + ":" + encodedSecret))
	req.Header.Set("Authorization", "Basic "+credentials)

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authclient: token provider: network error: %w", err)
	}
	defer resp.Body.Close()

	// Bounded read (G18: reuse maxResponseBodySize from introspection_client.go)
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodySize))
	if err != nil {
		return nil, fmt.Errorf("authclient: token provider: error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// G10: do NOT echo response body — include only status code
		return nil, fmt.Errorf("authclient: token provider: token request failed with status %d", resp.StatusCode)
	}

	var tokenResp oauthTokenProviderResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		// G10: do not chain JSON error (may contain partial response content)
		return nil, fmt.Errorf("authclient: token provider: invalid token response format")
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("authclient: token provider: empty access_token in response")
	}

	// G20: validate token_type is "Bearer" (case-insensitive per OAuth 2.1)
	// G10: do NOT echo server-provided token_type value in error — it is response body data
	if !strings.EqualFold(tokenResp.TokenType, "Bearer") {
		return nil, fmt.Errorf("authclient: token provider: unsupported token_type, expected Bearer")
	}

	// G16: validate expires_in > 0
	if tokenResp.ExpiresIn <= 0 {
		return nil, fmt.Errorf("authclient: token provider: invalid expires_in %d, must be positive", tokenResp.ExpiresIn)
	}

	// Reject unreasonably large expires_in to prevent Duration overflow (DoS via cache thrashing)
	if tokenResp.ExpiresIn > maxExpiresIn {
		return nil, fmt.Errorf("authclient: token provider: expires_in %d exceeds maximum %d", tokenResp.ExpiresIn, maxExpiresIn)
	}

	if tokenResp.ExpiresIn > 86400 {
		p.log.Warn("authclient: token provider: token lifetime exceeds 24 hours — verify auth server configuration",
			"expires_in", tokenResp.ExpiresIn)
	}

	// Log warning if granted scope differs from requested scope.
	// Scopes are space-separated sets where order is irrelevant per RFC 6749 Section 3.3.
	if p.scopes != "" && tokenResp.Scope != "" && !scopeSetsEqual(p.scopes, tokenResp.Scope) {
		p.log.Warn("authclient: token provider: granted scope differs from requested",
			"requested", p.scopes,
			"granted", tokenResp.Scope)
	}

	return &tokenResp, nil
}

// storeTokenData stores a validated token response into the cache fields.
// MUST be called with p.mu write lock held.
func (p *OAuthTokenProvider) storeTokenData(tokenResp *oauthTokenProviderResponse) {
	now := time.Now()
	lifetime := time.Duration(tokenResp.ExpiresIn) * time.Second
	p.accessToken = tokenResp.AccessToken
	p.expiresAt = now.Add(lifetime)
	p.refreshAt = now.Add(lifetime * 4 / 5)

	// G11: NEVER log token value
	logScope := tokenResp.Scope
	if len(logScope) > 256 {
		logScope = logScope[:256] + "...(truncated)"
	}
	p.log.Info("authclient: token provider: token obtained",
		"expires_in", tokenResp.ExpiresIn,
		"scope", logScope)
}

// triggerAsyncRefresh starts a background goroutine to refresh the token.
// Uses atomic.Bool CAS as single-flight guard.
func (p *OAuthTokenProvider) triggerAsyncRefresh() {
	if !p.refreshing.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer p.refreshing.Store(false)
		defer func() {
			if r := recover(); r != nil {
				p.log.Error("authclient: token provider: panic in async refresh", "panic", r)
			}
		}()

		// Use provider's refreshCtx as parent so Close() can cancel in-flight HTTP requests.
		// This differs from pkg/audit/token_cache.go which uses context.Background() directly —
		// the cancellable context ensures goroutines terminate promptly on Close().
		ctx, cancel := context.WithTimeout(p.refreshCtx, p.httpTimeout)
		defer cancel()

		tokenResp, err := p.doTokenRequest(ctx)
		if err != nil {
			p.log.Warn("authclient: token provider: proactive refresh failed", "error", err)
			return
		}

		p.mu.Lock()
		// Check closed under lock to prevent TOCTOU write-after-close race.
		// NOTE: This intentionally checks closed INSIDE the lock, unlike pkg/audit/token_cache.go
		// (lines 293-301) which checks OUTSIDE the lock. Checking inside prevents the race where
		// Close() executes between the check and lock acquisition. A future "align with reference"
		// refactor must NOT move this check outside the lock.
		if p.closed.Load() {
			p.mu.Unlock()
			return
		}
		p.storeTokenData(tokenResp)
		p.mu.Unlock()
	}()
}

// Close stops the token provider. Subsequent Token() calls return ErrTokenProviderClosed.
// Cancels in-flight async refresh goroutines, clears cached token and timestamps to allow GC. Idempotent.
func (p *OAuthTokenProvider) Close() error {
	p.closed.Store(true)
	// Cancel in-flight async refresh goroutines so they terminate promptly
	p.cancelRefresh()
	p.mu.Lock()
	p.accessToken = ""
	p.expiresAt = time.Time{}
	p.refreshAt = time.Time{}
	p.mu.Unlock()
	p.client.CloseIdleConnections()
	p.log.Info("authclient: token provider: closed")
	return nil
}

// scopeSetsEqual compares two space-separated scope strings as unordered sets
// per RFC 6749 Section 3.3. "read write" and "write read" are considered equal.
func scopeSetsEqual(a, b string) bool {
	as := strings.Fields(a)
	bs := strings.Fields(b)
	if len(as) != len(bs) {
		return false
	}
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}

// StaticTokenProvider returns a fixed token string on every call.
// Useful for testing and scenarios where tokens are managed externally.
type StaticTokenProvider struct {
	token string
}

// NewStaticTokenProvider creates a TokenProvider that always returns the given token.
func NewStaticTokenProvider(token string) *StaticTokenProvider {
	return &StaticTokenProvider{token: token}
}

// Token returns the static token.
func (p *StaticTokenProvider) Token(_ context.Context) (string, error) {
	return p.token, nil
}
