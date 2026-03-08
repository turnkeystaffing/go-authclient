package authclient

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"time"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/time/rate"
)

// Compile-time interface assertion.
var _ io.Closer = (*JWKSProvider)(nil)

// JWKSConfig holds the configuration for a JWKS provider.
type JWKSConfig struct {
	// Endpoint is the URL of the JWKS endpoint (required).
	Endpoint string
	// RefreshInterval is how often keys are refreshed in the background.
	// Defaults to 5 minutes if zero.
	RefreshInterval time.Duration
	// HTTPTimeout is the timeout for JWKS HTTP requests.
	// Defaults to 10 seconds if zero.
	HTTPTimeout time.Duration
}

const (
	defaultRefreshInterval = 5 * time.Minute
	defaultHTTPTimeout     = 10 * time.Second
)

// JWKSProvider manages JWKS key fetching and caching via keyfunc/v3.
// The background refresh goroutine is stopped by calling Close().
type JWKSProvider struct {
	kf     keyfunc.Keyfunc // keyfunc/v3 JWKS interface providing jwt.Keyfunc for token parsing
	cancel context.CancelFunc
	logger *slog.Logger
}

// NewJWKSProvider creates a JWKS provider that fetches and caches keys from the given endpoint.
// It fails fast if the endpoint is unreachable at startup.
// The background refresh goroutine is stopped by calling Close() or cancelling ctx.
func NewJWKSProvider(ctx context.Context, cfg JWKSConfig, logger *slog.Logger) (*JWKSProvider, error) {
	if logger == nil {
		panic("authclient.NewJWKSProvider: logger cannot be nil")
	}

	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("authclient: JWKS endpoint is required")
	}

	// Warn if JWKS endpoint is not HTTPS — keys fetched over HTTP are vulnerable to MITM.
	if u, err := url.Parse(cfg.Endpoint); err == nil && u.Scheme != "https" {
		logger.Warn("JWKS endpoint is not HTTPS — keys may be intercepted",
			slog.String("scheme", u.Scheme),
			slog.String("endpoint", sanitizeURL(cfg.Endpoint)),
		)
	}

	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = defaultRefreshInterval
	}
	if cfg.HTTPTimeout <= 0 {
		cfg.HTTPTimeout = defaultHTTPTimeout
	}

	logger.Info("initializing JWKS provider",
		slog.String("endpoint", sanitizeURL(cfg.Endpoint)),
		slog.Duration("refresh_interval", cfg.RefreshInterval),
	)

	childCtx, cancel := context.WithCancel(ctx)

	// NoErrorReturnFirstHTTPReq=false ensures startup fails fast if the JWKS
	// endpoint is unreachable.
	noError := false

	kf, err := keyfunc.NewDefaultOverrideCtx(childCtx, []string{cfg.Endpoint}, keyfunc.Override{
		RefreshInterval:           cfg.RefreshInterval,
		HTTPTimeout:               cfg.HTTPTimeout,
		RateLimitWaitMax:          30 * time.Second,
		NoErrorReturnFirstHTTPReq: &noError,
		RefreshUnknownKID:         rate.NewLimiter(rate.Every(time.Minute), 1),
		RefreshErrorHandlerFunc: func(u string) func(ctx context.Context, err error) {
			safeURL := sanitizeURL(u)
			return func(_ context.Context, _ error) {
				logger.Error("JWKS refresh failed",
					slog.String("url", safeURL),
				)
			}
		},
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("authclient: create JWKS provider: %w", err)
	}

	logger.Info("JWKS provider initialized successfully")

	return &JWKSProvider{
		kf:     kf,
		cancel: cancel,
		logger: logger,
	}, nil
}

// Keyfunc returns the jwt.Keyfunc for use in JWT token parsing.
func (p *JWKSProvider) Keyfunc() jwt.Keyfunc {
	return p.kf.Keyfunc
}

// Close shuts down the JWKS provider, stopping the background refresh goroutine.
func (p *JWKSProvider) Close() error {
	p.logger.Info("shutting down JWKS provider")
	p.cancel()
	return nil
}

// sanitizeURL strips credentials and query parameters from a URL for safe logging.
func sanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "<invalid-url>"
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
