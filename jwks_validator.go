package authclient

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sort"

	"github.com/golang-jwt/jwt/v5"
)

// MaxBearerTokenLength is the maximum allowed length of a Bearer token string.
// Tokens exceeding this limit are rejected before parsing to prevent DoS.
const MaxBearerTokenLength = 4096

// allowedAlgorithms defines the single source of truth for acceptable signing algorithms.
// Only asymmetric RSA algorithms are accepted; symmetric (HMAC) and "none" are rejected.
// This map is read-only after package init — do not mutate at runtime.
var allowedAlgorithms = map[string]bool{
	"RS256": true,
	"RS384": true,
	"RS512": true,
}

// cachedAllowedAlgorithmsList is the deterministic sorted slice of allowed algorithms,
// computed once at package init from the allowedAlgorithms map.
var cachedAllowedAlgorithmsList []string

func init() {
	cachedAllowedAlgorithmsList = make([]string, 0, len(allowedAlgorithms))
	for alg := range allowedAlgorithms {
		cachedAllowedAlgorithmsList = append(cachedAllowedAlgorithmsList, alg)
	}
	sort.Strings(cachedAllowedAlgorithmsList)
}

// JWKSValidatorConfig holds the configuration for creating a JWKSValidator.
type JWKSValidatorConfig struct {
	// Issuer is the expected token issuer (iss claim).
	Issuer string
	// Audience is the expected token audience (aud claim). Optional.
	Audience []string
	// JWKS holds the JWKS provider configuration.
	JWKS JWKSConfig
}

// JWKSValidator validates JWT tokens using a JWKS-backed keyfunc.
// It implements TokenValidator and io.Closer.
type JWKSValidator struct {
	provider *JWKSProvider
	issuer   string
	audience []string
	logger   *slog.Logger
}

// Compile-time interface assertions.
var (
	_ TokenValidator = (*JWKSValidator)(nil)
	_ io.Closer      = (*JWKSValidator)(nil)
)

// NewJWKSValidator creates a new JWKSValidator that validates tokens locally using JWKS keys.
// It fetches JWKS keys at startup and fails fast if the endpoint is unreachable.
func NewJWKSValidator(ctx context.Context, cfg JWKSValidatorConfig, logger *slog.Logger) (*JWKSValidator, error) {
	if logger == nil {
		panic("authclient.NewJWKSValidator: logger cannot be nil")
	}

	if cfg.Issuer == "" {
		return nil, fmt.Errorf("authclient: issuer is required")
	}

	provider, err := NewJWKSProvider(ctx, cfg.JWKS, logger)
	if err != nil {
		return nil, fmt.Errorf("authclient: create JWKS validator: %w", err)
	}

	return &JWKSValidator{
		provider: provider,
		issuer:   cfg.Issuer,
		audience: cfg.Audience,
		logger:   logger,
	}, nil
}

// ValidateToken parses and validates a JWT token string, returning the extracted claims.
func (v *JWKSValidator) ValidateToken(_ context.Context, tokenString string) (*Claims, error) {
	if len(tokenString) > MaxBearerTokenLength {
		return nil, fmt.Errorf("authclient: validate token: %w", ErrTokenOversized)
	}

	claims := &Claims{}

	parserOpts := []jwt.ParserOption{
		jwt.WithIssuer(v.issuer),
		jwt.WithExpirationRequired(),
		jwt.WithValidMethods(cachedAllowedAlgorithmsList),
	}
	if len(v.audience) > 0 {
		parserOpts = append(parserOpts, jwt.WithAudience(v.audience...))
	}

	token, err := jwt.ParseWithClaims(tokenString, claims, v.provider.Keyfunc(), parserOpts...)
	if err != nil {
		return nil, fmt.Errorf("authclient: validate token: %w", classifyJWTError(err))
	}

	if !token.Valid {
		return nil, fmt.Errorf("authclient: validate token: %w", ErrTokenInvalid)
	}

	// Defense in depth: verify algorithm is in allowed set beyond WithValidMethods.
	// This branch is intentionally unreachable under normal operation — jwt.ParseWithClaims
	// with jwt.WithValidMethods rejects disallowed algorithms first. This guard exists as a
	// safety net against future jwt library behavioral changes.
	if !allowedAlgorithms[token.Method.Alg()] {
		return nil, fmt.Errorf("authclient: validate token: %w", ErrAlgorithmNotAllowed)
	}

	// Client UUID is mandatory — identifies the service or user context.
	if claims.ClientID == "" {
		return nil, fmt.Errorf("authclient: validate token: %w", ErrMissingClientID)
	}

	v.logger.Debug("token validated successfully",
		slog.String("client_id", claims.ClientID),
		slog.Int("scope_count", len(claims.Scopes)),
	)

	return claims, nil
}

// Close shuts down the underlying JWKS provider, stopping the background refresh goroutine.
func (v *JWKSValidator) Close() error {
	return v.provider.Close()
}
