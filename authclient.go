// Package authclient provides framework-agnostic OAuth token validation
// and token acquisition for Go services. It supports local JWKS-based JWT
// validation with background key refresh, RFC 7662 token introspection with
// Redis caching, scope-based authorization checking, context propagation
// helpers, and OAuth client_credentials token acquisition with proactive refresh.
//
// Import: github.com/turnkeystaffing/go-authclient
package authclient

import "context"

// TokenValidator validates bearer tokens and returns claims.
// Returned errors can be classified using errors.Is with the following sentinel errors:
// ErrTokenOversized, ErrTokenMalformed, ErrTokenExpired, ErrTokenNotYetValid,
// ErrTokenUnverifiable, ErrTokenInvalid, ErrAlgorithmNotAllowed, ErrMissingClientID.
type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (*Claims, error)
}

// TokenProvider obtains bearer tokens for outbound API authentication.
// Implementations must be safe for concurrent use.
type TokenProvider interface {
	Token(ctx context.Context) (string, error)
}
