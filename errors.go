package authclient

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Sentinel errors for token validation.
var (
	ErrTokenOversized      = errors.New("token exceeds maximum allowed length")
	ErrTokenMalformed      = errors.New("token is malformed")
	ErrTokenExpired        = errors.New("token has expired")
	ErrTokenNotYetValid    = errors.New("token is not yet valid")
	ErrTokenUnverifiable   = errors.New("token signing method unknown or unverifiable")
	ErrTokenInvalid        = errors.New("token validation failed")
	ErrAlgorithmNotAllowed = errors.New("signing algorithm not allowed")
	ErrMissingClientID     = errors.New("missing client_id claim")

	// Introspection-specific errors (Story 6-2).
	// ErrIntrospectionFailed is the root sentinel for all introspection errors (network/transport).
	ErrIntrospectionFailed = errors.New("introspection request failed")
	// ErrIntrospectionRejected means the server responded with a non-200 HTTP status.
	ErrIntrospectionRejected = fmt.Errorf("introspection endpoint error: %w", ErrIntrospectionFailed)
	// ErrIntrospectionParse means the server responded but the body was empty or unparseable.
	ErrIntrospectionParse = fmt.Errorf("introspection parse error: %w", ErrIntrospectionFailed)

	ErrTokenInactive = fmt.Errorf("token is inactive: %w", ErrTokenInvalid)

	// Token provider errors (Story 6-8).
	ErrTokenProviderClosed = errors.New("token provider is closed")
)

// classifyJWTError maps golang-jwt/v5 internal errors to our sentinel errors.
func classifyJWTError(err error) error {
	switch {
	case errors.Is(err, jwt.ErrTokenMalformed):
		return ErrTokenMalformed
	case errors.Is(err, jwt.ErrTokenExpired):
		return ErrTokenExpired
	case errors.Is(err, jwt.ErrTokenNotValidYet):
		return ErrTokenNotYetValid
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return ErrTokenInvalid
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		return ErrTokenUnverifiable
	default:
		return ErrTokenInvalid
	}
}
