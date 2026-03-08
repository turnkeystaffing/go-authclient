package authclient

import (
	"context"
	"io"
	"log/slog"
)

// NoopValidator is a TokenValidator that skips validation and returns
// pre-configured default claims. Use for development and testing only.
type NoopValidator struct {
	defaultClaims *Claims
}

// Compile-time interface assertions.
var (
	_ TokenValidator = (*NoopValidator)(nil)
	_ io.Closer      = (*NoopValidator)(nil)
)

// NewNoopValidator creates a NoopValidator that returns defaultClaims on every call.
// WARNING: This validator accepts ALL tokens without verification. It must only be
// used in development or testing environments.
func NewNoopValidator(defaultClaims *Claims, logger *slog.Logger) *NoopValidator {
	if defaultClaims == nil {
		panic("authclient.NewNoopValidator: defaultClaims cannot be nil")
	}
	if logger == nil {
		panic("authclient.NewNoopValidator: logger cannot be nil")
	}
	logger.Warn("authclient: NoopValidator active — all tokens accepted without validation")
	return &NoopValidator{defaultClaims: defaultClaims}
}

// ValidateToken returns a deep copy of the configured default claims, ignoring the token string.
func (v *NoopValidator) ValidateToken(_ context.Context, _ string) (*Claims, error) {
	return v.defaultClaims.DeepCopy(), nil
}

// Close is a no-op that satisfies io.Closer for parity with JWKSValidator.
func (v *NoopValidator) Close() error {
	return nil
}
