package authclient

import "context"

// mockTokenValidator is a test double for TokenValidator.
// Set ValidateTokenFunc to control the behavior per test.
type mockTokenValidator struct {
	ValidateTokenFunc func(ctx context.Context, token string) (*Claims, error)
}

func (m *mockTokenValidator) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	return m.ValidateTokenFunc(ctx, token)
}
