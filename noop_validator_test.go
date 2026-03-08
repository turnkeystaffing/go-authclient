package authclient

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewNoopValidator_NilClaimsPanics(t *testing.T) {
	assert.PanicsWithValue(t, "authclient.NewNoopValidator: defaultClaims cannot be nil", func() {
		NewNoopValidator(nil, testLogger())
	})
}

func TestNewNoopValidator_NilLoggerPanics(t *testing.T) {
	assert.PanicsWithValue(t, "authclient.NewNoopValidator: logger cannot be nil", func() {
		NewNoopValidator(&Claims{ClientID: "test"}, nil)
	})
}

func TestNoopValidator_ReturnsDefaultClaims(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "dev-client",
		Scopes:   []string{"admin"},
		UserID:   "dev-user",
	}

	v := NewNoopValidator(defaultClaims, testLogger())

	result, err := v.ValidateToken(context.Background(), "any-token-string")
	require.NoError(t, err)
	assert.Equal(t, defaultClaims.ClientID, result.ClientID)
	assert.Equal(t, defaultClaims.Scopes, result.Scopes)
	assert.Equal(t, defaultClaims.UserID, result.UserID)
}

func TestNoopValidator_IgnoresTokenString(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "test-client",
		Scopes:   []string{"read"},
	}

	v := NewNoopValidator(defaultClaims, testLogger())

	// Empty token
	result1, err := v.ValidateToken(context.Background(), "")
	require.NoError(t, err)
	assert.Equal(t, "test-client", result1.ClientID)

	// Garbage token
	result2, err := v.ValidateToken(context.Background(), "garbage.token.value")
	require.NoError(t, err)
	assert.Equal(t, "test-client", result2.ClientID)
}

func TestNoopValidator_ImplementsTokenValidator(t *testing.T) {
	defaultClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "dev-issuer",
		},
		ClientID: "dev-client",
	}

	var validator TokenValidator = NewNoopValidator(defaultClaims, testLogger())

	result, err := validator.ValidateToken(context.Background(), "token")
	require.NoError(t, err)
	assert.Equal(t, "dev-client", result.ClientID)
}

func TestNoopValidator_MutationSafety(t *testing.T) {
	defaultClaims := &Claims{
		ClientID: "dev-client",
		Scopes:   []string{"read"},
	}

	v := NewNoopValidator(defaultClaims, testLogger())

	// Get first result and mutate it
	result1, err := v.ValidateToken(context.Background(), "token1")
	require.NoError(t, err)
	result1.Scopes = append(result1.Scopes, "admin")
	result1.ClientID = "mutated"

	// Second call must return original values, not mutated ones
	result2, err := v.ValidateToken(context.Background(), "token2")
	require.NoError(t, err)
	assert.Equal(t, "dev-client", result2.ClientID)
	assert.Equal(t, []string{"read"}, result2.Scopes)
}

func TestNoopValidator_AudienceMutationSafety(t *testing.T) {
	defaultClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{"aud1", "aud2"},
		},
		ClientID: "dev-client",
		Scopes:   []string{"read"},
	}

	v := NewNoopValidator(defaultClaims, testLogger())

	// Get first result and mutate audience
	result1, err := v.ValidateToken(context.Background(), "token1")
	require.NoError(t, err)
	result1.Audience = append(result1.Audience, "injected-aud")

	// Second call must return original audience, not mutated
	result2, err := v.ValidateToken(context.Background(), "token2")
	require.NoError(t, err)
	assert.Equal(t, jwt.ClaimStrings{"aud1", "aud2"}, result2.Audience)
}

func TestNoopValidator_NumericDateMutationSafety(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	defaultClaims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
		ClientID: "dev-client",
		Scopes:   []string{"read"},
	}

	v := NewNoopValidator(defaultClaims, testLogger())

	// Get first result and mutate NumericDate pointers
	result1, err := v.ValidateToken(context.Background(), "token1")
	require.NoError(t, err)
	result1.ExpiresAt.Time = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	result1.IssuedAt.Time = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

	// Second call must return original timestamps, not mutated
	result2, err := v.ValidateToken(context.Background(), "token2")
	require.NoError(t, err)
	assert.True(t, result2.ExpiresAt.Time.Equal(now.Add(time.Hour)), "ExpiresAt should not be mutated")
	assert.True(t, result2.IssuedAt.Time.Equal(now), "IssuedAt should not be mutated")
	assert.True(t, result2.NotBefore.Time.Equal(now), "NotBefore should not be mutated")
}

func TestNoopValidator_Close(t *testing.T) {
	v := NewNoopValidator(&Claims{ClientID: "test"}, testLogger())

	// Verify io.Closer is implemented
	var closer io.Closer = v
	err := closer.Close()
	assert.NoError(t, err)
}
