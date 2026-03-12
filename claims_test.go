package authclient

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaims_JSONRoundTrip(t *testing.T) {
	original := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Subject:   "test-subject",
			Audience:  jwt.ClaimStrings{"aud1", "aud2"},
			ExpiresAt: jwt.NewNumericDate(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)),
			IssuedAt:  jwt.NewNumericDate(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
		ClientID: "client-abc-123",
		Scopes:   []string{"read", "write"},
		UserID:   "user-456",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Claims
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.ClientID, decoded.ClientID)
	assert.Equal(t, original.Scopes, decoded.Scopes)
	assert.Equal(t, original.UserID, decoded.UserID)
	assert.Equal(t, original.Issuer, decoded.Issuer)
}

func TestClaims_JSONRoundTrip_WithEmailUsername(t *testing.T) {
	original := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-1",
		},
		ClientID: "client-abc",
		Scopes:   []string{"read"},
		Email:    "user@example.com",
		Username: "jdoe",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Claims
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Email, decoded.Email)
	assert.Equal(t, original.Username, decoded.Username)
}

func TestClaims_EmailUsername_OmitEmpty(t *testing.T) {
	c := &Claims{
		ClientID: "client-123",
		Scopes:   []string{"audit:write"},
	}

	data, err := json.Marshal(c)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.NotContains(t, jsonStr, "email")
	assert.NotContains(t, jsonStr, "username")
}

func TestClaims_OptionalUserID(t *testing.T) {
	c := &Claims{
		ClientID: "client-123",
		Scopes:   []string{"audit:write"},
	}

	data, err := json.Marshal(c)
	require.NoError(t, err)

	assert.NotContains(t, string(data), "user_id")
}

func TestClaims_JSONRoundTrip_WithGrantTypeAuthTime(t *testing.T) {
	original := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject: "user-1",
		},
		ClientID:  "client-abc",
		Scopes:    []string{"read"},
		GrantType: "client_credentials",
		AuthTime:  1710000000,
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded Claims
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)

	assert.Equal(t, "client_credentials", decoded.GrantType)
	assert.Equal(t, int64(1710000000), decoded.AuthTime)
}

func TestClaims_AuthenticatedWithin(t *testing.T) {
	t.Run("recent auth passes", func(t *testing.T) {
		c := &Claims{AuthTime: time.Now().Add(-2 * time.Minute).Unix()}
		assert.True(t, c.AuthenticatedWithin(5*time.Minute))
	})

	t.Run("stale auth fails", func(t *testing.T) {
		c := &Claims{AuthTime: time.Now().Add(-10 * time.Minute).Unix()}
		assert.False(t, c.AuthenticatedWithin(5*time.Minute))
	})

	t.Run("zero auth_time returns false", func(t *testing.T) {
		c := &Claims{}
		assert.False(t, c.AuthenticatedWithin(5*time.Minute))
	})

	t.Run("zero maxAge defaults to 15 minutes", func(t *testing.T) {
		c := &Claims{AuthTime: time.Now().Add(-10 * time.Minute).Unix()}
		assert.True(t, c.AuthenticatedWithin(0))

		c = &Claims{AuthTime: time.Now().Add(-20 * time.Minute).Unix()}
		assert.False(t, c.AuthenticatedWithin(0))
	})
}

func TestClaims_GrantTypeAuthTime_OmitEmpty(t *testing.T) {
	c := &Claims{
		ClientID: "client-123",
		Scopes:   []string{"audit:write"},
	}

	data, err := json.Marshal(c)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.NotContains(t, jsonStr, "gty")
	assert.NotContains(t, jsonStr, "auth_time")
}
