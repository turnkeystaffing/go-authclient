package authclient

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClaimsFromIntrospection_AllFieldsPopulated(t *testing.T) {
	resp := &IntrospectionResponse{
		Active:   true,
		Sub:      "user-123",
		Scope:    "read write admin",
		Email:    "user@example.com",
		Username: "jdoe",
		ClientID: "client-abc",
		Exp:      time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC).Unix(),
	}

	claims := ClaimsFromIntrospection(resp)

	assert.Equal(t, "client-abc", claims.ClientID)
	assert.Equal(t, "user-123", claims.Subject)
	assert.Equal(t, "user-123", claims.UserID)
	assert.Equal(t, []string{"read", "write", "admin"}, claims.Scopes)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.Equal(t, "jdoe", claims.Username)
	require.NotNil(t, claims.ExpiresAt)
	assert.Equal(t, resp.Exp, claims.ExpiresAt.Unix())
}

func TestClaimsFromIntrospection_ZeroExp(t *testing.T) {
	resp := &IntrospectionResponse{
		Active:   true,
		Sub:      "user-1",
		ClientID: "client-1",
		Exp:      0,
	}

	claims := ClaimsFromIntrospection(resp)

	assert.Nil(t, claims.ExpiresAt)
}

func TestClaimsFromIntrospection_EmptyScope(t *testing.T) {
	resp := &IntrospectionResponse{
		Active:   true,
		Sub:      "user-1",
		ClientID: "client-1",
		Scope:    "",
	}

	claims := ClaimsFromIntrospection(resp)

	assert.Nil(t, claims.Scopes)
}

func TestClaimsFromIntrospection_EmailUsernamePresent(t *testing.T) {
	resp := &IntrospectionResponse{
		Active:   true,
		Sub:      "user-1",
		ClientID: "client-1",
		Email:    "test@test.com",
		Username: "testuser",
	}

	claims := ClaimsFromIntrospection(resp)

	assert.Equal(t, "test@test.com", claims.Email)
	assert.Equal(t, "testuser", claims.Username)
}

func TestClaimsFromIntrospection_EmailUsernameAbsent(t *testing.T) {
	resp := &IntrospectionResponse{
		Active:   true,
		Sub:      "user-1",
		ClientID: "client-1",
	}

	claims := ClaimsFromIntrospection(resp)

	assert.Empty(t, claims.Email)
	assert.Empty(t, claims.Username)
}

func TestClaimsFromIntrospection_IssuerNotSet(t *testing.T) {
	resp := &IntrospectionResponse{
		Active:   true,
		Sub:      "user-1",
		ClientID: "client-1",
		Scope:    "read",
	}

	claims := ClaimsFromIntrospection(resp)

	// Issuer is intentionally NOT set — introspection responses have no "iss" field.
	// The introspection endpoint itself IS the authority.
	assert.Empty(t, claims.Issuer)
}

func TestClaimsFromIntrospection_ScopeCheckerIntegration(t *testing.T) {
	resp := &IntrospectionResponse{
		Active:   true,
		Sub:      "user-1",
		ClientID: "client-1",
		Scope:    "read write admin",
	}

	claims := ClaimsFromIntrospection(resp)

	assert.True(t, HasScope(claims, "read"))
	assert.True(t, HasScope(claims, "admin"))
	assert.False(t, HasScope(claims, "delete"))
	assert.True(t, HasAnyScope(claims, "delete", "write"))
}

func TestClaimsFromIntrospection_WhitespaceOnlyScope(t *testing.T) {
	resp := &IntrospectionResponse{
		Active:   true,
		Sub:      "user-1",
		ClientID: "client-1",
		Scope:    "   ",
	}

	claims := ClaimsFromIntrospection(resp)

	// strings.Split("   ", " ") produces 4 elements (N+1 for N delimiters):
	// ["", "", "", ""]. HasAnyScope skips empty strings, so no scope matches.
	assert.Equal(t, []string{"", "", "", ""}, claims.Scopes)
	assert.False(t, HasAnyScope(claims, "read"))
	assert.False(t, HasScope(claims, ""))
}

func TestClaimsFromIntrospection_NegativeExp(t *testing.T) {
	resp := &IntrospectionResponse{
		Active:   true,
		Sub:      "user-1",
		ClientID: "client-1",
		Exp:      -100,
	}

	claims := ClaimsFromIntrospection(resp)

	// Negative Exp is treated as "no expiry", same as zero.
	assert.Nil(t, claims.ExpiresAt)
}

func TestClaimsFromIntrospection_NilResponse_Panics(t *testing.T) {
	assert.PanicsWithValue(t, "ClaimsFromIntrospection: resp must not be nil", func() {
		ClaimsFromIntrospection(nil)
	})
}
