package authclient

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ExampleClaimsFromContext() {
	claims := &Claims{ClientID: "service-abc", Scopes: []string{"read"}}
	ctx := ContextWithClaims(context.Background(), claims)

	got, ok := ClaimsFromContext(ctx)
	fmt.Println(ok, got.ClientID)

	_, ok = ClaimsFromContext(context.Background())
	fmt.Println(ok)
	// Output:
	// true service-abc
	// false
}

func TestContextRoundTrip(t *testing.T) {
	original := &Claims{
		ClientID: "client-1",
		Scopes:   []string{"read"},
		Email:    "test@example.com",
	}

	ctx := ContextWithClaims(context.Background(), original)
	got, ok := ClaimsFromContext(ctx)

	require.True(t, ok)
	assert.Same(t, original, got)
}

func TestClaimsFromContext_Missing(t *testing.T) {
	got, ok := ClaimsFromContext(context.Background())
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestClaimsFromContext_NilClaimsStored(t *testing.T) {
	ctx := ContextWithClaims(context.Background(), nil)
	got, ok := ClaimsFromContext(ctx)

	assert.True(t, ok)
	assert.Nil(t, got)
}

func TestClaimsFromContext_SurvivesContextWrapping(t *testing.T) {
	original := &Claims{ClientID: "client-wrap"}

	ctx := ContextWithClaims(context.Background(), original)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	type unrelatedKey struct{}
	ctx = context.WithValue(ctx, unrelatedKey{}, "something")

	got, ok := ClaimsFromContext(ctx)
	require.True(t, ok)
	assert.Equal(t, original, got)
}

func TestContextWithClaims_NilContext(t *testing.T) {
	claims := &Claims{ClientID: "client-nil-ctx"}

	// Should not panic — nil ctx is guarded with context.Background().
	ctx := ContextWithClaims(nil, claims)
	got, ok := ClaimsFromContext(ctx)

	require.True(t, ok)
	assert.Equal(t, claims, got)
}

func TestClaimsFromContext_NilContext(t *testing.T) {
	got, ok := ClaimsFromContext(nil)
	assert.False(t, ok)
	assert.Nil(t, got)
}

func TestContextWithClaims_NilContextNilClaims(t *testing.T) {
	// Both ctx and claims nil — should not panic, produces (nil, true).
	ctx := ContextWithClaims(nil, nil)
	got, ok := ClaimsFromContext(ctx)

	assert.True(t, ok)
	assert.Nil(t, got)
}

func TestClaimsFromContext_TypeSafety(t *testing.T) {
	// Store a non-Claims value at a different key — should not interfere.
	type otherKey struct{}
	ctx := context.WithValue(context.Background(), otherKey{}, "not-claims")

	got, ok := ClaimsFromContext(ctx)
	assert.False(t, ok)
	assert.Nil(t, got)
}
