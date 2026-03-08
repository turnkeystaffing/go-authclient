package authclient

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func ExampleHasScope() {
	claims := &Claims{Scopes: []string{"read", "write", "admin"}}
	fmt.Println(HasScope(claims, "admin"))
	fmt.Println(HasScope(claims, "delete"))
	fmt.Println(HasScope(nil, "admin"))
	// Output:
	// true
	// false
	// false
}

func ExampleHasAnyScope() {
	claims := &Claims{Scopes: []string{"read", "write"}}
	fmt.Println(HasAnyScope(claims, "admin", "write"))
	fmt.Println(HasAnyScope(claims, "admin", "delete"))
	// Output:
	// true
	// false
}

func TestHasScope_ExactMatch(t *testing.T) {
	claims := &Claims{Scopes: []string{"read", "write", "admin"}}
	assert.True(t, HasScope(claims, "admin"))
}

func TestHasScope_NotFound(t *testing.T) {
	claims := &Claims{Scopes: []string{"read", "write"}}
	assert.False(t, HasScope(claims, "admin"))
}

func TestHasScope_NilClaims(t *testing.T) {
	assert.False(t, HasScope(nil, "admin"))
}

func TestHasScope_EmptyScopeList(t *testing.T) {
	claims := &Claims{Scopes: []string{}}
	assert.False(t, HasScope(claims, "read"))
}

func TestHasScope_EmptyRequiredScope(t *testing.T) {
	claims := &Claims{Scopes: []string{"read", "write"}}
	assert.False(t, HasScope(claims, ""))
}

func TestHasScope_NilScopesField(t *testing.T) {
	claims := &Claims{ClientID: "client-1"} // Scopes is nil (not empty slice)
	assert.False(t, HasScope(claims, "read"))
}

func TestHasAnyScope_NilScopesField(t *testing.T) {
	claims := &Claims{ClientID: "client-1"} // Scopes is nil
	assert.False(t, HasAnyScope(claims, "read", "write"))
}

func TestHasScope_SubstringNonMatch(t *testing.T) {
	claims := &Claims{Scopes: []string{"admin:read", "administrator"}}
	assert.False(t, HasScope(claims, "admin"))
}

func TestHasScope_CaseSensitive(t *testing.T) {
	claims := &Claims{Scopes: []string{"Read", "WRITE"}}
	assert.False(t, HasScope(claims, "read"))
	assert.False(t, HasScope(claims, "write"))
	assert.True(t, HasScope(claims, "Read"))
	assert.True(t, HasScope(claims, "WRITE"))
}

func TestHasAnyScope_OneMatch(t *testing.T) {
	claims := &Claims{Scopes: []string{"read", "write"}}
	assert.True(t, HasAnyScope(claims, "admin", "write"))
}

func TestHasAnyScope_NoMatch(t *testing.T) {
	claims := &Claims{Scopes: []string{"read", "write"}}
	assert.False(t, HasAnyScope(claims, "admin", "delete"))
}

func TestHasAnyScope_NilClaims(t *testing.T) {
	assert.False(t, HasAnyScope(nil, "read"))
}

func TestHasAnyScope_EmptyRequiredScopes(t *testing.T) {
	claims := &Claims{Scopes: []string{"read", "write"}}
	assert.False(t, HasAnyScope(claims))
}

func TestHasAnyScope_AllPresent(t *testing.T) {
	claims := &Claims{Scopes: []string{"read", "write", "admin"}}
	assert.True(t, HasAnyScope(claims, "read", "write", "admin"))
}

func TestHasAnyScope_MixedEmptyAndValid(t *testing.T) {
	claims := &Claims{Scopes: []string{"valid_scope"}}
	assert.True(t, HasAnyScope(claims, "", "valid_scope"))
}

func TestHasAnyScope_SingleEmptyString(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	assert.False(t, HasAnyScope(claims, ""))
}

func TestHasAnyScope_AllEmpty(t *testing.T) {
	claims := &Claims{Scopes: []string{"read"}}
	assert.False(t, HasAnyScope(claims, "", ""))
}

func BenchmarkHasScope_TypicalOAuth(b *testing.B) {
	claims := &Claims{Scopes: []string{"read", "write", "admin", "audit:read", "audit:write", "scope:manage", "user:read", "user:write"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasScope(claims, "audit:write")
	}
}

func BenchmarkHasScope_NotFound(b *testing.B) {
	claims := &Claims{Scopes: []string{"read", "write", "admin", "audit:read", "audit:write", "scope:manage", "user:read", "user:write"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasScope(claims, "nonexistent")
	}
}

func BenchmarkHasAnyScope_TypicalOAuth(b *testing.B) {
	claims := &Claims{Scopes: []string{"read", "write", "admin", "audit:read", "audit:write", "scope:manage", "user:read", "user:write"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasAnyScope(claims, "delete", "scope:manage", "nonexistent")
	}
}
