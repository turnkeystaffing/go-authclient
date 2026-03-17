package authclient

import (
	"fmt"
	"sync"
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

func ExampleHasScopeWildcard() {
	claims := &Claims{Scopes: []string{"bgc:contractors:*", "admin:*"}}
	fmt.Println(HasScopeWildcard(claims, "bgc:contractors:read"))
	fmt.Println(HasScopeWildcard(claims, "admin:users:delete"))
	fmt.Println(HasScopeWildcard(claims, "acct:invoices:read"))
	fmt.Println(HasScopeWildcard(nil, "admin:read"))
	// Output:
	// true
	// true
	// false
	// false
}

func ExampleHasAnyScopeWildcard() {
	claims := &Claims{Scopes: []string{"bgc:contractors:*"}}
	fmt.Println(HasAnyScopeWildcard(claims, "acct:invoices:read", "bgc:contractors:write"))
	fmt.Println(HasAnyScopeWildcard(claims, "acct:invoices:read", "admin:users:delete"))
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

// ============================================================================
// Contract Tests: matchScopeWildcard
// Mirror get-native-auth/internal/scopes/domain/scope_pattern_test.go
// ============================================================================

func TestMatchScopeWildcard_ContractTests(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		scope    string
		expected bool
	}{
		// --- ExactMatch (4 cases) ---
		{"exact match", "expenses:approve", "expenses:approve", true},
		{"no match - different action", "expenses:approve", "expenses:submit", false},
		{"no match - different resource", "expenses:approve", "admin:approve", false},
		{"no match - completely different", "expenses:approve", "users:read", false},

		// --- UniversalWildcard (4 cases) ---
		{"universal wildcard *:* matches anything", "*:*", "expenses:approve", true},
		{"universal wildcard *:* matches any resource", "*:*", "admin:users", true},
		{"single asterisk matches anything", "*", "expenses:approve", true},
		{"single asterisk matches any format", "*", "invalid_format", true},

		// --- ActionWildcard 2-part (6 cases) ---
		{"action wildcard matches approve", "expenses:*", "expenses:approve", true},
		{"action wildcard matches submit", "expenses:*", "expenses:submit", true},
		{"action wildcard matches any action", "expenses:*", "expenses:delete", true},
		{"action wildcard doesn't match different resource", "expenses:*", "admin:approve", false},
		{"admin wildcard matches any admin action", "admin:*", "admin:users", true},
		{"admin wildcard matches settings", "admin:*", "admin:settings", true},

		// --- ResourceWildcard 2-part (7 cases) ---
		{"resource wildcard matches expenses:read", "*:read", "expenses:read", true},
		{"resource wildcard matches admin:read", "*:read", "admin:read", true},
		{"resource wildcard matches any resource with read", "*:read", "users:read", true},
		{"resource wildcard doesn't match different action", "*:read", "expenses:write", false},
		{"resource wildcard doesn't match approve action", "*:read", "expenses:approve", false},
		{"resource wildcard does not match 3-part scope", "*:read", "bgc:contractors:read", false},
		{"resource wildcard does not match 3-part scope different action", "*:read", "bgc:contractors:write", false},

		// --- InvalidPatterns (8 cases) ---
		{"pattern without colon doesn't match valid scope", "expenses", "expenses:approve", false},
		{"scope without colon doesn't match valid pattern", "expenses:approve", "expenses", false},
		{"both without colon - no match", "expenses", "admin", false},
		{"both without colon - exact match", "expenses", "expenses", true},
		{"empty pattern doesn't match", "", "expenses:approve", false},
		{"pattern matches empty scope", "", "", true},
		{"wildcard pattern with missing resource part", ":*", "expenses:approve", false},
		{"wildcard pattern with missing action part", "expenses:", "expenses:approve", false},

		// --- EdgeCases (4 cases) ---
		{"multiple colons in pattern - exact match", "resource:sub:action", "resource:sub:action", true},
		{"pattern with spaces", "expenses: approve", "expenses: approve", true},
		{"case sensitive - different case no match", "Expenses:Approve", "expenses:approve", false},
		{"case sensitive - exact case match", "expenses:approve", "expenses:approve", true},

		// --- ThreePartWildcard (30 cases) ---
		// AC1: Suffix wildcard
		{"suffix wildcard matches read action", "bgc:contractors:*", "bgc:contractors:read", true},
		{"suffix wildcard matches write action", "bgc:contractors:*", "bgc:contractors:write", true},
		{"suffix wildcard matches delete action", "bgc:contractors:*", "bgc:contractors:delete", true},
		{"suffix wildcard does not match different resource", "bgc:contractors:*", "bgc:expenses:read", false},
		{"suffix wildcard does not match different service", "bgc:contractors:*", "acct:contractors:read", false},
		// AC2: Service-level wildcard
		{"service wildcard matches 3-part scope", "bgc:*", "bgc:contractors:read", true},
		{"service wildcard matches different resource/action", "bgc:*", "bgc:expenses:approve", true},
		{"service wildcard matches settings write", "bgc:*", "bgc:settings:write", true},
		// AC5: No cross-service leakage
		{"service wildcard does not match different service prefix", "bgc:*", "bgc_admin:settings:read", false},
		// AC6: Context scope coverage
		{"wildcard covers context affiliate", "app:*", "app:context:affiliate", true},
		{"wildcard covers context contractor", "app:*", "app:context:contractor", true},
		{"wildcard covers all app scopes", "app:*", "app:expenses:approve", true},
		// AC4: Universal wildcard with 3-part
		{"universal wildcard *:* matches 3-part scope", "*:*", "bgc:contractors:read", true},
		{"universal wildcard * matches 3-part scope", "*", "bgc:contractors:read", true},
		// Edge: wildcard requires segment at position
		{"suffix wildcard does not match scope without action segment", "bgc:contractors:*", "bgc:contractors", false},
		{"service wildcard does not match scope without resource segment", "bgc:*", "bgc", false},
		{"suffix wildcard does not match different resource wildcard", "bgc:contractors:*", "bgc:expenses:*", false},
		// Triple wildcard
		{"triple wildcard matches 3-part scope", "*:*:*", "bgc:contractors:read", true},
		{"triple wildcard does not match 2-part scope", "*:*:*", "bgc:read", false},
		// Unbounded depth
		{"trailing wildcard matches 4-segment scope (beyond validator max)", "bgc:contractors:*", "bgc:contractors:read:extra", true},
		{"service wildcard matches 5-segment scope (beyond validator max)", "bgc:*", "bgc:a:b:c:d", true},
		// Defense-in-depth: empty segments
		{"suffix wildcard rejects scope with trailing colon (empty segment)", "bgc:contractors:*", "bgc:contractors:", false},
		{"service wildcard rejects scope with trailing colon", "bgc:*", "bgc:contractors:", false},
		{"service wildcard rejects scope with leading colon", "bgc:*", ":contractors:read", false},
		{"pattern with double colon rejects (empty pattern segment)", "bgc::*", "bgc:contractors:read", false},
		{"scope with double colon in middle rejected", "bgc:*", "bgc::read", false},
		{"wildcard does not match empty string scope", "bgc:*", "", false},
		{"degenerate pattern ::* rejected by empty segment defense", "::*", "bgc:contractors:read", false},
		{"degenerate pattern *:: rejected by empty segment defense", "*::", "bgc:contractors:read", false},
		{"3-part wildcard does not match 1-segment scope", "bgc:contractors:*", "bgc", false},

		// --- NonFinalWildcard (6 cases) ---
		{"middle wildcard matches with exact final segment", "bgc:*:read", "bgc:contractors:read", true},
		{"middle wildcard does not match different final segment", "bgc:*:read", "bgc:contractors:write", false},
		{"middle wildcard matches any middle segment", "app:*:view", "app:dashboard:view", true},
		{"scope shorter than pattern after non-final wildcard", "bgc:*:read", "bgc:contractors", false},
		{"scope much shorter than pattern with wildcard", "bgc:*:read", "bgc", false},
		{"scope longer than pattern with non-final wildcard", "bgc:*:read", "bgc:contractors:read:extra", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchScopeWildcard(tt.pattern, tt.scope)
			assert.Equal(t, tt.expected, result, "matchScopeWildcard(%q, %q)", tt.pattern, tt.scope)
		})
	}
}

// ============================================================================
// HasScopeWildcard Tests
// ============================================================================

func TestHasScopeWildcard(t *testing.T) {
	tests := []struct {
		name          string
		scopes        []string
		requiredScope string
		expected      bool
	}{
		{"AC1: suffix wildcard grants specific 3-part", []string{"bgc:contractors:*"}, "bgc:contractors:read", true},
		{"AC2: service wildcard grants any 3-part", []string{"bgc:*"}, "bgc:contractors:read", true},
		{"AC3: specific does NOT satisfy wildcard", []string{"bgc:contractors:read"}, "bgc:contractors:*", false},
		{"AC4: universal wildcard grants 3-part", []string{"*:*"}, "bgc:contractors:read", true},
		{"AC5: wildcard does not cross service prefix", []string{"bgc:*"}, "bgc_admin:settings:read", false},
		{"AC6: wildcard covers context scopes", []string{"app:*"}, "app:context:affiliate", true},
		{"exact 3-part match", []string{"bgc:contractors:read"}, "bgc:contractors:read", true},
		{"different action no match", []string{"bgc:contractors:write"}, "bgc:contractors:read", false},
		{"exact 3-part wildcard match", []string{"bgc:contractors:*"}, "bgc:contractors:*", true},
		{"broader wildcard covers narrower wildcard requirement", []string{"bgc:*"}, "bgc:contractors:*", true},
		{"3-part wildcard does not match 2-part scope", []string{"bgc:contractors:*"}, "bgc:read", false},
		{"universal wildcard satisfies wildcard required scope", []string{"*:*"}, "bgc:*", true},
		{"user with admin:read cannot access admin:* routes (SECURITY)", []string{"admin:read"}, "admin:*", false},
		{"user with admin:* CAN access admin:read", []string{"admin:*"}, "admin:read", true},
		{"exact match works", []string{"expenses:approve"}, "expenses:approve", true},
		{"user has universal wildcard", []string{"*:*"}, "expenses:approve", true},
		{"empty user scopes", []string{}, "expenses:approve", false},
		{"nil user scopes", nil, "expenses:approve", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := &Claims{Scopes: tt.scopes}
			result := HasScopeWildcard(claims, tt.requiredScope)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasScopeWildcard_NilAndEdgeCases(t *testing.T) {
	assert.False(t, HasScopeWildcard(nil, "admin"), "nil claims")
	assert.False(t, HasScopeWildcard(&Claims{Scopes: []string{"read"}}, ""), "empty required scope")
	assert.False(t, HasScopeWildcard(&Claims{ClientID: "c"}, "read"), "nil Scopes field")
	assert.False(t, HasScopeWildcard(&Claims{Scopes: []string{}}, "read"), "empty scopes list")

	// Case sensitivity preserved
	claims := &Claims{Scopes: []string{"Admin:*"}}
	assert.False(t, HasScopeWildcard(claims, "admin:read"), "case sensitive")
	assert.True(t, HasScopeWildcard(claims, "Admin:read"), "case sensitive match")
}

func TestHasAnyScopeWildcard(t *testing.T) {
	tests := []struct {
		name           string
		scopes         []string
		requiredScopes []string
		expected       bool
	}{
		{"wildcard matches first required scope", []string{"bgc:contractors:*"}, []string{"bgc:contractors:read", "acct:expenses:approve"}, true},
		{"wildcard matches last required scope", []string{"bgc:*"}, []string{"acct:expenses:approve", "bgc:contractors:read"}, true},
		{"no match across different services", []string{"acct:expenses:read"}, []string{"bgc:contractors:read", "acct:expenses:approve"}, false},
		{"empty required scopes returns false", []string{"expenses:*"}, []string{}, false},
		{"nil claims returns false", nil, []string{"read"}, false},
		{"empty strings in required scopes skipped", []string{"admin:*"}, []string{"", "admin:read"}, true},
		{"all empty strings returns false", []string{"admin:*"}, []string{"", ""}, false},
		{"mixed wildcard and exact in claims", []string{"expenses:*", "bgc:contractors:*", "users:read"}, []string{"users:read"}, true},
		{"service wildcard in claims matches 3-part required", []string{"bgc:*"}, []string{"bgc:contractors:read"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var claims *Claims
			if tt.scopes != nil {
				claims = &Claims{Scopes: tt.scopes}
			}
			result := HasAnyScopeWildcard(claims, tt.requiredScopes...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasAnyScopeWildcard_NilAndEdgeCases(t *testing.T) {
	assert.False(t, HasAnyScopeWildcard(nil, "admin"), "nil claims")
	assert.False(t, HasAnyScopeWildcard(&Claims{ClientID: "c"}, "read"), "nil Scopes field")
	assert.False(t, HasAnyScopeWildcard(&Claims{Scopes: []string{}}, "read"), "empty scopes list")
	assert.False(t, HasAnyScopeWildcard(&Claims{Scopes: []string{"admin:*"}}, ""), "empty required scope skipped, no others")
}

func TestHasScopeWildcard_BackwardCompatibility(t *testing.T) {
	// 2-part scopes still work with wildcard matching
	claims := &Claims{Scopes: []string{"expenses:*", "admin:*", "users:read"}}
	assert.True(t, HasScopeWildcard(claims, "expenses:approve"))
	assert.True(t, HasScopeWildcard(claims, "admin:read"))
	assert.True(t, HasScopeWildcard(claims, "users:read"))
	assert.False(t, HasScopeWildcard(claims, "users:write"))
}

func TestHasScopeWildcard_ComplexScenarios(t *testing.T) {
	t.Run("mixed 2-part and 3-part wildcards", func(t *testing.T) {
		claims := &Claims{Scopes: []string{"expenses:*", "bgc:contractors:*", "users:read"}}
		assert.True(t, HasScopeWildcard(claims, "expenses:approve"))
		assert.True(t, HasScopeWildcard(claims, "bgc:contractors:read"))
		assert.True(t, HasScopeWildcard(claims, "users:read"))
		assert.False(t, HasScopeWildcard(claims, "bgc:expenses:read"))
		assert.False(t, HasScopeWildcard(claims, "users:write"))
	})

	t.Run("multiple wildcards covering different services", func(t *testing.T) {
		claims := &Claims{Scopes: []string{"bgc:*", "admin:*"}}
		assert.True(t, HasScopeWildcard(claims, "bgc:contractors:read"))
		assert.True(t, HasScopeWildcard(claims, "admin:users:delete"))
		assert.True(t, HasScopeWildcard(claims, "bgc:expenses:approve"))
		assert.False(t, HasScopeWildcard(claims, "acct:invoices:read"))
	})

	t.Run("service wildcard + suffix wildcard + exact in same claims", func(t *testing.T) {
		claims := &Claims{Scopes: []string{"bgc:*", "acct:invoices:*", "users:read"}}
		assert.True(t, HasScopeWildcard(claims, "bgc:contractors:read"))
		assert.True(t, HasScopeWildcard(claims, "acct:invoices:approve"))
		assert.True(t, HasScopeWildcard(claims, "users:read"))
		assert.False(t, HasScopeWildcard(claims, "acct:expenses:read"))
	})
}

func TestHasScopeWildcard_ConcurrentSafety(t *testing.T) {
	claims := &Claims{Scopes: []string{"bgc:contractors:*", "admin:*", "expenses:approve"}}

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			assert.True(t, HasScopeWildcard(claims, "bgc:contractors:read"))
			assert.True(t, HasScopeWildcard(claims, "admin:users:delete"))
			assert.True(t, HasScopeWildcard(claims, "expenses:approve"))
			assert.False(t, HasScopeWildcard(claims, "acct:invoices:read"))
		}()
	}

	wg.Wait()
}

// ============================================================================
// Benchmarks
// ============================================================================

func BenchmarkHasScopeWildcard_WildcardMatch(b *testing.B) {
	claims := &Claims{Scopes: []string{"read", "write", "bgc:contractors:*", "admin:*"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasScopeWildcard(claims, "bgc:contractors:read")
	}
}

func BenchmarkHasScopeWildcard_ExactMatch(b *testing.B) {
	claims := &Claims{Scopes: []string{"read", "write", "bgc:contractors:read", "admin:users"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasScopeWildcard(claims, "bgc:contractors:read")
	}
}

func BenchmarkHasScopeWildcard_NotFound(b *testing.B) {
	claims := &Claims{Scopes: []string{"read", "write", "bgc:contractors:*", "admin:*"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasScopeWildcard(claims, "nonexistent:scope:here")
	}
}

func BenchmarkHasScopeWildcard_ServiceWildcard(b *testing.B) {
	claims := &Claims{Scopes: []string{"read", "write", "bgc:*", "admin:users"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasScopeWildcard(claims, "bgc:contractors:read")
	}
}

func BenchmarkHasScopeWildcard_ManySegments(b *testing.B) {
	claims := &Claims{Scopes: []string{"bgc:*"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasScopeWildcard(claims, "bgc:a:b:c:d:e:f")
	}
}

func BenchmarkHasAnyScopeWildcard_Match(b *testing.B) {
	claims := &Claims{Scopes: []string{"read", "write", "bgc:contractors:*", "admin:*"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasAnyScopeWildcard(claims, "acct:invoices:read", "bgc:contractors:write")
	}
}

func BenchmarkHasAnyScopeWildcard_NoMatch(b *testing.B) {
	claims := &Claims{Scopes: []string{"read", "write", "bgc:contractors:*", "admin:*"}}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasAnyScopeWildcard(claims, "acct:invoices:read", "acct:expenses:approve")
	}
}

func BenchmarkHasScopeWildcard_LargeScopeCount(b *testing.B) {
	scopes := make([]string, 60)
	for i := 0; i < 60; i++ {
		scopes[i] = fmt.Sprintf("svc%d:resource%d:action%d", i, i, i)
	}
	// Target scope is at the end, forcing full iteration
	scopes[59] = "target:resource:read"
	claims := &Claims{Scopes: scopes}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		HasScopeWildcard(claims, "target:resource:read")
	}
}

func TestHasScopeWildcard_DuplicateWildcardScopes(t *testing.T) {
	claims := &Claims{Scopes: []string{"bgc:*", "bgc:*", "admin:*"}}
	assert.True(t, HasScopeWildcard(claims, "bgc:contractors:read"), "duplicate wildcards should not cause issues")
	assert.True(t, HasScopeWildcard(claims, "admin:users:delete"), "non-duplicate wildcard should still match")
	assert.False(t, HasScopeWildcard(claims, "acct:invoices:read"), "unrelated scope should not match")
}
