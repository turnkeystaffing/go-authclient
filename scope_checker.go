package authclient

import "strings"

// HasScope returns true if the claims contain the exact required scope.
// Returns false for nil claims, empty required scope, or invalid scope names.
//
// Both the required scope and user scopes are validated against the auth service's
// naming rules (IsValidScope). Invalid scopes are silently skipped — a JWT containing
// malformed scopes like "BOGUS:::thing" or "a:b:c:d" will not match anything.
//
// OIDC standard scopes (openid, profile, email, etc.) are valid and match exactly.
func HasScope(claims *Claims, requiredScope string) bool {
	if claims == nil || requiredScope == "" {
		return false
	}
	if !IsValidScope(requiredScope) {
		return false
	}
	for _, s := range claims.Scopes {
		if !IsValidScope(s) {
			continue
		}
		if s == requiredScope {
			return true
		}
	}
	return false
}

// HasScopeWildcard returns true if the claims contain a scope that matches the
// required scope using wildcard matching. Supports patterns like "expenses:*"
// matching "expenses:approve", "bgc:contractors:*" matching "bgc:contractors:read",
// and "bgc:*" matching "bgc:contractors:read".
//
// Both the required scope and user scopes are validated against the auth service's
// naming rules (IsValidScope). Invalid scopes are silently skipped.
//
// Matching is unidirectional: user wildcard scopes match specific requirements,
// but NOT vice versa. A user with "admin:read" does NOT satisfy "admin:*".
//
// Returns false for nil claims, empty required scope, or invalid scope names.
func HasScopeWildcard(claims *Claims, requiredScope string) bool {
	if claims == nil || requiredScope == "" {
		return false
	}
	if !IsValidScope(requiredScope) {
		return false
	}
	for _, userScope := range claims.Scopes {
		if !IsValidScope(userScope) {
			continue
		}
		if matchScopeWildcard(userScope, requiredScope) {
			return true
		}
	}
	return false
}

// HasAnyScopeWildcard returns true if the claims contain a scope that matches
// any of the required scopes using wildcard matching.
// Returns false for nil claims or empty required scopes list.
// Empty strings and invalid scope names in requiredScopes are skipped.
func HasAnyScopeWildcard(claims *Claims, requiredScopes ...string) bool {
	if claims == nil || len(requiredScopes) == 0 {
		return false
	}
	for _, req := range requiredScopes {
		if req == "" {
			continue
		}
		if HasScopeWildcard(claims, req) {
			return true
		}
	}
	return false
}

// matchScopeWildcard checks if userScope (pattern) matches requiredScope (concrete).
// This replicates get-native-auth's ScopePattern.Matches() algorithm exactly.
//
// Callers must validate scope names via IsValidScope before calling this function.
// In practice, IsValidScope rejects non-final wildcards (bgc:*:read), but the matcher
// handles them as defense-in-depth.
//
// Supports:
//   - Exact match: "expenses:approve" matches "expenses:approve"
//   - Action wildcard: "expenses:*" matches "expenses:approve"
//   - Service wildcard: "bgc:*" matches "bgc:contractors:read"
//   - Suffix wildcard: "bgc:contractors:*" matches "bgc:contractors:read"
//   - Universal wildcard: "*:*" or "*" matches anything
//
// A trailing wildcard (*) matches all remaining segments at that position.
// SECURITY: Only checks if userScope (pattern) matches requiredScope (concrete).
// Never called with arguments reversed.
func matchScopeWildcard(userScope, requiredScope string) bool {
	// Exact match (cheapest check)
	if userScope == requiredScope {
		return true
	}

	// Universal wildcard
	if userScope == "*:*" || userScope == "*" {
		return true
	}

	// No wildcard in pattern — exact match already checked above
	if !strings.Contains(userScope, "*") {
		return false
	}

	// Split into segments for multi-part matching
	patternParts := strings.Split(userScope, ":")
	scopeParts := strings.Split(requiredScope, ":")

	// Defense-in-depth: reject empty segments (trailing colon, double colon)
	for _, pp := range patternParts {
		if pp == "" {
			return false
		}
	}
	for _, sp := range scopeParts {
		if sp == "" {
			return false
		}
	}

	for i, pp := range patternParts {
		if pp == "*" && i == len(patternParts)-1 {
			// Wildcard as LAST pattern segment matches everything remaining
			// BUT scope must have at least one segment at this position
			return i < len(scopeParts)
		}
		if i >= len(scopeParts) {
			return false
		}
		if pp == "*" {
			// Non-final wildcard: match any single segment
			// Note: IsValidScope rejects non-final wildcards, so this is defense-in-depth only.
			continue
		}
		if pp != scopeParts[i] {
			return false
		}
	}
	// All pattern parts matched — scope must not have extra unmatched segments
	return len(patternParts) == len(scopeParts)
}

// HasAnyScope returns true if the claims contain any of the required scopes.
// Returns false for nil claims or empty required scopes list.
// Empty strings and invalid scope names in requiredScopes are skipped.
//
// Both required scopes and user scopes are validated against the auth service's
// naming rules (IsValidScope). Invalid scopes are silently skipped.
func HasAnyScope(claims *Claims, requiredScopes ...string) bool {
	if claims == nil || len(requiredScopes) == 0 {
		return false
	}
	for _, req := range requiredScopes {
		if req == "" {
			continue
		}
		if !IsValidScope(req) {
			continue
		}
		for _, s := range claims.Scopes {
			if !IsValidScope(s) {
				continue
			}
			if s == req {
				return true
			}
		}
	}
	return false
}
