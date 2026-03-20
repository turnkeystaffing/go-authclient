package authclient

import "strings"

// HasScope returns true if the claims contain the exact required scope.
// Returns false for nil claims or empty required scope.
//
// Scope comparison is case-sensitive and uses exact string matching per RFC 6749 Section 3.3.
// Note: scope token characters are not validated against the RFC 6749 NQCHAR production;
// Claims.Scopes may contain empty strings if the source scope string had consecutive spaces;
// these are harmless here because empty requiredScope returns false before iteration.
func HasScope(claims *Claims, requiredScope string) bool {
	if claims == nil || requiredScope == "" {
		return false
	}
	for _, s := range claims.Scopes {
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
// Matching is unidirectional: user wildcard scopes match specific requirements,
// but NOT vice versa. A user with "admin:read" does NOT satisfy "admin:*".
//
// Returns false for nil claims or empty required scope.
func HasScopeWildcard(claims *Claims, requiredScope string) bool {
	if claims == nil || requiredScope == "" {
		return false
	}
	for _, userScope := range claims.Scopes {
		if matchScopeWildcard(userScope, requiredScope) {
			return true
		}
	}
	return false
}

// HasAnyScopeWildcard returns true if the claims contain a scope that matches
// any of the required scopes using wildcard matching.
// Returns false for nil claims or empty required scopes list.
// Empty strings in requiredScopes are skipped.
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
// Supports:
//   - Exact match: "expenses:approve" matches "expenses:approve"
//   - Action wildcard: "expenses:*" matches "expenses:approve"
//   - Service wildcard: "bgc:*" matches "bgc:contractors:read"
//   - Suffix wildcard: "bgc:contractors:*" matches "bgc:contractors:read"
//   - Non-final wildcard: "bgc:*:read" matches "bgc:contractors:read"
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
// Empty strings in requiredScopes are skipped (not matched), preventing
// accidental open access from empty scope values.
func HasAnyScope(claims *Claims, requiredScopes ...string) bool {
	if claims == nil || len(requiredScopes) == 0 {
		return false
	}
	for _, req := range requiredScopes {
		if req == "" {
			continue
		}
		for _, s := range claims.Scopes {
			if s == req {
				return true
			}
		}
	}
	return false
}
