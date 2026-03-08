package authclient

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
