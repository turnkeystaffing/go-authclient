package authclient

import (
	"regexp"
	"strings"
)

// scopeNamePattern matches valid scope names: 2-3 colon-separated segments.
// First segment: lowercase alphanumeric + underscore.
// Subsequent segments: same + wildcard (*).
// CONTRACT: Must match get-native-auth's scopeNamePattern in
// internal/scopes/validation/scope_validator.go. Divergence causes sync failures.
var scopeNamePattern = regexp.MustCompile(`^[a-z0-9_]+(?::[a-z0-9_*]+){1,2}$`)

// oidcStandardScopes are OpenID Connect specification scopes that bypass the
// resource:action pattern. These are always valid as user scopes in JWT claims.
// CONTRACT: Must match get-native-auth's oidcStandardScopes in
// internal/scopes/validation/scope_validator.go.
var oidcStandardScopes = map[string]bool{
	"openid":         true,
	"profile":        true,
	"email":          true,
	"address":        true,
	"phone":          true,
	"offline_access": true,
}

// IsValidScope checks if a scope name conforms to the auth service's naming rules.
// Used by scope checking functions to reject malformed scopes from JWT claims.
//
// Returns true for:
//   - OIDC standard scopes (openid, profile, email, address, phone, offline_access)
//   - Universal wildcards (*:*, *)
//   - 2-3 segment names matching ^[a-z0-9_]+(?::[a-z0-9_*]+){1,2}$
//   - Wildcards only as the final complete segment (bgc:* ok, bgc:*:read rejected)
//   - No embedded wildcards (app*rove rejected)
//
// Returns false for empty, oversized (>255), uppercase, 4+ segment, or otherwise
// malformed scope names.
//
// CONTRACT: Must match get-native-auth's ScopeValidator.ValidateName rules.
func IsValidScope(name string) bool {
	if name == "" || len(name) > 255 {
		return false
	}
	if name != strings.ToLower(name) {
		return false
	}
	if oidcStandardScopes[name] {
		return true
	}
	if name == "*:*" || name == "*" {
		return true
	}
	if !scopeNamePattern.MatchString(name) {
		return false
	}
	if strings.Contains(name, "*") {
		segments := strings.Split(name, ":")
		// Reject embedded wildcards (e.g., "app*rove")
		for _, seg := range segments[1:] {
			if seg != "*" && strings.Contains(seg, "*") {
				return false
			}
		}
		// Reject non-final wildcards (e.g., "bgc:*:read")
		for _, seg := range segments[1 : len(segments)-1] {
			if seg == "*" {
				return false
			}
		}
	}
	return true
}

// IsOIDCStandardScope returns true if the scope is a standard OIDC scope.
func IsOIDCStandardScope(name string) bool {
	return oidcStandardScopes[name]
}
