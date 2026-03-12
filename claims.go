package authclient

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the authenticated identity extracted from a token.
// ClientID identifies the OAuth client (from client_credentials grant).
// The validator checks that ClientID is non-empty but does not enforce format;
// consumers should validate format (e.g., UUID) and sanitize before use in queries or logs.
// UserID is optional and present only for user-context tokens.
//
// Security: Email and Username are populated from introspection responses and passed
// through unsanitized. Consumers MUST sanitize these fields before use in SQL queries,
// log templates, HTML output, or any injection-sensitive context.
type Claims struct {
	jwt.RegisteredClaims
	ClientID  string   `json:"client_id"`
	Scopes    []string `json:"scopes"`
	UserID    string   `json:"user_id,omitempty"`
	Email     string   `json:"email,omitempty"`
	Username  string   `json:"username,omitempty"`
	GrantType string   `json:"gty,omitempty"`
	AuthTime  int64    `json:"auth_time,omitempty"`
}

// DeepCopy returns a deep copy of the Claims, duplicating slices and
// NumericDate fields to prevent shared-state mutation across goroutines.
func (c *Claims) DeepCopy() *Claims {
	cp := *c
	if c.Scopes != nil {
		cp.Scopes = make([]string, len(c.Scopes))
		copy(cp.Scopes, c.Scopes)
	}
	if c.Audience != nil {
		cp.Audience = make([]string, len(c.Audience))
		copy(cp.Audience, c.Audience)
	}
	cp.ExpiresAt = copyNumericDate(c.ExpiresAt)
	cp.NotBefore = copyNumericDate(c.NotBefore)
	cp.IssuedAt = copyNumericDate(c.IssuedAt)
	return &cp
}

// DefaultReauthMaxAge is the default maximum age for step-up authentication checks,
// matching the auth server's default reauth_max_age setting.
const DefaultReauthMaxAge = 15 * time.Minute

// AuthenticatedWithin reports whether the user's authentication occurred
// within maxAge of now. Use this in handlers that guard sensitive operations
// to require recent credential proof (step-up authentication).
// If maxAge is zero, DefaultReauthMaxAge (15 minutes) is used.
// Returns false if AuthTime is zero (not present in the token).
func (c *Claims) AuthenticatedWithin(maxAge time.Duration) bool {
	if c.AuthTime == 0 {
		return false
	}
	if maxAge == 0 {
		maxAge = DefaultReauthMaxAge
	}
	return time.Since(time.Unix(c.AuthTime, 0)) <= maxAge
}

// copyNumericDate returns a deep copy of a *jwt.NumericDate, or nil if src is nil.
func copyNumericDate(src *jwt.NumericDate) *jwt.NumericDate {
	if src == nil {
		return nil
	}
	return jwt.NewNumericDate(src.Time.In(time.UTC))
}
