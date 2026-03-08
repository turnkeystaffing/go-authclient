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
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	UserID   string   `json:"user_id,omitempty"`
	Email    string   `json:"email,omitempty"`
	Username string   `json:"username,omitempty"`
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

// copyNumericDate returns a deep copy of a *jwt.NumericDate, or nil if src is nil.
func copyNumericDate(src *jwt.NumericDate) *jwt.NumericDate {
	if src == nil {
		return nil
	}
	return jwt.NewNumericDate(src.Time.In(time.UTC))
}
