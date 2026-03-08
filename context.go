package authclient

import "context"

// claimsContextKey is an unexported typed key for storing Claims in context.
// Using an empty struct avoids allocation and prevents cross-package key collisions.
type claimsContextKey struct{}

// ContextWithClaims returns a new context with the given claims stored.
// If ctx is nil, context.Background() is used as the parent (fail-safe for
// middleware chains where context propagation may be incomplete).
// Nil claims are stored as-is; ClaimsFromContext will return (nil, true),
// distinguishing "auth ran but produced no claims" from "auth never ran".
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// ClaimsFromContext retrieves claims from the context.
// Returns (claims, true) if found, (nil, false) if not present.
// If ctx is nil, returns (nil, false).
//
// The returned *Claims is the same pointer stored by ContextWithClaims.
// Callers MUST NOT mutate the returned struct; doing so would affect all
// subsequent reads from the same context chain.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	if ctx == nil {
		return nil, false
	}
	claims, ok := ctx.Value(claimsContextKey{}).(*Claims)
	return claims, ok
}
