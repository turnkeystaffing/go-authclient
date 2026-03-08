package authclient

import (
	"context"
	"strings"
	"time"
)

// Introspector validates tokens via remote introspection.
type Introspector interface {
	Introspect(ctx context.Context, token string) (*IntrospectionResponse, error)
}

// IntrospectionResponse represents an RFC 7662 introspection response.
type IntrospectionResponse struct {
	Active   bool   `json:"active"`
	Sub      string `json:"sub"`
	Scope    string `json:"scope"`
	Email    string `json:"email,omitempty"`
	Username string `json:"username,omitempty"`
	ClientID string `json:"client_id"`
	Exp      int64  `json:"exp"`
}

// Scopes returns the space-delimited scope string split into individual scopes.
func (r *IntrospectionResponse) Scopes() []string {
	if r.Scope == "" {
		return nil
	}
	return strings.Split(r.Scope, " ")
}

// CacheResult represents the result of a cache lookup.
type CacheResult struct {
	Value string // The cached value (empty string if miss).
	Hit   bool   // true if value was found, false for miss.
}

// IntrospectionCache provides cache operations for token introspection.
// Implementations: noopIntrospectionCache (built-in), InMemoryCache (built-in),
// RedisIntrospectionCache (adapter for pkg/redis.RedisClient).
type IntrospectionCache interface {
	Get(ctx context.Context, key string) (CacheResult, error)
	Set(ctx context.Context, key string, value string, expiration time.Duration) error
	Del(ctx context.Context, keys ...string) (int64, error)
}
