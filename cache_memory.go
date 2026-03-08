package authclient

import (
	"context"
	"sync"
	"time"
)

// InMemoryCache is a simple TTL-based in-memory cache for introspection responses.
// Suitable for single-instance services that don't need distributed cache (Redis).
// Safe for concurrent use.
type InMemoryCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	maxSize int
}

type cacheEntry struct {
	value     string
	expiresAt time.Time
}

// NewInMemoryCache creates an in-memory introspection cache.
// maxSize limits the number of cached entries; when exceeded, all expired entries
// are evicted first, then the oldest entry is removed if still at capacity.
// Panics if maxSize < 1.
func NewInMemoryCache(maxSize int) *InMemoryCache {
	if maxSize < 1 {
		panic("authclient.NewInMemoryCache: maxSize must be >= 1")
	}
	return &InMemoryCache{
		entries: make(map[string]cacheEntry, maxSize),
		maxSize: maxSize,
	}
}

var _ IntrospectionCache = (*InMemoryCache)(nil)

// Get returns the cached value if present and not expired.
func (c *InMemoryCache) Get(_ context.Context, key string) (CacheResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.entries[key]
	if !ok {
		return CacheResult{}, nil
	}
	if time.Now().After(entry.expiresAt) {
		delete(c.entries, key)
		return CacheResult{}, nil
	}
	return CacheResult{Value: entry.value, Hit: true}, nil
}

// Set stores a value with the given TTL. Evicts expired/oldest entries if at capacity.
func (c *InMemoryCache) Set(_ context.Context, key string, value string, expiration time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}

	c.entries[key] = cacheEntry{
		value:     value,
		expiresAt: time.Now().Add(expiration),
	}
	return nil
}

// Del removes the specified keys from the cache.
func (c *InMemoryCache) Del(_ context.Context, keys ...string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var deleted int64
	for _, key := range keys {
		if _, ok := c.entries[key]; ok {
			delete(c.entries, key)
			deleted++
		}
	}
	return deleted, nil
}

// evictLocked removes all expired entries. If still at capacity, removes the
// entry closest to expiration. Caller must hold c.mu.
func (c *InMemoryCache) evictLocked() {
	now := time.Now()
	for k, e := range c.entries {
		if now.After(e.expiresAt) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) < c.maxSize {
		return
	}

	// Still full — evict the entry with the earliest expiration.
	var oldestKey string
	var oldestExp time.Time
	for k, e := range c.entries {
		if oldestKey == "" || e.expiresAt.Before(oldestExp) {
			oldestKey = k
			oldestExp = e.expiresAt
		}
	}
	if oldestKey != "" {
		delete(c.entries, oldestKey)
	}
}
