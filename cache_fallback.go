package authclient

import (
	"context"
	"log/slog"
	"time"

	pkgredis "github.com/turnkeystaffing/go-redis"
)

// FallbackIntrospectionCache wraps a primary (Redis) and fallback (in-memory) cache.
// When a Redis operation fails, the shared DegradationMonitor is notified and
// subsequent operations use the fallback until the monitor recovers.
//
// On Set, both primary and fallback are written (dual-write) so the fallback
// cache is warm on failover. On Get, only the active cache is queried.
type FallbackIntrospectionCache struct {
	primary  IntrospectionCache
	fallback IntrospectionCache
	monitor  pkgredis.DegradationMonitor
	logger   *slog.Logger
}

// NewFallbackIntrospectionCache creates a cache that falls back to an in-memory
// implementation when Redis is unavailable. The monitor is shared across all
// Redis consumers (rate limiter, auth cache, etc.) — a single probe goroutine
// handles recovery for all.
//
// Panics if any argument is nil.
func NewFallbackIntrospectionCache(
	primary IntrospectionCache,
	fallback IntrospectionCache,
	monitor pkgredis.DegradationMonitor,
	logger *slog.Logger,
) *FallbackIntrospectionCache {
	if primary == nil {
		panic("authclient.NewFallbackIntrospectionCache: primary cannot be nil")
	}
	if fallback == nil {
		panic("authclient.NewFallbackIntrospectionCache: fallback cannot be nil")
	}
	if monitor == nil {
		panic("authclient.NewFallbackIntrospectionCache: monitor cannot be nil")
	}
	if logger == nil {
		panic("authclient.NewFallbackIntrospectionCache: logger cannot be nil")
	}
	return &FallbackIntrospectionCache{
		primary:  primary,
		fallback: fallback,
		monitor:  monitor,
		logger:   logger,
	}
}

var _ IntrospectionCache = (*FallbackIntrospectionCache)(nil)

// Get retrieves a cached value from the active cache.
func (c *FallbackIntrospectionCache) Get(ctx context.Context, key string) (CacheResult, error) {
	if c.monitor.IsDegraded() {
		return c.fallback.Get(ctx, key)
	}

	result, err := c.primary.Get(ctx, key)
	if err != nil {
		c.monitor.MarkDegraded()
		c.logger.Warn("introspection cache: Redis Get failed, using fallback",
			slog.String("error", err.Error()))
		return c.fallback.Get(ctx, key)
	}
	return result, nil
}

// Set stores a value in both primary and fallback (dual-write).
// The fallback is always written so it stays warm for failover.
func (c *FallbackIntrospectionCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	// Always write to fallback to keep it warm
	_ = c.fallback.Set(ctx, key, value, expiration)

	if c.monitor.IsDegraded() {
		return nil
	}

	if err := c.primary.Set(ctx, key, value, expiration); err != nil {
		c.monitor.MarkDegraded()
		c.logger.Warn("introspection cache: Redis Set failed, using fallback",
			slog.String("error", err.Error()))
		return nil
	}
	return nil
}

// Del removes keys from both primary and fallback.
func (c *FallbackIntrospectionCache) Del(ctx context.Context, keys ...string) (int64, error) {
	// Always delete from fallback
	fallbackDeleted, _ := c.fallback.Del(ctx, keys...)

	if c.monitor.IsDegraded() {
		return fallbackDeleted, nil
	}

	deleted, err := c.primary.Del(ctx, keys...)
	if err != nil {
		c.monitor.MarkDegraded()
		c.logger.Warn("introspection cache: Redis Del failed, using fallback",
			slog.String("error", err.Error()))
		return fallbackDeleted, nil
	}
	return deleted, nil
}
