package authclient

import (
	"context"
	"time"

	pkgredis "github.com/turnkeystaffing/go-redis"
)

// RedisIntrospectionCache adapts a pkg/redis.RedisClient to the IntrospectionCache
// interface. This keeps pkg/authclient decoupled from pkg/redis — services that
// don't use Redis have no transitive dependency on go-redis.
type RedisIntrospectionCache struct {
	client pkgredis.RedisClient
}

// NewRedisIntrospectionCache wraps a RedisClient as an IntrospectionCache.
// Panics if client is nil.
func NewRedisIntrospectionCache(client pkgredis.RedisClient) *RedisIntrospectionCache {
	if client == nil {
		panic("authclient.NewRedisIntrospectionCache: client cannot be nil")
	}
	return &RedisIntrospectionCache{client: client}
}

var _ IntrospectionCache = (*RedisIntrospectionCache)(nil)

// Get retrieves a cached value from Redis.
func (c *RedisIntrospectionCache) Get(ctx context.Context, key string) (CacheResult, error) {
	result, err := c.client.Get(ctx, key)
	if err != nil {
		return CacheResult{}, err
	}
	return CacheResult{Value: result.Value, Hit: result.Hit}, nil
}

// Set stores a value in Redis with the given TTL.
func (c *RedisIntrospectionCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	return c.client.Set(ctx, key, value, expiration)
}

// Del removes keys from Redis.
func (c *RedisIntrospectionCache) Del(ctx context.Context, keys ...string) (int64, error) {
	return c.client.Del(ctx, keys...)
}
