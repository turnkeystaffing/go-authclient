package authclient

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewInMemoryCache_PanicsOnZeroSize(t *testing.T) {
	assert.PanicsWithValue(t, "authclient.NewInMemoryCache: maxSize must be >= 1", func() {
		NewInMemoryCache(0)
	})
}

func TestInMemoryCache_GetMiss(t *testing.T) {
	cache := NewInMemoryCache(10)
	result, err := cache.Get(context.Background(), "nonexistent")
	require.NoError(t, err)
	assert.False(t, result.Hit)
	assert.Empty(t, result.Value)
}

func TestInMemoryCache_SetAndGet(t *testing.T) {
	cache := NewInMemoryCache(10)
	ctx := context.Background()

	err := cache.Set(ctx, "key1", "value1", time.Minute)
	require.NoError(t, err)

	result, err := cache.Get(ctx, "key1")
	require.NoError(t, err)
	assert.True(t, result.Hit)
	assert.Equal(t, "value1", result.Value)
}

func TestInMemoryCache_Expiration(t *testing.T) {
	cache := NewInMemoryCache(10)
	ctx := context.Background()

	err := cache.Set(ctx, "key1", "value1", time.Millisecond)
	require.NoError(t, err)

	time.Sleep(5 * time.Millisecond)

	result, err := cache.Get(ctx, "key1")
	require.NoError(t, err)
	assert.False(t, result.Hit, "expired entry should not be returned")
}

func TestInMemoryCache_Del(t *testing.T) {
	cache := NewInMemoryCache(10)
	ctx := context.Background()

	_ = cache.Set(ctx, "key1", "v1", time.Minute)
	_ = cache.Set(ctx, "key2", "v2", time.Minute)

	deleted, err := cache.Del(ctx, "key1", "key3")
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted, "only key1 existed")

	result, _ := cache.Get(ctx, "key1")
	assert.False(t, result.Hit)

	result, _ = cache.Get(ctx, "key2")
	assert.True(t, result.Hit)
}

func TestInMemoryCache_EvictsExpiredOnFull(t *testing.T) {
	cache := NewInMemoryCache(2)
	ctx := context.Background()

	_ = cache.Set(ctx, "expired", "v", time.Millisecond)
	_ = cache.Set(ctx, "live", "v", time.Minute)

	time.Sleep(5 * time.Millisecond)

	// Cache is full (2 entries), but one is expired. Set should evict the expired one.
	err := cache.Set(ctx, "new", "v", time.Minute)
	require.NoError(t, err)

	result, _ := cache.Get(ctx, "expired")
	assert.False(t, result.Hit)

	result, _ = cache.Get(ctx, "live")
	assert.True(t, result.Hit)

	result, _ = cache.Get(ctx, "new")
	assert.True(t, result.Hit)
}

func TestInMemoryCache_EvictsOldestWhenFull(t *testing.T) {
	cache := NewInMemoryCache(2)
	ctx := context.Background()

	_ = cache.Set(ctx, "first", "v", 1*time.Minute)
	_ = cache.Set(ctx, "second", "v", 10*time.Minute)

	// Both are live; "first" has earliest expiration, so it gets evicted.
	err := cache.Set(ctx, "third", "v", time.Minute)
	require.NoError(t, err)

	result, _ := cache.Get(ctx, "first")
	assert.False(t, result.Hit, "earliest-expiring entry should be evicted")

	result, _ = cache.Get(ctx, "second")
	assert.True(t, result.Hit)

	result, _ = cache.Get(ctx, "third")
	assert.True(t, result.Hit)
}

func TestInMemoryCache_ImplementsInterface(t *testing.T) {
	var _ IntrospectionCache = NewInMemoryCache(1)
}
