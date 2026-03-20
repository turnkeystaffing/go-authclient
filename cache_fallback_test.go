package authclient

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testFallbackLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
}

// --- mock monitor ---

type mockMonitor struct {
	degraded atomic.Bool
}

func (m *mockMonitor) IsDegraded() bool { return m.degraded.Load() }
func (m *mockMonitor) MarkDegraded()    { m.degraded.Store(true) }
func (m *mockMonitor) MarkHealthy()     { m.degraded.Store(false) }

// --- mock failing cache ---

type failingCache struct {
	err error
}

func (c *failingCache) Get(_ context.Context, _ string) (CacheResult, error) {
	return CacheResult{}, c.err
}

func (c *failingCache) Set(_ context.Context, _ string, _ string, _ time.Duration) error {
	return c.err
}

func (c *failingCache) Del(_ context.Context, _ ...string) (int64, error) {
	return 0, c.err
}

// --- Constructor tests ---

func TestNewFallbackIntrospectionCache_PanicsOnNilPrimary(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t, "authclient.NewFallbackIntrospectionCache: primary cannot be nil", func() {
		NewFallbackIntrospectionCache(nil, NewInMemoryCache(10), &mockMonitor{}, testFallbackLogger())
	})
}

func TestNewFallbackIntrospectionCache_PanicsOnNilFallback(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t, "authclient.NewFallbackIntrospectionCache: fallback cannot be nil", func() {
		NewFallbackIntrospectionCache(NewInMemoryCache(10), nil, &mockMonitor{}, testFallbackLogger())
	})
}

func TestNewFallbackIntrospectionCache_PanicsOnNilMonitor(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t, "authclient.NewFallbackIntrospectionCache: monitor cannot be nil", func() {
		NewFallbackIntrospectionCache(NewInMemoryCache(10), NewInMemoryCache(10), nil, testFallbackLogger())
	})
}

func TestNewFallbackIntrospectionCache_PanicsOnNilLogger(t *testing.T) {
	t.Parallel()
	assert.PanicsWithValue(t, "authclient.NewFallbackIntrospectionCache: logger cannot be nil", func() {
		NewFallbackIntrospectionCache(NewInMemoryCache(10), NewInMemoryCache(10), &mockMonitor{}, nil)
	})
}

// --- Get tests ---

func TestFallbackCache_Get_UsesPrimaryWhenHealthy(t *testing.T) {
	primary := NewInMemoryCache(10)
	fallback := NewInMemoryCache(10)
	monitor := &mockMonitor{}

	_ = primary.Set(context.Background(), "key1", "from-primary", 5*time.Minute)
	_ = fallback.Set(context.Background(), "key1", "from-fallback", 5*time.Minute)

	cache := NewFallbackIntrospectionCache(primary, fallback, monitor, testFallbackLogger())

	result, err := cache.Get(context.Background(), "key1")
	require.NoError(t, err)
	assert.True(t, result.Hit)
	assert.Equal(t, "from-primary", result.Value)
}

func TestFallbackCache_Get_UsesFallbackWhenDegraded(t *testing.T) {
	primary := NewInMemoryCache(10)
	fallback := NewInMemoryCache(10)
	monitor := &mockMonitor{}
	monitor.MarkDegraded()

	_ = primary.Set(context.Background(), "key1", "from-primary", 5*time.Minute)
	_ = fallback.Set(context.Background(), "key1", "from-fallback", 5*time.Minute)

	cache := NewFallbackIntrospectionCache(primary, fallback, monitor, testFallbackLogger())

	result, err := cache.Get(context.Background(), "key1")
	require.NoError(t, err)
	assert.True(t, result.Hit)
	assert.Equal(t, "from-fallback", result.Value)
}

func TestFallbackCache_Get_FallsBackOnPrimaryError(t *testing.T) {
	primary := &failingCache{err: errors.New("redis down")}
	fallback := NewInMemoryCache(10)
	monitor := &mockMonitor{}

	_ = fallback.Set(context.Background(), "key1", "from-fallback", 5*time.Minute)

	cache := NewFallbackIntrospectionCache(primary, fallback, monitor, testFallbackLogger())

	result, err := cache.Get(context.Background(), "key1")
	require.NoError(t, err)
	assert.True(t, result.Hit)
	assert.Equal(t, "from-fallback", result.Value)
	assert.True(t, monitor.IsDegraded(), "monitor should be marked degraded")
}

func TestFallbackCache_Get_CacheMiss(t *testing.T) {
	primary := NewInMemoryCache(10)
	fallback := NewInMemoryCache(10)
	monitor := &mockMonitor{}

	cache := NewFallbackIntrospectionCache(primary, fallback, monitor, testFallbackLogger())

	result, err := cache.Get(context.Background(), "nonexistent")
	require.NoError(t, err)
	assert.False(t, result.Hit)
}

// --- Set tests ---

func TestFallbackCache_Set_DualWriteWhenHealthy(t *testing.T) {
	primary := NewInMemoryCache(10)
	fallback := NewInMemoryCache(10)
	monitor := &mockMonitor{}

	cache := NewFallbackIntrospectionCache(primary, fallback, monitor, testFallbackLogger())

	err := cache.Set(context.Background(), "key1", "value1", 5*time.Minute)
	require.NoError(t, err)

	// Both caches should have the value
	pResult, _ := primary.Get(context.Background(), "key1")
	assert.True(t, pResult.Hit)
	assert.Equal(t, "value1", pResult.Value)

	fResult, _ := fallback.Get(context.Background(), "key1")
	assert.True(t, fResult.Hit)
	assert.Equal(t, "value1", fResult.Value)
}

func TestFallbackCache_Set_OnlyFallbackWhenDegraded(t *testing.T) {
	primary := NewInMemoryCache(10)
	fallback := NewInMemoryCache(10)
	monitor := &mockMonitor{}
	monitor.MarkDegraded()

	cache := NewFallbackIntrospectionCache(primary, fallback, monitor, testFallbackLogger())

	err := cache.Set(context.Background(), "key1", "value1", 5*time.Minute)
	require.NoError(t, err)

	// Only fallback should have the value
	pResult, _ := primary.Get(context.Background(), "key1")
	assert.False(t, pResult.Hit)

	fResult, _ := fallback.Get(context.Background(), "key1")
	assert.True(t, fResult.Hit)
	assert.Equal(t, "value1", fResult.Value)
}

func TestFallbackCache_Set_PrimaryError_StillWritesFallback(t *testing.T) {
	primary := &failingCache{err: errors.New("redis down")}
	fallback := NewInMemoryCache(10)
	monitor := &mockMonitor{}

	cache := NewFallbackIntrospectionCache(primary, fallback, monitor, testFallbackLogger())

	err := cache.Set(context.Background(), "key1", "value1", 5*time.Minute)
	require.NoError(t, err)

	fResult, _ := fallback.Get(context.Background(), "key1")
	assert.True(t, fResult.Hit)
	assert.Equal(t, "value1", fResult.Value)
	assert.True(t, monitor.IsDegraded())
}

// --- Del tests ---

func TestFallbackCache_Del_DeletesFromBothWhenHealthy(t *testing.T) {
	primary := NewInMemoryCache(10)
	fallback := NewInMemoryCache(10)
	monitor := &mockMonitor{}

	_ = primary.Set(context.Background(), "key1", "v", 5*time.Minute)
	_ = fallback.Set(context.Background(), "key1", "v", 5*time.Minute)

	cache := NewFallbackIntrospectionCache(primary, fallback, monitor, testFallbackLogger())

	deleted, err := cache.Del(context.Background(), "key1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	pResult, _ := primary.Get(context.Background(), "key1")
	assert.False(t, pResult.Hit)
	fResult, _ := fallback.Get(context.Background(), "key1")
	assert.False(t, fResult.Hit)
}

func TestFallbackCache_Del_OnlyFallbackWhenDegraded(t *testing.T) {
	primary := NewInMemoryCache(10)
	fallback := NewInMemoryCache(10)
	monitor := &mockMonitor{}
	monitor.MarkDegraded()

	_ = primary.Set(context.Background(), "key1", "v", 5*time.Minute)
	_ = fallback.Set(context.Background(), "key1", "v", 5*time.Minute)

	cache := NewFallbackIntrospectionCache(primary, fallback, monitor, testFallbackLogger())

	deleted, err := cache.Del(context.Background(), "key1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)

	// Primary untouched, fallback deleted
	pResult, _ := primary.Get(context.Background(), "key1")
	assert.True(t, pResult.Hit)
	fResult, _ := fallback.Get(context.Background(), "key1")
	assert.False(t, fResult.Hit)
}

func TestFallbackCache_Del_PrimaryError_StillDeletesFallback(t *testing.T) {
	primary := &failingCache{err: errors.New("redis down")}
	fallback := NewInMemoryCache(10)
	monitor := &mockMonitor{}

	_ = fallback.Set(context.Background(), "key1", "v", 5*time.Minute)

	cache := NewFallbackIntrospectionCache(primary, fallback, monitor, testFallbackLogger())

	deleted, err := cache.Del(context.Background(), "key1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), deleted)
	assert.True(t, monitor.IsDegraded())
}

// --- Recovery test ---

func TestFallbackCache_Recovery_ResumesPrimaryAfterMonitorRecovers(t *testing.T) {
	primary := NewInMemoryCache(10)
	fallback := NewInMemoryCache(10)
	monitor := &mockMonitor{}

	cache := NewFallbackIntrospectionCache(primary, fallback, monitor, testFallbackLogger())

	// Start degraded
	monitor.MarkDegraded()
	_ = cache.Set(context.Background(), "key1", "during-degradation", 5*time.Minute)

	// Only fallback has it
	pResult, _ := primary.Get(context.Background(), "key1")
	assert.False(t, pResult.Hit)

	// Recover
	monitor.MarkHealthy()

	_ = cache.Set(context.Background(), "key2", "after-recovery", 5*time.Minute)

	// Both should have key2
	pResult, _ = primary.Get(context.Background(), "key2")
	assert.True(t, pResult.Hit)
	assert.Equal(t, "after-recovery", pResult.Value)

	fResult, _ := fallback.Get(context.Background(), "key2")
	assert.True(t, fResult.Hit)
	assert.Equal(t, "after-recovery", fResult.Value)
}

// --- Interface compliance ---

func TestFallbackIntrospectionCache_ImplementsInterface(t *testing.T) {
	t.Parallel()
	var _ IntrospectionCache = (*FallbackIntrospectionCache)(nil)
}
