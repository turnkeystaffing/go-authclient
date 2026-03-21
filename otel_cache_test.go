package authclient

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// mockCache is a test double for IntrospectionCache.
type mockCache struct {
	getFunc func(ctx context.Context, key string) (CacheResult, error)
	setFunc func(ctx context.Context, key string, value string, expiration time.Duration) error
	delFunc func(ctx context.Context, keys ...string) (int64, error)
}

func (m *mockCache) Get(ctx context.Context, key string) (CacheResult, error) {
	return m.getFunc(ctx, key)
}

func (m *mockCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	return m.setFunc(ctx, key, value, expiration)
}

func (m *mockCache) Del(ctx context.Context, keys ...string) (int64, error) {
	return m.delFunc(ctx, keys...)
}

func TestInstrumentedCache_GetHit(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	inner := &mockCache{
		getFunc: func(_ context.Context, _ string) (CacheResult, error) {
			return CacheResult{Value: "cached_data", Hit: true}, nil
		},
	}

	cache := NewInstrumentedCache(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	result, err := cache.Get(context.Background(), "test-key")

	require.NoError(t, err)
	assert.True(t, result.Hit)
	assert.Equal(t, "cached_data", result.Value)

	// Verify span
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, "authclient.cache.get", spans[0].Name)
	assert.Equal(t, codes.Unset, spans[0].Status.Code)
	assert.Equal(t, trace.SpanKindInternal, spans[0].SpanKind)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.cache.operation", "get")
	assertSpanAttribute(t, spans[0].Attributes, "authclient.cache.result", "hit")

	// Verify metrics
	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.cache.ops.total", 1,
		attribute.String("operation", "get"), attribute.String("result", "hit"))
	assertHistogramCount(t, rm, "authclient.cache.ops.duration", 1)
}

func TestInstrumentedCache_GetMiss(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	inner := &mockCache{
		getFunc: func(_ context.Context, _ string) (CacheResult, error) {
			return CacheResult{}, nil
		},
	}

	cache := NewInstrumentedCache(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	result, err := cache.Get(context.Background(), "test-key")

	require.NoError(t, err)
	assert.False(t, result.Hit)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.cache.result", "miss")

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.cache.ops.total", 1,
		attribute.String("operation", "get"), attribute.String("result", "miss"))
}

func TestInstrumentedCache_GetError(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	cacheErr := errors.New("redis connection refused")
	inner := &mockCache{
		getFunc: func(_ context.Context, _ string) (CacheResult, error) {
			return CacheResult{}, cacheErr
		},
	}

	cache := NewInstrumentedCache(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	_, err := cache.Get(context.Background(), "test-key")

	assert.ErrorIs(t, err, cacheErr)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Error, spans[0].Status.Code)
	assert.Equal(t, "cache_get_failed", spans[0].Status.Description)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.cache.result", "error")
	assertErrorEventRecorded(t, spans[0])

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.cache.ops.total", 1,
		attribute.String("operation", "get"), attribute.String("result", "error"))
}

func TestInstrumentedCache_SetSuccess(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	inner := &mockCache{
		setFunc: func(_ context.Context, _ string, _ string, _ time.Duration) error {
			return nil
		},
	}

	cache := NewInstrumentedCache(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	err := cache.Set(context.Background(), "test-key", "value", 5*time.Minute)

	require.NoError(t, err)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, "authclient.cache.set", spans[0].Name)
	assert.Equal(t, codes.Unset, spans[0].Status.Code)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.cache.operation", "set")
	assertSpanAttribute(t, spans[0].Attributes, "authclient.cache.result", "success")

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.cache.ops.total", 1,
		attribute.String("operation", "set"), attribute.String("result", "success"))
}

func TestInstrumentedCache_SetError(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	setErr := errors.New("redis write error")
	inner := &mockCache{
		setFunc: func(_ context.Context, _ string, _ string, _ time.Duration) error {
			return setErr
		},
	}

	cache := NewInstrumentedCache(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	err := cache.Set(context.Background(), "test-key", "value", 5*time.Minute)

	assert.ErrorIs(t, err, setErr)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Error, spans[0].Status.Code)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.cache.result", "error")

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.cache.ops.total", 1,
		attribute.String("operation", "set"), attribute.String("result", "error"))
}

func TestInstrumentedCache_DelSuccess(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	inner := &mockCache{
		delFunc: func(_ context.Context, _ ...string) (int64, error) {
			return 2, nil
		},
	}

	cache := NewInstrumentedCache(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	deleted, err := cache.Del(context.Background(), "key1", "key2")

	require.NoError(t, err)
	assert.Equal(t, int64(2), deleted)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, "authclient.cache.del", spans[0].Name)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.cache.operation", "del")
	assertSpanAttribute(t, spans[0].Attributes, "authclient.cache.result", "success")
	assertSpanInt64Attribute(t, spans[0].Attributes, "authclient.cache.deleted_count", 2)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.cache.ops.total", 1,
		attribute.String("operation", "del"), attribute.String("result", "success"))
}

func TestInstrumentedCache_DelError(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	delErr := errors.New("redis del error")
	inner := &mockCache{
		delFunc: func(_ context.Context, _ ...string) (int64, error) {
			return 0, delErr
		},
	}

	cache := NewInstrumentedCache(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	_, err := cache.Del(context.Background(), "key1")

	assert.ErrorIs(t, err, delErr)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Error, spans[0].Status.Code)

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.cache.ops.total", 1,
		attribute.String("operation", "del"), attribute.String("result", "error"))
}

func TestInstrumentedCache_NilInnerPanics(t *testing.T) {
	assert.PanicsWithValue(t, "authclient.NewInstrumentedCache: inner cannot be nil", func() {
		NewInstrumentedCache(nil)
	})
}

func TestInstrumentedCache_TransparentPassthrough(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	expected := CacheResult{Value: "data", Hit: true}
	inner := &mockCache{
		getFunc: func(_ context.Context, _ string) (CacheResult, error) {
			return expected, nil
		},
	}

	cache := NewInstrumentedCache(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	result, err := cache.Get(context.Background(), "key")

	require.NoError(t, err)
	assert.Equal(t, expected, result)
}

func TestInstrumentedCache_ConcurrentUse(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	inner := &mockCache{
		getFunc: func(_ context.Context, _ string) (CacheResult, error) {
			return CacheResult{Hit: true, Value: "v"}, nil
		},
		setFunc: func(_ context.Context, _ string, _ string, _ time.Duration) error {
			return nil
		},
		delFunc: func(_ context.Context, _ ...string) (int64, error) {
			return 1, nil
		},
	}

	cache := NewInstrumentedCache(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, _ = cache.Get(context.Background(), "key")
		}()
		go func() {
			defer wg.Done()
			_ = cache.Set(context.Background(), "key", "val", time.Minute)
		}()
		go func() {
			defer wg.Done()
			_, _ = cache.Del(context.Background(), "key")
		}()
	}
	wg.Wait()
}

func TestInstrumentedCache_SpanContextPropagated(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	var capturedCtx context.Context
	inner := &mockCache{
		getFunc: func(ctx context.Context, _ string) (CacheResult, error) {
			capturedCtx = ctx
			return CacheResult{}, nil
		},
	}

	cache := NewInstrumentedCache(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	_, _ = cache.Get(context.Background(), "key")

	require.NotNil(t, capturedCtx)
	span := trace.SpanFromContext(capturedCtx)
	assert.True(t, span.SpanContext().IsValid(), "inner should receive context with valid span")
}

// --- Test helper ---

func assertSpanInt64Attribute(t *testing.T, attrs []attribute.KeyValue, key string, expected int64) {
	t.Helper()
	for _, a := range attrs {
		if string(a.Key) == key {
			assert.Equal(t, expected, a.Value.AsInt64())
			return
		}
	}
	t.Errorf("span attribute %s not found", key)
}
