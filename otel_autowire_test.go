package authclient

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

func TestInstrumentValidator_NilSafe(t *testing.T) {
	assert.Nil(t, InstrumentValidator(nil))
}

func TestInstrumentValidator_Wraps(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	inner := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "c"}, nil
		},
	}

	v := InstrumentValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	require.NotNil(t, v)

	_, err := v.ValidateToken(context.Background(), "token")
	require.NoError(t, err)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, "authclient.validate_token", spans[0].Name)
}

func TestInstrumentCache_NilSafe(t *testing.T) {
	assert.Nil(t, InstrumentCache(nil))
}

func TestInstrumentCache_Wraps(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	inner := NewInMemoryCache(10)
	c := InstrumentCache(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	require.NotNil(t, c)

	_ = c.Set(context.Background(), "key", "val", time.Minute)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, "authclient.cache.set", spans[0].Name)
}

func TestInstrumentTokenProvider_NilSafe(t *testing.T) {
	assert.Nil(t, InstrumentTokenProvider(nil))
}

func TestInstrumentTokenProvider_Wraps(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	inner := &mockTokenProvider{
		tokenFunc: func(_ context.Context) (string, error) {
			return "tok", nil
		},
	}

	p := InstrumentTokenProvider(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	require.NotNil(t, p)

	tok, err := p.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "tok", tok)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, "authclient.token_provider.get_token", spans[0].Name)
}

// TestWiringOrder_CacheMustBeInstrumentedFirst demonstrates the correct
// dependency order: cache must be instrumented BEFORE being passed to
// IntrospectionClient, otherwise cache operations are not traced.
func TestWiringOrder_CacheMustBeInstrumentedFirst(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)
	opts := []InstrumentationOption{WithTracerProvider(tp), WithMeterProvider(mp)}

	// 1. Instrument cache FIRST
	rawCache := NewInMemoryCache(100)
	instrumentedCache := InstrumentCache(rawCache, opts...)

	// 2. Use instrumented cache via the interface (simulating what
	//    IntrospectionClient does internally when calling cache.Get/Set)
	_ = instrumentedCache.Set(context.Background(), "key", "value", time.Minute)
	result, err := instrumentedCache.Get(context.Background(), "key")
	require.NoError(t, err)
	assert.True(t, result.Hit)

	// Verify cache operations produced spans
	spans := exporter.GetSpans()
	require.Len(t, spans, 2)
	assert.Equal(t, "authclient.cache.set", spans[0].Name)
	assert.Equal(t, "authclient.cache.get", spans[1].Name)

	// Verify cache metrics
	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.cache.ops.total", 1,
		attribute.String("operation", "set"), attribute.String("result", "success"))
	assertCounterValue(t, rm, "authclient.cache.ops.total", 1,
		attribute.String("operation", "get"), attribute.String("result", "hit"))
}
