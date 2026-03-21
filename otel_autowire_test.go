package authclient

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
)

func TestInstrumentAll_AllComponents(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "c"}, nil
		},
	}
	cache := NewInMemoryCache(10)
	provider := &mockTokenProvider{
		tokenFunc: func(_ context.Context) (string, error) {
			return "tok", nil
		},
	}

	opts := []InstrumentationOption{WithTracerProvider(tp), WithMeterProvider(mp)}
	iv, ic, itp := InstrumentAll(validator, cache, provider, opts...)

	require.NotNil(t, iv)
	require.NotNil(t, ic)
	require.NotNil(t, itp)

	// Use each instrumented component
	_, err := iv.ValidateToken(context.Background(), "token")
	require.NoError(t, err)

	_ = ic.Set(context.Background(), "key", "val", 0)

	tok, err := itp.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "tok", tok)

	// Verify all produce spans
	spans := exporter.GetSpans()
	require.Len(t, spans, 3)
	spanNames := make([]string, 3)
	for i, s := range spans {
		spanNames[i] = s.Name
	}
	assert.Contains(t, spanNames, "authclient.validate_token")
	assert.Contains(t, spanNames, "authclient.cache.set")
	assert.Contains(t, spanNames, "authclient.token_provider.get_token")

	// Verify all produce metrics
	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.validate_token.total", 1, attribute.String("result", "success"))
	assertCounterValue(t, rm, "authclient.cache.ops.total", 1,
		attribute.String("operation", "set"), attribute.String("result", "success"))
	assertCounterValue(t, rm, "authclient.token_provider.total", 1, attribute.String("result", "success"))
}

func TestInstrumentAll_NilComponents(t *testing.T) {
	iv, ic, itp := InstrumentAll(nil, nil, nil)
	assert.Nil(t, iv)
	assert.Nil(t, ic)
	assert.Nil(t, itp)
}

func TestInstrumentAll_PartialNil(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "c"}, nil
		},
	}

	iv, ic, itp := InstrumentAll(validator, nil, nil, WithTracerProvider(tp), WithMeterProvider(mp))
	assert.NotNil(t, iv)
	assert.Nil(t, ic)
	assert.Nil(t, itp)
}

func TestInstrumentValidator_NilSafe(t *testing.T) {
	assert.Nil(t, InstrumentValidator(nil))
}

func TestInstrumentCache_NilSafe(t *testing.T) {
	assert.Nil(t, InstrumentCache(nil))
}

func TestInstrumentTokenProvider_NilSafe(t *testing.T) {
	assert.Nil(t, InstrumentTokenProvider(nil))
}
