package authclient

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// mockTokenProvider is a test double for TokenProvider.
type mockTokenProvider struct {
	tokenFunc func(ctx context.Context) (string, error)
}

func (m *mockTokenProvider) Token(ctx context.Context) (string, error) {
	return m.tokenFunc(ctx)
}

func TestInstrumentedTokenProvider_Success(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	inner := &mockTokenProvider{
		tokenFunc: func(_ context.Context) (string, error) {
			return "access-token-123", nil
		},
	}

	p := NewInstrumentedTokenProvider(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	token, err := p.Token(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "access-token-123", token)

	// Verify span
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, "authclient.token_provider.get_token", spans[0].Name)
	assert.Equal(t, codes.Unset, spans[0].Status.Code)
	assert.Equal(t, trace.SpanKindInternal, spans[0].SpanKind)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.token_provider.result", "success")

	// Verify no token value in span attributes
	for _, a := range spans[0].Attributes {
		assert.NotContains(t, string(a.Key), "token_value",
			"token value must NEVER appear in span attributes")
	}

	// Verify metrics
	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.token_provider.total", 1, attribute.String("result", "success"))
	assertHistogramCount(t, rm, "authclient.token_provider.duration", 1)
}

func TestInstrumentedTokenProvider_Error(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	networkErr := errors.New("network timeout")
	inner := &mockTokenProvider{
		tokenFunc: func(_ context.Context) (string, error) {
			return "", networkErr
		},
	}

	p := NewInstrumentedTokenProvider(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	token, err := p.Token(context.Background())

	assert.Empty(t, token)
	assert.ErrorIs(t, err, networkErr)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Error, spans[0].Status.Code)
	// S1 security fix: span status uses classified error type, not raw err.Error()
	assert.Equal(t, "error", spans[0].Status.Description)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.token_provider.result", "error")
	assertSpanAttribute(t, spans[0].Attributes, "authclient.token_provider.error_type", "error")
	assertErrorEventRecorded(t, spans[0])

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.token_provider.total", 1, attribute.String("result", "error"))
}

func TestInstrumentedTokenProvider_ClosedError(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	inner := &mockTokenProvider{
		tokenFunc: func(_ context.Context) (string, error) {
			return "", ErrTokenProviderClosed
		},
	}

	p := NewInstrumentedTokenProvider(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	_, err := p.Token(context.Background())

	assert.ErrorIs(t, err, ErrTokenProviderClosed)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Error, spans[0].Status.Code)
	assert.Equal(t, "closed", spans[0].Status.Description)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.token_provider.error_type", "closed")
}

func TestInstrumentedTokenProvider_NilInnerPanics(t *testing.T) {
	assert.PanicsWithValue(t, "authclient.NewInstrumentedTokenProvider: inner cannot be nil", func() {
		NewInstrumentedTokenProvider(nil)
	})
}

func TestInstrumentedTokenProvider_TransparentPassthrough(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	inner := &mockTokenProvider{
		tokenFunc: func(_ context.Context) (string, error) {
			return "tok", nil
		},
	}

	p := NewInstrumentedTokenProvider(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	token, err := p.Token(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "tok", token)
}

func TestInstrumentedTokenProvider_ConcurrentUse(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	inner := &mockTokenProvider{
		tokenFunc: func(_ context.Context) (string, error) {
			return "tok", nil
		},
	}

	p := NewInstrumentedTokenProvider(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.Token(context.Background())
		}()
	}
	wg.Wait()
}

func TestInstrumentedTokenProvider_SpanContextPropagated(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	var capturedCtx context.Context
	inner := &mockTokenProvider{
		tokenFunc: func(ctx context.Context) (string, error) {
			capturedCtx = ctx
			return "tok", nil
		},
	}

	p := NewInstrumentedTokenProvider(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	_, _ = p.Token(context.Background())

	require.NotNil(t, capturedCtx)
	span := trace.SpanFromContext(capturedCtx)
	assert.True(t, span.SpanContext().IsValid(), "inner should receive context with valid span")
}

func TestInstrumentedTokenProvider_DurationPositive(t *testing.T) {
	tp, _, mp, reader := setupTestOTel(t)

	inner := &mockTokenProvider{
		tokenFunc: func(_ context.Context) (string, error) {
			return "tok", nil
		},
	}

	p := NewInstrumentedTokenProvider(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	_, _ = p.Token(context.Background())

	rm := collectMetrics(t, reader)
	assertHistogramCount(t, rm, "authclient.token_provider.duration", 1)
}

func TestClassifyTokenProviderError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"closed", ErrTokenProviderClosed, "closed"},
		{"generic_error", errors.New("something else"), "error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, classifyTokenProviderError(tt.err))
		})
	}
}
