package authclient

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	metricsdk "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// setupTestOTel creates in-memory OTel providers for testing.
func setupTestOTel(t *testing.T) (*tracesdk.TracerProvider, *tracetest.InMemoryExporter, *metricsdk.MeterProvider, *metricsdk.ManualReader) {
	t.Helper()
	spanExporter := tracetest.NewInMemoryExporter()
	tp := tracesdk.NewTracerProvider(tracesdk.WithSyncer(spanExporter))
	metricReader := metricsdk.NewManualReader()
	mp := metricsdk.NewMeterProvider(metricsdk.WithReader(metricReader))
	t.Cleanup(func() {
		tp.Shutdown(context.Background())
		mp.Shutdown(context.Background())
	})
	return tp, spanExporter, mp, metricReader
}

func TestInstrumentedValidator_Success(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	inner := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "test-client", Scopes: []string{"read", "write"}}, nil
		},
	}

	v := NewInstrumentedValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	claims, err := v.ValidateToken(context.Background(), "token")

	require.NoError(t, err)
	assert.Equal(t, "test-client", claims.ClientID)
	assert.Equal(t, []string{"read", "write"}, claims.Scopes)

	// Verify span
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	span := spans[0]
	assert.Equal(t, "authclient.validate_token", span.Name)
	assert.Equal(t, codes.Unset, span.Status.Code)
	assert.Equal(t, trace.SpanKindInternal, span.SpanKind)
	assertSpanAttribute(t, span.Attributes, "authclient.validation.result", "success")
	assertSpanAttribute(t, span.Attributes, "authclient.claims.client_id", "test-client")
	assertSpanIntAttribute(t, span.Attributes, "authclient.claims.scope_count", 2)

	// Verify metrics
	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.validate_token.total", 1, attribute.String("result", "success"))
	assertHistogramCount(t, rm, "authclient.validate_token.duration", 1)
}

func TestInstrumentedValidator_Error(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	inner := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenExpired
		},
	}
	v := NewInstrumentedValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	claims, err := v.ValidateToken(context.Background(), "token")

	assert.Nil(t, claims)
	assert.ErrorIs(t, err, ErrTokenExpired)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	span := spans[0]
	assert.Equal(t, codes.Error, span.Status.Code)
	// S1 security fix: span status uses classified error type, not raw err.Error()
	assert.Equal(t, "token_expired", span.Status.Description)
	assertSpanAttribute(t, span.Attributes, "authclient.validation.result", "error")
	assertSpanAttribute(t, span.Attributes, "authclient.validation.error_type", "token_expired")

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.validate_token.total", 1, attribute.String("result", "error"))
}

func TestInstrumentedValidator_TransparentPassthrough(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	expectedClaims := &Claims{ClientID: "abc", Scopes: []string{"s1"}}
	inner := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return expectedClaims, nil
		},
	}
	v := NewInstrumentedValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	claims, err := v.ValidateToken(context.Background(), "token")
	require.NoError(t, err)
	assert.Same(t, expectedClaims, claims)
}

func TestInstrumentedValidator_NilInnerPanics(t *testing.T) {
	assert.PanicsWithValue(t, "authclient.NewInstrumentedValidator: inner cannot be nil", func() {
		NewInstrumentedValidator(nil)
	})
}

func TestClassifyValidationError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"token_expired", ErrTokenExpired, "token_expired"},
		{"token_malformed", ErrTokenMalformed, "token_malformed"},
		{"token_oversized", ErrTokenOversized, "token_oversized"},
		{"algorithm_not_allowed", ErrAlgorithmNotAllowed, "algorithm_not_allowed"},
		{"missing_client_id", ErrMissingClientID, "missing_client_id"},
		{"token_not_yet_valid", ErrTokenNotYetValid, "token_not_yet_valid"},
		{"token_unverifiable", ErrTokenUnverifiable, "token_unverifiable"},
		{"token_inactive", ErrTokenInactive, "token_inactive"},
		{"token_invalid", ErrTokenInvalid, "token_invalid"},
		{"introspection_failed", ErrIntrospectionFailed, "introspection_failed"},
		{"unknown", errors.New("something else"), "unknown"},
		// Wrapped errors must classify correctly via errors.Is chain traversal
		{"wrapped_token_inactive", fmt.Errorf("wrap: %w", ErrTokenInactive), "token_inactive"},
		{"wrapped_token_invalid", fmt.Errorf("wrap: %w", ErrTokenInvalid), "token_invalid"},
		{"wrapped_token_expired", fmt.Errorf("context: %w", ErrTokenExpired), "token_expired"},
		{"wrapped_token_oversized", fmt.Errorf("context: %w", ErrTokenOversized), "token_oversized"},
		{"wrapped_algorithm_not_allowed", fmt.Errorf("context: %w", ErrAlgorithmNotAllowed), "algorithm_not_allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, classifyValidationError(tt.err))
		})
	}
}

func TestClassifyValidationError_InactiveBeforeInvalid(t *testing.T) {
	// ErrTokenInactive wraps ErrTokenInvalid. Verify ordering is correct.
	assert.True(t, errors.Is(ErrTokenInactive, ErrTokenInvalid), "ErrTokenInactive should wrap ErrTokenInvalid")
	assert.Equal(t, "token_inactive", classifyValidationError(ErrTokenInactive))
}

func TestInstrumentedValidator_ErrorRecordedInSpan(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	inner := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenMalformed
		},
	}
	v := NewInstrumentedValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	_, _ = v.ValidateToken(context.Background(), "token")

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	// Verify span has error events recorded
	require.NotEmpty(t, spans[0].Events)
	foundError := false
	for _, event := range spans[0].Events {
		if event.Name == "exception" {
			foundError = true
			break
		}
	}
	assert.True(t, foundError, "expected error event recorded in span")
}

func TestInstrumentedValidator_DurationRecorded(t *testing.T) {
	tp, _, mp, reader := setupTestOTel(t)

	inner := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "c"}, nil
		},
	}
	v := NewInstrumentedValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	_, _ = v.ValidateToken(context.Background(), "token")

	rm := collectMetrics(t, reader)
	assertHistogramCount(t, rm, "authclient.validate_token.duration", 1)
}

func TestInstrumentedValidator_ConcurrentUse(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	inner := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "c", Scopes: []string{"read"}}, nil
		},
	}
	v := NewInstrumentedValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = v.ValidateToken(context.Background(), "token")
		}()
	}
	wg.Wait()
}

func TestInstrumentedValidator_NilClaimsSuccess(t *testing.T) {
	tp, exporter, mp, reader := setupTestOTel(t)

	// Inner returns (nil, nil) — violates contract but must not panic (F2 nil guard).
	inner := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, nil
		},
	}
	v := NewInstrumentedValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	claims, err := v.ValidateToken(context.Background(), "token")
	assert.NoError(t, err)
	assert.Nil(t, claims)

	// Span should have result=success but no client_id or scope_count.
	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.validation.result", "success")
	// Verify client_id is NOT present when claims is nil.
	for _, a := range spans[0].Attributes {
		assert.NotEqual(t, "authclient.claims.client_id", string(a.Key),
			"client_id should not be set when claims is nil")
	}

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.validate_token.total", 1, attribute.String("result", "success"))
}

func TestInstrumentedValidator_OversizedClientIDTruncated(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	// S2 security test: oversized ClientID must be truncated in span attributes.
	oversized := make([]byte, 1024)
	for i := range oversized {
		oversized[i] = 'X'
	}
	inner := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: string(oversized), Scopes: []string{"read"}}, nil
		},
	}
	v := NewInstrumentedValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	_, err := v.ValidateToken(context.Background(), "token")
	require.NoError(t, err)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	for _, a := range spans[0].Attributes {
		if string(a.Key) == "authclient.claims.client_id" {
			assert.Equal(t, 256, len(a.Value.AsString()),
				"oversized ClientID should be truncated to 256 chars")
			return
		}
	}
	t.Error("client_id attribute not found")
}

func TestInstrumentedValidator_ClientIDBoundary(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	// Exactly maxSpanAttributeBytes (256) chars — should NOT be truncated.
	exact := make([]byte, maxSpanAttributeBytes)
	for i := range exact {
		exact[i] = 'A'
	}
	inner := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: string(exact), Scopes: []string{"r"}}, nil
		},
	}
	v := NewInstrumentedValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	_, err := v.ValidateToken(context.Background(), "token")
	require.NoError(t, err)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	for _, a := range spans[0].Attributes {
		if string(a.Key) == "authclient.claims.client_id" {
			assert.Equal(t, maxSpanAttributeBytes, len(a.Value.AsString()),
				"exactly maxSpanAttributeBytes should NOT be truncated")
			break
		}
	}

	// 257 chars — should be truncated to 256.
	exporter.Reset()
	overBy1 := make([]byte, maxSpanAttributeBytes+1)
	for i := range overBy1 {
		overBy1[i] = 'B'
	}
	inner2 := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: string(overBy1), Scopes: []string{"r"}}, nil
		},
	}
	v2 := NewInstrumentedValidator(inner2, WithTracerProvider(tp), WithMeterProvider(mp))
	_, err = v2.ValidateToken(context.Background(), "token")
	require.NoError(t, err)

	spans = exporter.GetSpans()
	require.Len(t, spans, 1)
	for _, a := range spans[0].Attributes {
		if string(a.Key) == "authclient.claims.client_id" {
			assert.Equal(t, maxSpanAttributeBytes, len(a.Value.AsString()),
				"maxSpanAttributeBytes+1 should be truncated to maxSpanAttributeBytes")
			return
		}
	}
	t.Error("client_id attribute not found")
}

func TestInstrumentedValidator_SpanContextPropagated(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	var capturedCtx context.Context
	inner := &mockTokenValidator{
		ValidateTokenFunc: func(ctx context.Context, _ string) (*Claims, error) {
			capturedCtx = ctx
			return &Claims{ClientID: "c"}, nil
		},
	}
	v := NewInstrumentedValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	_, _ = v.ValidateToken(context.Background(), "token")

	// The inner validator should receive a context with an active span.
	require.NotNil(t, capturedCtx)
	span := trace.SpanFromContext(capturedCtx)
	assert.True(t, span.SpanContext().IsValid(), "inner should receive context with valid span")
}

func TestInstrumentedValidator_DurationPositive(t *testing.T) {
	tp, _, mp, reader := setupTestOTel(t)

	inner := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "c"}, nil
		},
	}
	v := NewInstrumentedValidator(inner, WithTracerProvider(tp), WithMeterProvider(mp))
	_, _ = v.ValidateToken(context.Background(), "token")

	rm := collectMetrics(t, reader)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == "authclient.validate_token.duration" {
				hist, ok := m.Data.(metricdata.Histogram[float64])
				require.True(t, ok)
				require.NotEmpty(t, hist.DataPoints)
				assert.Greater(t, hist.DataPoints[0].Sum, 0.0,
					"duration should be strictly positive")
				return
			}
		}
	}
	t.Error("histogram authclient.validate_token.duration not found")
}

// --- Test helpers ---

func collectMetrics(t *testing.T, reader *metricsdk.ManualReader) *metricdata.ResourceMetrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(context.Background(), &rm))
	return &rm
}

func assertCounterValue(t *testing.T, rm *metricdata.ResourceMetrics, name string, expectedValue int64, attrs ...attribute.KeyValue) {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				sum, ok := m.Data.(metricdata.Sum[int64])
				require.True(t, ok, "expected Sum[int64] for %s", name)
				for _, dp := range sum.DataPoints {
					if containsAttributes(dp.Attributes, attrs) {
						assert.Equal(t, expectedValue, dp.Value)
						return
					}
				}
			}
		}
	}
	t.Errorf("counter %s not found with expected attributes", name)
}

func assertHistogramCount(t *testing.T, rm *metricdata.ResourceMetrics, name string, expectedCount uint64) {
	t.Helper()
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				hist, ok := m.Data.(metricdata.Histogram[float64])
				require.True(t, ok, "expected Histogram[float64] for %s", name)
				require.NotEmpty(t, hist.DataPoints)
				assert.Equal(t, expectedCount, hist.DataPoints[0].Count)
				return
			}
		}
	}
	t.Errorf("histogram %s not found", name)
}

func containsAttributes(set attribute.Set, attrs []attribute.KeyValue) bool {
	for _, a := range attrs {
		v, exists := set.Value(a.Key)
		if !exists || v != a.Value {
			return false
		}
	}
	return true
}

func assertSpanAttribute(t *testing.T, attrs []attribute.KeyValue, key, expected string) {
	t.Helper()
	for _, a := range attrs {
		if string(a.Key) == key {
			assert.Equal(t, expected, a.Value.AsString())
			return
		}
	}
	t.Errorf("span attribute %s not found", key)
}

func assertSpanIntAttribute(t *testing.T, attrs []attribute.KeyValue, key string, expected int) {
	t.Helper()
	for _, a := range attrs {
		if string(a.Key) == key {
			assert.Equal(t, int64(expected), a.Value.AsInt64())
			return
		}
	}
	t.Errorf("span attribute %s not found", key)
}
