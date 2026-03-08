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
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// mockIntrospector is a test double for Introspector.
type mockIntrospector struct {
	resp *IntrospectionResponse
	err  error
}

func (m *mockIntrospector) Introspect(_ context.Context, _ string) (*IntrospectionResponse, error) {
	return m.resp, m.err
}

func TestInstrumentedIntrospector_ActiveToken(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	inner := &mockIntrospector{resp: &IntrospectionResponse{Active: true, Sub: "user1"}}
	intr := NewInstrumentedIntrospector(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	resp, err := intr.Introspect(context.Background(), "token")
	require.NoError(t, err)
	assert.True(t, resp.Active)
	assert.Equal(t, "user1", resp.Sub)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, "authclient.introspect", spans[0].Name)
	assert.Equal(t, codes.Unset, spans[0].Status.Code)
	assert.Equal(t, trace.SpanKindInternal, spans[0].SpanKind)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.introspection.result", "success")
	assertSpanBoolAttribute(t, spans[0].Attributes, "authclient.introspection.active", true)
}

func TestInstrumentedIntrospector_InactiveToken(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	inner := &mockIntrospector{resp: &IntrospectionResponse{Active: false}}
	intr := NewInstrumentedIntrospector(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	resp, err := intr.Introspect(context.Background(), "token")
	require.NoError(t, err)
	assert.False(t, resp.Active)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.introspection.result", "success")
	assertSpanBoolAttribute(t, spans[0].Attributes, "authclient.introspection.active", false)
}

func TestInstrumentedIntrospector_Error(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	inner := &mockIntrospector{err: errors.New("endpoint unreachable")}
	intr := NewInstrumentedIntrospector(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	resp, err := intr.Introspect(context.Background(), "token")
	assert.Nil(t, resp)
	assert.Error(t, err)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Error, spans[0].Status.Code)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.introspection.result", "error")
	assertErrorEventRecorded(t, spans[0])
}

func TestInstrumentedIntrospector_NilInnerPanics(t *testing.T) {
	assert.PanicsWithValue(t, "authclient.NewInstrumentedIntrospector: inner cannot be nil", func() {
		NewInstrumentedIntrospector(nil)
	})
}

func TestInstrumentedIntrospector_TransparentPassthrough(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	expectedResp := &IntrospectionResponse{Active: true, Sub: "user1", Scope: "read write"}
	inner := &mockIntrospector{resp: expectedResp}
	intr := NewInstrumentedIntrospector(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	resp, err := intr.Introspect(context.Background(), "token")
	require.NoError(t, err)
	assert.Same(t, expectedResp, resp)
}

func TestInstrumentedIntrospector_ConcurrentUse(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	inner := &mockIntrospector{resp: &IntrospectionResponse{Active: true, Sub: "user1"}}
	intr := NewInstrumentedIntrospector(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = intr.Introspect(context.Background(), "token")
		}()
	}
	wg.Wait()
}

func TestInstrumentedIntrospector_NilRespSuccess(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	// Inner returns (nil, nil) — violates contract but must not panic.
	inner := &mockIntrospector{resp: nil, err: nil}
	intr := NewInstrumentedIntrospector(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	resp, err := intr.Introspect(context.Background(), "token")
	assert.NoError(t, err)
	assert.Nil(t, resp)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.introspection.result", "success")
	// active attribute should NOT be present when resp is nil.
	for _, a := range spans[0].Attributes {
		assert.NotEqual(t, "authclient.introspection.active", string(a.Key),
			"active should not be set when resp is nil")
	}
}

func TestInstrumentedIntrospector_ErrorPreservesResponse(t *testing.T) {
	tp, exporter, _, _ := setupTestOTel(t)

	// Inner returns both a response AND an error (partial failure).
	// Decorator must preserve both per transparent decoration contract (AC-2).
	partialResp := &IntrospectionResponse{Active: false, Sub: "user1"}
	inner := &mockIntrospector{resp: partialResp, err: fmt.Errorf("partial: %w", ErrIntrospectionFailed)}
	intr := NewInstrumentedIntrospector(inner, WithTracerProvider(tp))

	resp, err := intr.Introspect(context.Background(), "token")
	assert.Same(t, partialResp, resp, "decorator must preserve inner's response on error")
	assert.ErrorIs(t, err, ErrIntrospectionFailed)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Error, spans[0].Status.Code)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.introspection.result", "error")
}

func TestInstrumentedIntrospector_SpanContextPropagated(t *testing.T) {
	tp, _, mp, _ := setupTestOTel(t)

	var capturedCtx context.Context
	inner := &contextCapturingIntrospector{
		resp:       &IntrospectionResponse{Active: true},
		captureCtx: func(ctx context.Context) { capturedCtx = ctx },
	}
	intr := NewInstrumentedIntrospector(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	_, _ = intr.Introspect(context.Background(), "token")

	require.NotNil(t, capturedCtx)
	span := trace.SpanFromContext(capturedCtx)
	assert.True(t, span.SpanContext().IsValid(), "inner should receive context with valid span")
}

func TestInstrumentedIntrospector_TracerProviderOnly(t *testing.T) {
	tp, exporter, _, _ := setupTestOTel(t)

	// Verify decorator works with only WithTracerProvider (no WithMeterProvider) —
	// confirming documented API surface from Pass 1 F1.
	inner := &mockIntrospector{resp: &IntrospectionResponse{Active: true, Sub: "u1"}}
	intr := NewInstrumentedIntrospector(inner, WithTracerProvider(tp))

	resp, err := intr.Introspect(context.Background(), "token")
	require.NoError(t, err)
	assert.True(t, resp.Active)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assertSpanAttribute(t, spans[0].Attributes, "authclient.introspection.result", "success")
}

func TestInstrumentedIntrospector_WrappedSentinelError(t *testing.T) {
	tp, exporter, _, _ := setupTestOTel(t)

	// Test with wrapped sentinel error to verify span.RecordError handles error chains.
	wrappedErr := fmt.Errorf("network timeout: %w", ErrIntrospectionFailed)
	inner := &mockIntrospector{err: wrappedErr}
	intr := NewInstrumentedIntrospector(inner, WithTracerProvider(tp))

	resp, err := intr.Introspect(context.Background(), "token")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrIntrospectionFailed)

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Error, spans[0].Status.Code)
	assertErrorEventRecorded(t, spans[0])
}

func TestInstrumentedIntrospector_ErrorMessageInSpanStatus(t *testing.T) {
	tp, exporter, mp, _ := setupTestOTel(t)

	inner := &mockIntrospector{err: errors.New("connection refused")}
	intr := NewInstrumentedIntrospector(inner, WithTracerProvider(tp), WithMeterProvider(mp))

	_, _ = intr.Introspect(context.Background(), "token")

	spans := exporter.GetSpans()
	require.Len(t, spans, 1)
	assert.Equal(t, codes.Error, spans[0].Status.Code)
	// S1 security fix: span status uses generic description, not raw err.Error()
	assert.Equal(t, "introspection_failed", spans[0].Status.Description)
}

// contextCapturingIntrospector captures the context passed to Introspect.
type contextCapturingIntrospector struct {
	resp       *IntrospectionResponse
	captureCtx func(context.Context)
}

func (i *contextCapturingIntrospector) Introspect(ctx context.Context, _ string) (*IntrospectionResponse, error) {
	i.captureCtx(ctx)
	return i.resp, nil
}

// --- Test helpers ---

func assertSpanBoolAttribute(t *testing.T, attrs []attribute.KeyValue, key string, expected bool) {
	t.Helper()
	for _, a := range attrs {
		if string(a.Key) == key {
			assert.Equal(t, expected, a.Value.AsBool())
			return
		}
	}
	t.Errorf("span attribute %s not found", key)
}

func assertErrorEventRecorded(t *testing.T, span tracetest.SpanStub) {
	t.Helper()
	for _, event := range span.Events {
		if event.Name == "exception" {
			return
		}
	}
	t.Error("expected error event recorded in span")
}
