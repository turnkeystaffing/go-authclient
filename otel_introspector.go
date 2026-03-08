package authclient

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// Compile-time interface assertion.
var _ Introspector = (*instrumentedIntrospector)(nil)

// instrumentedIntrospector decorates Introspector with OTel spans only (no metrics).
// The Introspector interface does not expose cache/fallback metadata needed for
// meaningful counters. Logger is omitted because there are no metric creation warnings.
type instrumentedIntrospector struct {
	inner  Introspector
	tracer trace.Tracer
}

// NewInstrumentedIntrospector wraps an Introspector with OpenTelemetry tracing.
// Each Introspect call creates a span with active/error attributes.
// Panics if inner is nil (fail-fast constructor pattern).
//
// Only WithTracerProvider is effective for this decorator. WithMeterProvider and
// WithLogger are accepted for API consistency with NewInstrumentedValidator but
// are not used — the introspector emits spans only, no metrics. Cache hit/miss
// and fallback counters require metadata not exposed by the Introspector interface.
// See Story 6.4 Dev Notes for the design decision.
// The IntrospectionClient itself logs cache hits (Debug) and fallback activations (Warn).
//
// The returned Introspector is safe for concurrent use if the inner introspector is.
// Do not double-wrap: passing an already-instrumented introspector produces duplicate spans.
func NewInstrumentedIntrospector(inner Introspector, opts ...InstrumentationOption) Introspector {
	if inner == nil {
		panic("authclient.NewInstrumentedIntrospector: inner cannot be nil")
	}

	cfg := newInstrumentationConfig(opts...)
	tracer := cfg.tracerProvider.Tracer(tracerName, trace.WithInstrumentationVersion(instrumentationVersion))

	return &instrumentedIntrospector{
		inner:  inner,
		tracer: tracer,
	}
}

// Introspect validates the token via the inner introspector and records OTel span.
func (i *instrumentedIntrospector) Introspect(ctx context.Context, token string) (*IntrospectionResponse, error) {
	ctx, span := i.tracer.Start(ctx, "authclient.introspect", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	resp, err := i.inner.Introspect(ctx, token)
	if err != nil {
		// Use generic description in span status instead of raw err.Error()
		// to prevent leaking sensitive details from inner introspector errors (S1 security fix).
		span.SetStatus(codes.Error, "introspection_failed")
		span.RecordError(err)
		span.SetAttributes(attribute.String("authclient.introspection.result", "error"))
		// Return resp as-is (may be non-nil on partial failure) to preserve
		// transparent decoration contract (AC-2).
		return resp, err
	}

	attrs := []attribute.KeyValue{
		attribute.String("authclient.introspection.result", "success"),
	}
	if resp != nil {
		attrs = append(attrs, attribute.Bool("authclient.introspection.active", resp.Active))
	}
	span.SetAttributes(attrs...)
	return resp, nil
}
