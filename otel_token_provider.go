package authclient

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Compile-time interface assertion.
var _ TokenProvider = (*instrumentedTokenProvider)(nil)

type instrumentedTokenProvider struct {
	inner    TokenProvider
	tracer   trace.Tracer
	counter  metric.Int64Counter
	duration metric.Float64Histogram
	logger   *slog.Logger
}

// NewInstrumentedTokenProvider wraps a TokenProvider with OpenTelemetry tracing and metrics.
// Each Token call creates a span and records latency/result metrics.
// Panics if inner is nil (fail-fast constructor pattern).
//
// Security: The token value is NEVER recorded in span attributes or metric labels.
// Only the result (success/error) and error classification are recorded.
//
// Metric/span creation failures are logged at Warn level but never fail token operations.
// The returned TokenProvider is safe for concurrent use if the inner provider is.
// Do not double-wrap: passing an already-instrumented provider produces duplicate spans and metrics.
func NewInstrumentedTokenProvider(inner TokenProvider, opts ...InstrumentationOption) TokenProvider {
	if inner == nil {
		panic("authclient.NewInstrumentedTokenProvider: inner cannot be nil")
	}

	cfg := newInstrumentationConfig(opts...)
	tracer := cfg.tracerProvider.Tracer(tracerName, trace.WithInstrumentationVersion(instrumentationVersion))
	meter := cfg.meterProvider.Meter(meterName, metric.WithInstrumentationVersion(instrumentationVersion))

	counter, err := meter.Int64Counter("authclient.token_provider.total",
		metric.WithDescription("Total number of token provider calls"),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		cfg.logger.Warn("failed to create token_provider counter", slog.String("error", err.Error()))
	}

	histogram, err := meter.Float64Histogram("authclient.token_provider.duration",
		metric.WithDescription("Token provider call duration"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		cfg.logger.Warn("failed to create token_provider duration histogram", slog.String("error", err.Error()))
	}

	return &instrumentedTokenProvider{
		inner:    inner,
		tracer:   tracer,
		counter:  counter,
		duration: histogram,
		logger:   cfg.logger,
	}
}

// Token obtains a bearer token and records OTel span and metrics.
func (p *instrumentedTokenProvider) Token(ctx context.Context) (string, error) {
	ctx, span := p.tracer.Start(ctx, "authclient.token_provider.get_token", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	start := time.Now()
	token, err := p.inner.Token(ctx)
	durationMs := float64(time.Since(start).Nanoseconds()) / 1e6

	if err != nil {
		errorType := classifyTokenProviderError(err)
		// Use classified error type in span status description instead of raw err.Error()
		// to prevent leaking sensitive details (S1 security fix).
		span.SetStatus(codes.Error, errorType)
		span.RecordError(err)
		span.SetAttributes(
			attribute.String("authclient.token_provider.result", "error"),
			attribute.String("authclient.token_provider.error_type", errorType),
		)
		if p.counter != nil {
			p.counter.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "error")))
		}
	} else {
		span.SetAttributes(attribute.String("authclient.token_provider.result", "success"))
		if p.counter != nil {
			p.counter.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "success")))
		}
	}

	if p.duration != nil {
		resultLabel := "success"
		if err != nil {
			resultLabel = "error"
		}
		p.duration.Record(ctx, durationMs, metric.WithAttributes(attribute.String("result", resultLabel)))
	}

	return token, err
}

// classifyTokenProviderError maps sentinel errors to string labels for span attributes.
func classifyTokenProviderError(err error) string {
	if errors.Is(err, ErrTokenProviderClosed) {
		return "closed"
	}
	return "error"
}
