package authclient

import (
	"context"
	"log/slog"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Compile-time interface assertion.
var _ IntrospectionCache = (*instrumentedCache)(nil)

type instrumentedCache struct {
	inner       IntrospectionCache
	tracer      trace.Tracer
	opsTotal    metric.Int64Counter
	opsDuration metric.Float64Histogram
	logger      *slog.Logger
}

// NewInstrumentedCache wraps an IntrospectionCache with OpenTelemetry tracing and metrics.
// Each Get/Set/Del call creates a span and records latency/result metrics.
// Panics if inner is nil (fail-fast constructor pattern).
//
// Security: Cache keys (SHA-256 hashes of tokens) and cache values (serialized
// IntrospectionResponses) are NOT recorded in span attributes to prevent data leakage.
//
// Metric/span creation failures are logged at Warn level but never fail cache operations.
// The returned IntrospectionCache is safe for concurrent use if the inner cache is.
// Do not double-wrap: passing an already-instrumented cache produces duplicate spans and metrics.
func NewInstrumentedCache(inner IntrospectionCache, opts ...InstrumentationOption) IntrospectionCache {
	if inner == nil {
		panic("authclient.NewInstrumentedCache: inner cannot be nil")
	}

	cfg := newInstrumentationConfig(opts...)
	tracer := cfg.tracerProvider.Tracer(tracerName, trace.WithInstrumentationVersion(instrumentationVersion))
	meter := cfg.meterProvider.Meter(meterName, metric.WithInstrumentationVersion(instrumentationVersion))

	counter, err := meter.Int64Counter("authclient.cache.ops.total",
		metric.WithDescription("Total number of cache operations"),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		cfg.logger.Warn("failed to create cache ops counter", slog.String("error", err.Error()))
	}

	histogram, err := meter.Float64Histogram("authclient.cache.ops.duration",
		metric.WithDescription("Cache operation duration"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		cfg.logger.Warn("failed to create cache ops duration histogram", slog.String("error", err.Error()))
	}

	return &instrumentedCache{
		inner:       inner,
		tracer:      tracer,
		opsTotal:    counter,
		opsDuration: histogram,
		logger:      cfg.logger,
	}
}

// Get retrieves a cached value and records OTel span and metrics.
func (c *instrumentedCache) Get(ctx context.Context, key string) (CacheResult, error) {
	ctx, span := c.tracer.Start(ctx, "authclient.cache.get", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	start := time.Now()
	result, err := c.inner.Get(ctx, key)
	durationMs := float64(time.Since(start).Nanoseconds()) / 1e6

	opAttr := attribute.String("operation", "get")
	var resultLabel string

	if err != nil {
		resultLabel = "error"
		span.SetStatus(codes.Error, "cache_get_failed")
		span.RecordError(err)
		span.SetAttributes(
			attribute.String("authclient.cache.operation", "get"),
			attribute.String("authclient.cache.result", "error"),
		)
	} else {
		if result.Hit {
			resultLabel = "hit"
		} else {
			resultLabel = "miss"
		}
		span.SetAttributes(
			attribute.String("authclient.cache.operation", "get"),
			attribute.String("authclient.cache.result", resultLabel),
		)
	}

	resultAttr := attribute.String("result", resultLabel)
	if c.opsTotal != nil {
		c.opsTotal.Add(ctx, 1, metric.WithAttributes(opAttr, resultAttr))
	}
	if c.opsDuration != nil {
		c.opsDuration.Record(ctx, durationMs, metric.WithAttributes(opAttr, resultAttr))
	}

	return result, err
}

// Set stores a value and records OTel span and metrics.
func (c *instrumentedCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	ctx, span := c.tracer.Start(ctx, "authclient.cache.set", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	start := time.Now()
	err := c.inner.Set(ctx, key, value, expiration)
	durationMs := float64(time.Since(start).Nanoseconds()) / 1e6

	opAttr := attribute.String("operation", "set")
	resultLabel := "success"

	if err != nil {
		resultLabel = "error"
		span.SetStatus(codes.Error, "cache_set_failed")
		span.RecordError(err)
		span.SetAttributes(
			attribute.String("authclient.cache.operation", "set"),
			attribute.String("authclient.cache.result", "error"),
		)
	} else {
		span.SetAttributes(
			attribute.String("authclient.cache.operation", "set"),
			attribute.String("authclient.cache.result", "success"),
		)
	}

	resultAttr := attribute.String("result", resultLabel)
	if c.opsTotal != nil {
		c.opsTotal.Add(ctx, 1, metric.WithAttributes(opAttr, resultAttr))
	}
	if c.opsDuration != nil {
		c.opsDuration.Record(ctx, durationMs, metric.WithAttributes(opAttr, resultAttr))
	}

	return err
}

// Del removes keys and records OTel span and metrics.
func (c *instrumentedCache) Del(ctx context.Context, keys ...string) (int64, error) {
	ctx, span := c.tracer.Start(ctx, "authclient.cache.del", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	start := time.Now()
	deleted, err := c.inner.Del(ctx, keys...)
	durationMs := float64(time.Since(start).Nanoseconds()) / 1e6

	opAttr := attribute.String("operation", "del")
	resultLabel := "success"

	if err != nil {
		resultLabel = "error"
		span.SetStatus(codes.Error, "cache_del_failed")
		span.RecordError(err)
		span.SetAttributes(
			attribute.String("authclient.cache.operation", "del"),
			attribute.String("authclient.cache.result", "error"),
		)
	} else {
		span.SetAttributes(
			attribute.String("authclient.cache.operation", "del"),
			attribute.String("authclient.cache.result", "success"),
			attribute.Int64("authclient.cache.deleted_count", deleted),
		)
	}

	resultAttr := attribute.String("result", resultLabel)
	if c.opsTotal != nil {
		c.opsTotal.Add(ctx, 1, metric.WithAttributes(opAttr, resultAttr))
	}
	if c.opsDuration != nil {
		c.opsDuration.Record(ctx, durationMs, metric.WithAttributes(opAttr, resultAttr))
	}

	return deleted, err
}
