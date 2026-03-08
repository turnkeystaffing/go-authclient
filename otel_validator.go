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

// maxSpanAttributeBytes limits span attribute values to prevent size inflation from oversized claims.
const maxSpanAttributeBytes = 256

// Compile-time interface assertion.
var _ TokenValidator = (*instrumentedValidator)(nil)

type instrumentedValidator struct {
	inner              TokenValidator
	tracer             trace.Tracer
	validationCounter  metric.Int64Counter
	validationDuration metric.Float64Histogram
	logger             *slog.Logger
}

// NewInstrumentedValidator wraps a TokenValidator with OpenTelemetry tracing and metrics.
// Each ValidateToken call creates a span and records latency/result metrics.
// Panics if inner is nil (fail-fast constructor pattern).
//
// Metric/span creation failures are logged at Warn level but never fail the auth operation.
// The returned TokenValidator is safe for concurrent use if the inner validator is.
// Do not double-wrap: passing an already-instrumented validator produces duplicate spans and metrics.
func NewInstrumentedValidator(inner TokenValidator, opts ...InstrumentationOption) TokenValidator {
	if inner == nil {
		panic("authclient.NewInstrumentedValidator: inner cannot be nil")
	}

	cfg := newInstrumentationConfig(opts...)
	tracer := cfg.tracerProvider.Tracer(tracerName, trace.WithInstrumentationVersion(instrumentationVersion))
	meter := cfg.meterProvider.Meter(meterName, metric.WithInstrumentationVersion(instrumentationVersion))

	// Counter uses bare "result" attribute per AC spec (not namespaced like span attributes).
	counter, err := meter.Int64Counter("authclient.validate_token.total",
		metric.WithDescription("Total number of token validations"),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		cfg.logger.Warn("failed to create validate_token counter", slog.String("error", err.Error()))
	}

	histogram, err := meter.Float64Histogram("authclient.validate_token.duration",
		metric.WithDescription("Token validation duration"),
		metric.WithUnit("ms"),
	)
	if err != nil {
		cfg.logger.Warn("failed to create validate_token duration histogram", slog.String("error", err.Error()))
	}

	return &instrumentedValidator{
		inner:              inner,
		tracer:             tracer,
		validationCounter:  counter,
		validationDuration: histogram,
		logger:             cfg.logger,
	}
}

// ValidateToken validates the token and records OTel span and metrics.
func (v *instrumentedValidator) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	ctx, span := v.tracer.Start(ctx, "authclient.validate_token", trace.WithSpanKind(trace.SpanKindInternal))
	defer span.End()

	start := time.Now()
	claims, err := v.inner.ValidateToken(ctx, token)
	durationMs := float64(time.Since(start).Nanoseconds()) / 1e6

	if err != nil {
		errorType := classifyValidationError(err)
		// Use classified error type in span status description instead of raw err.Error()
		// to prevent leaking sensitive details from inner validator errors (S1 security fix).
		span.SetStatus(codes.Error, errorType)
		// RecordError captures the full error as an exception event for debugging.
		// The span status description above uses the classified type (not raw err.Error())
		// to prevent sensitive data in high-level status. Full error in events is acceptable
		// given OTel backends must be on authenticated internal networks (see InstrumentationOption godoc).
		span.RecordError(err)
		span.SetAttributes(
			attribute.String("authclient.validation.result", "error"),
			attribute.String("authclient.validation.error_type", errorType),
		)
		if v.validationCounter != nil {
			v.validationCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "error")))
		}
	} else {
		attrs := make([]attribute.KeyValue, 0, 3)
		attrs = append(attrs, attribute.String("authclient.validation.result", "success"))
		if claims != nil {
			// Bound ClientID length to prevent span size inflation from oversized JWT claims (S2 security fix).
			clientID := claims.ClientID
			if len(clientID) > maxSpanAttributeBytes {
				clientID = clientID[:maxSpanAttributeBytes]
			}
			attrs = append(attrs,
				attribute.String("authclient.claims.client_id", clientID),
				attribute.Int("authclient.claims.scope_count", len(claims.Scopes)),
			)
		}
		span.SetAttributes(attrs...)
		if v.validationCounter != nil {
			v.validationCounter.Add(ctx, 1, metric.WithAttributes(attribute.String("result", "success")))
		}
	}

	if v.validationDuration != nil {
		// Include result attribute so dashboards can compute p99 by success/error separately.
		resultLabel := "success"
		if err != nil {
			resultLabel = "error"
		}
		v.validationDuration.Record(ctx, durationMs, metric.WithAttributes(attribute.String("result", resultLabel)))
	}

	return claims, err
}

// classifyValidationError maps sentinel errors to string labels for the
// authclient.validation.error_type span attribute.
// CRITICAL ordering: ErrTokenInactive wraps ErrTokenInvalid, so it must be checked first.
func classifyValidationError(err error) string {
	switch {
	case errors.Is(err, ErrTokenExpired):
		return "token_expired"
	case errors.Is(err, ErrTokenMalformed):
		return "token_malformed"
	case errors.Is(err, ErrTokenOversized):
		return "token_oversized"
	case errors.Is(err, ErrAlgorithmNotAllowed):
		return "algorithm_not_allowed"
	case errors.Is(err, ErrMissingClientID):
		return "missing_client_id"
	case errors.Is(err, ErrTokenNotYetValid):
		return "token_not_yet_valid"
	case errors.Is(err, ErrTokenUnverifiable):
		return "token_unverifiable"
	case errors.Is(err, ErrTokenInactive):
		return "token_inactive"
	case errors.Is(err, ErrTokenInvalid):
		return "token_invalid"
	case errors.Is(err, ErrIntrospectionFailed):
		return "introspection_failed"
	default:
		return "unknown"
	}
}
