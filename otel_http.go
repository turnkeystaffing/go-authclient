package authclient

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// InstrumentedHTTPBearerAuth wraps HTTPBearerAuth with an OTel counter that records
// auth middleware outcomes (success vs rejection with reason).
//
// This is a drop-in replacement for HTTPBearerAuth. The auth logic is fully delegated
// to HTTPBearerAuth — this wrapper only adds a counter. For span-level tracing of
// token validation, wrap the validator with NewInstrumentedValidator.
//
// Counter: authclient.middleware.auth.total
//   - result=success — token validated, request passed to next handler
//   - result=rejected, reason=missing_header|invalid_format|empty_token|oversized|validation_failed
//
// Panics if validator is nil (fail-fast at startup).
func InstrumentedHTTPBearerAuth(validator TokenValidator, iOpts []InstrumentationOption, opts ...HTTPOption) func(http.Handler) http.Handler {
	if validator == nil {
		panic("InstrumentedHTTPBearerAuth: validator cannot be nil")
	}

	iCfg := newInstrumentationConfig(iOpts...)
	meter := iCfg.meterProvider.Meter(meterName, metric.WithInstrumentationVersion(instrumentationVersion))

	counter, err := meter.Int64Counter("authclient.middleware.auth.total",
		metric.WithDescription("Total number of auth middleware invocations"),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		iCfg.logger.Warn("failed to create middleware auth counter", slog.String("error", err.Error()))
	}

	bearerAuth := HTTPBearerAuth(validator, opts...)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var passed bool
			proxy := http.HandlerFunc(func(w2 http.ResponseWriter, r2 *http.Request) {
				passed = true
				next.ServeHTTP(w2, r2)
			})

			bearerAuth(proxy).ServeHTTP(w, r)

			attrs := []attribute.KeyValue{attribute.String("framework", "net_http")}
			if passed {
				attrs = append(attrs, attribute.String("result", "success"))
			} else {
				attrs = append(attrs,
					attribute.String("result", "rejected"),
					attribute.String("reason", classifyHTTPAuthRejection(r)),
				)
			}
			recordMiddlewareCounter(counter, r.Context(), attrs)
		})
	}
}

// classifyHTTPAuthRejection examines request headers to determine why BearerAuth
// rejected the request. Called only when rejection is already known.
func classifyHTTPAuthRejection(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "missing_header"
	}
	if len(authHeader) < 7 || !strings.EqualFold(authHeader[:7], "Bearer ") {
		return "invalid_format"
	}
	token := strings.TrimSpace(authHeader[7:])
	if token == "" {
		return "empty_token"
	}
	if len(token) > MaxBearerTokenLength {
		return "oversized"
	}
	return "validation_failed"
}

// recordMiddlewareCounter is a nil-safe counter helper shared by middleware instrumentors.
func recordMiddlewareCounter(counter metric.Int64Counter, ctx context.Context, attrs []attribute.KeyValue) {
	if counter == nil {
		return
	}
	counter.Add(ctx, 1, metric.WithAttributes(attrs...))
}
