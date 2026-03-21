package authclient

import (
	"log/slog"
	"strings"

	"github.com/valyala/fasthttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// InstrumentedFastHTTPBearerAuth wraps FastHTTPBearerAuth with an OTel counter that
// records auth middleware outcomes (success vs rejection with reason).
//
// This is a drop-in replacement for FastHTTPBearerAuth. The auth logic is fully delegated
// to FastHTTPBearerAuth — this wrapper only adds a counter. For span-level tracing of
// token validation, wrap the validator with NewInstrumentedValidator.
//
// Counter: authclient.middleware.auth.total
//   - result=success — token validated, claims stored in UserValues
//   - result=rejected, reason=missing_header|invalid_format|empty_token|oversized|validation_failed
//
// Panics if validator is nil (fail-fast at startup).
func InstrumentedFastHTTPBearerAuth(validator TokenValidator, iOpts []InstrumentationOption, opts ...FastHTTPOption) func(fasthttp.RequestHandler) fasthttp.RequestHandler {
	if validator == nil {
		panic("InstrumentedFastHTTPBearerAuth: validator cannot be nil")
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

	// Extract claimsKey from FastHTTPOptions to detect auth success via claims presence.
	cfg := fasthttpConfig{
		claimsKey:    DefaultClaimsKey,
		clientIDKey:  DefaultClientIDKey,
		contextKey:   DefaultContextKey,
		errorHandler: defaultErrorHandler,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	claimsKey := cfg.claimsKey

	inner := FastHTTPBearerAuth(validator, opts...)

	return func(next fasthttp.RequestHandler) fasthttp.RequestHandler {
		wrappedInner := inner(next)

		return func(ctx *fasthttp.RequestCtx) {
			wrappedInner(ctx)

			attrs := []attribute.KeyValue{attribute.String("framework", "fasthttp")}
			if ctx.UserValue(claimsKey) != nil {
				attrs = append(attrs, attribute.String("result", "success"))
			} else {
				attrs = append(attrs,
					attribute.String("result", "rejected"),
					attribute.String("reason", classifyFastHTTPAuthRejection(ctx)),
				)
			}
			recordMiddlewareCounter(counter, ctx, attrs)
		}
	}
}

// classifyFastHTTPAuthRejection examines request headers to determine why BearerAuth
// rejected the request. Called only when rejection is already known.
func classifyFastHTTPAuthRejection(ctx *fasthttp.RequestCtx) string {
	authHeader := string(ctx.Request.Header.Peek("Authorization"))
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
