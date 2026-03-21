package authclient

import (
	"log/slog"
	"strings"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// InstrumentedGinBearerAuth wraps GinBearerAuth with an OTel counter that records
// auth middleware outcomes (success vs rejection with reason).
//
// This is a drop-in replacement for GinBearerAuth. The auth logic is fully delegated
// to GinBearerAuth — this wrapper only adds a counter. For span-level tracing of
// token validation, wrap the validator with NewInstrumentedValidator.
//
// Counter: authclient.middleware.auth.total
//   - result=success — token validated, claims stored in context
//   - result=rejected, reason=missing_header|invalid_format|empty_token|oversized|validation_failed
//
// Panics if validator is nil (fail-fast at startup).
func InstrumentedGinBearerAuth(validator TokenValidator, iOpts []InstrumentationOption, opts ...GinOption) gin.HandlerFunc {
	if validator == nil {
		panic("InstrumentedGinBearerAuth: validator cannot be nil")
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

	// Extract claimsKey from GinOptions to detect auth success via claims presence.
	cfg := ginConfig{
		claimsKey:    "auth_claims",
		errorHandler: ginDefaultErrorHandler,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	claimsKey := cfg.claimsKey

	inner := GinBearerAuth(validator, opts...)

	return func(c *gin.Context) {
		inner(c)

		attrs := []attribute.KeyValue{attribute.String("framework", "gin")}
		if _, exists := c.Get(claimsKey); exists {
			attrs = append(attrs, attribute.String("result", "success"))
		} else {
			attrs = append(attrs,
				attribute.String("result", "rejected"),
				attribute.String("reason", classifyGinAuthRejection(c)),
			)
		}
		recordMiddlewareCounter(counter, c.Request.Context(), attrs)
	}
}

// classifyGinAuthRejection examines request headers to determine why BearerAuth
// rejected the request. Called only when rejection is already known.
func classifyGinAuthRejection(c *gin.Context) string {
	authHeader := c.GetHeader("Authorization")
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

// InstrumentedGinRequireScope wraps GinRequireScope with an OTel counter that records
// scope check outcomes (pass vs denied).
//
// Counter: authclient.middleware.scope.total
//   - result=pass — scope check passed
//   - result=denied — required scope not present
//
// Panics if scope is empty (consistent with GinRequireScope).
func InstrumentedGinRequireScope(scope string, iOpts []InstrumentationOption, opts ...GinScopeOption) gin.HandlerFunc {
	if scope == "" {
		panic("InstrumentedGinRequireScope: scope cannot be empty")
	}

	iCfg := newInstrumentationConfig(iOpts...)
	meter := iCfg.meterProvider.Meter(meterName, metric.WithInstrumentationVersion(instrumentationVersion))

	counter, err := meter.Int64Counter("authclient.middleware.scope.total",
		metric.WithDescription("Total number of scope middleware invocations"),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		iCfg.logger.Warn("failed to create middleware scope counter", slog.String("error", err.Error()))
	}

	// Detect scope result via claims + HasScope check.
	scopeCfg := ginScopeConfig{
		claimsKey:    "auth_claims",
		errorHandler: ginDefaultErrorHandler,
	}
	for _, opt := range opts {
		opt(&scopeCfg)
	}
	claimsKey := scopeCfg.claimsKey

	inner := GinRequireScope(scope, opts...)

	return func(c *gin.Context) {
		inner(c)

		// Detect scope result via claims presence + scope check.
		// This is reliable regardless of downstream handler behavior.
		result := "denied"
		if val, exists := c.Get(claimsKey); exists {
			if claims, ok := val.(*Claims); ok && claims != nil && HasScope(claims, scope) {
				result = "pass"
			}
		}

		attrs := []attribute.KeyValue{
			attribute.String("result", result),
			attribute.String("scope", scope),
			attribute.String("framework", "gin"),
		}
		recordMiddlewareCounter(counter, c.Request.Context(), attrs)
	}
}
