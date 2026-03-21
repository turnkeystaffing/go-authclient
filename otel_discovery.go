package authclient

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/valyala/fasthttp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// InstrumentedDiscoveryHandler wraps a DiscoveryHandler with OTel request counters.
// The handler logic is fully delegated — this wrapper only adds metrics.
type InstrumentedDiscoveryHandler struct {
	inner          *DiscoveryHandler
	requestCounter metric.Int64Counter
	reloadCounter  metric.Int64Counter
}

// NewInstrumentedDiscoveryHandler wraps a DiscoveryHandler with OTel metrics.
// Panics if handler is nil (fail-fast constructor pattern).
//
// Counters:
//   - authclient.discovery.requests.total — per-request counter with method and status attributes
//   - authclient.discovery.reload.total — reload attempt counter with result attribute
func NewInstrumentedDiscoveryHandler(handler *DiscoveryHandler, opts ...InstrumentationOption) *InstrumentedDiscoveryHandler {
	if handler == nil {
		panic("authclient.NewInstrumentedDiscoveryHandler: handler cannot be nil")
	}

	cfg := newInstrumentationConfig(opts...)
	meter := cfg.meterProvider.Meter(meterName, metric.WithInstrumentationVersion(instrumentationVersion))

	reqCounter, err := meter.Int64Counter("authclient.discovery.requests.total",
		metric.WithDescription("Total number of discovery handler requests"),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		cfg.logger.Warn("failed to create discovery requests counter", slog.String("error", err.Error()))
	}

	reloadCounter, err := meter.Int64Counter("authclient.discovery.reload.total",
		metric.WithDescription("Total number of discovery handler reload attempts"),
		metric.WithUnit("{call}"),
	)
	if err != nil {
		cfg.logger.Warn("failed to create discovery reload counter", slog.String("error", err.Error()))
	}

	return &InstrumentedDiscoveryHandler{
		inner:          handler,
		requestCounter: reqCounter,
		reloadCounter:  reloadCounter,
	}
}

// ServeHTTP implements http.Handler and records request metrics.
func (h *InstrumentedDiscoveryHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	method := "GET"
	status := "200"
	if r.Method != http.MethodGet {
		method = "other"
		status = "405"
	}

	h.inner.ServeHTTP(w, r)

	if h.requestCounter != nil {
		h.requestCounter.Add(r.Context(), 1, metric.WithAttributes(
			attribute.String("method", method),
			attribute.String("status", status),
		))
	}
}

// GinHandler returns a gin.HandlerFunc that serves the manifest and records request metrics.
func (h *InstrumentedDiscoveryHandler) GinHandler() gin.HandlerFunc {
	ginHandler := h.inner.GinHandler()

	return func(c *gin.Context) {
		method := "GET"
		status := "200"
		if c.Request.Method != http.MethodGet {
			method = "other"
			status = "405"
		}

		ginHandler(c)

		if h.requestCounter != nil {
			h.requestCounter.Add(c.Request.Context(), 1, metric.WithAttributes(
				attribute.String("method", method),
				attribute.String("status", status),
			))
		}
	}
}

// FastHTTPHandler returns a fasthttp.RequestHandler that serves the manifest and records request metrics.
func (h *InstrumentedDiscoveryHandler) FastHTTPHandler() fasthttp.RequestHandler {
	fhHandler := h.inner.FastHTTPHandler()

	return func(ctx *fasthttp.RequestCtx) {
		method := "GET"
		status := "200"
		if !ctx.IsGet() {
			method = "other"
			status = "405"
		}

		fhHandler(ctx)

		if h.requestCounter != nil {
			h.requestCounter.Add(ctx, 1, metric.WithAttributes(
				attribute.String("method", method),
				attribute.String("status", status),
			))
		}
	}
}

// Reload delegates to the inner handler's Reload and records the outcome.
func (h *InstrumentedDiscoveryHandler) Reload() error {
	err := h.inner.Reload()

	if h.reloadCounter != nil {
		result := "success"
		if err != nil {
			result = "error"
		}
		h.reloadCounter.Add(context.Background(), 1, metric.WithAttributes(
			attribute.String("result", result),
		))
	}

	return err
}

// Close delegates to the inner handler's Close.
func (h *InstrumentedDiscoveryHandler) Close() {
	h.inner.Close()
}
