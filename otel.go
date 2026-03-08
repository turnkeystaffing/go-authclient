package authclient

import (
	"log/slog"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

const (
	tracerName             = "authclient"
	meterName              = "authclient"
	instrumentationVersion = "1.0.0"
)

// InstrumentationOption configures OpenTelemetry instrumentation for authclient decorators.
//
// Security: Instrumented decorators record span attributes including validation results,
// error types, client_id, scope_count, and introspection active status. These attributes
// are sent to the configured OTel backend. Ensure OTel collectors and backends are deployed
// on authenticated, internal-only networks. Duration histograms may reveal timing patterns
// about token validation paths; metric endpoints should be rate-limited and authenticated.
type InstrumentationOption func(*instrumentationConfig)

type instrumentationConfig struct {
	tracerProvider trace.TracerProvider
	meterProvider  metric.MeterProvider
	logger         *slog.Logger
}

func newInstrumentationConfig(opts ...InstrumentationOption) *instrumentationConfig {
	cfg := &instrumentationConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	cfg.applyDefaults()
	return cfg
}

func (c *instrumentationConfig) applyDefaults() {
	if c.tracerProvider == nil {
		c.tracerProvider = otel.GetTracerProvider()
	}
	if c.meterProvider == nil {
		c.meterProvider = otel.GetMeterProvider()
	}
	if c.logger == nil {
		c.logger = slog.Default()
	}
}

// WithTracerProvider sets the TracerProvider for instrumentation.
// When nil or not set, otel.GetTracerProvider() is used.
func WithTracerProvider(tp trace.TracerProvider) InstrumentationOption {
	return func(c *instrumentationConfig) {
		c.tracerProvider = tp
	}
}

// WithMeterProvider sets the MeterProvider for instrumentation.
// When nil or not set, otel.GetMeterProvider() is used.
func WithMeterProvider(mp metric.MeterProvider) InstrumentationOption {
	return func(c *instrumentationConfig) {
		c.meterProvider = mp
	}
}

// WithLogger sets the logger for instrumentation warning messages (e.g. metric creation failures).
// When nil or not set, slog.Default() is used.
func WithLogger(l *slog.Logger) InstrumentationOption {
	return func(c *instrumentationConfig) {
		c.logger = l
	}
}
