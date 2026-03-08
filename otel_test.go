package authclient

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/otel"
	metricsdk "go.opentelemetry.io/otel/sdk/metric"
	tracesdk "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestInstrumentationConfig_Defaults(t *testing.T) {
	cfg := newInstrumentationConfig()

	assert.Equal(t, otel.GetTracerProvider(), cfg.tracerProvider)
	assert.Equal(t, otel.GetMeterProvider(), cfg.meterProvider)
	assert.NotNil(t, cfg.logger)
}

func TestInstrumentationConfig_WithTracerProvider(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := tracesdk.NewTracerProvider(tracesdk.WithSyncer(exporter))
	t.Cleanup(func() { tp.Shutdown(context.Background()) })

	cfg := newInstrumentationConfig(WithTracerProvider(tp))

	assert.Equal(t, tp, cfg.tracerProvider)
}

func TestInstrumentationConfig_WithMeterProvider(t *testing.T) {
	reader := metricsdk.NewManualReader()
	mp := metricsdk.NewMeterProvider(metricsdk.WithReader(reader))
	t.Cleanup(func() { mp.Shutdown(context.Background()) })

	cfg := newInstrumentationConfig(WithMeterProvider(mp))

	assert.Equal(t, mp, cfg.meterProvider)
}

func TestInstrumentationConfig_WithLogger(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))

	cfg := newInstrumentationConfig(WithLogger(logger))

	assert.Equal(t, logger, cfg.logger)
}

func TestInstrumentationConfig_NilLoggerFallsBackToDefault(t *testing.T) {
	cfg := newInstrumentationConfig(WithLogger(nil))

	assert.Equal(t, slog.Default(), cfg.logger)
}

// Note: These tests assume no other test in the process has modified the global OTel providers.
// Safe under -shuffle=on because global providers are not modified by any test in this package.
func TestInstrumentationConfig_NilTracerProviderFallsBackToGlobal(t *testing.T) {
	cfg := newInstrumentationConfig(WithTracerProvider(nil))

	assert.Equal(t, otel.GetTracerProvider(), cfg.tracerProvider)
}

func TestInstrumentationConfig_NilMeterProviderFallsBackToGlobal(t *testing.T) {
	cfg := newInstrumentationConfig(WithMeterProvider(nil))

	assert.Equal(t, otel.GetMeterProvider(), cfg.meterProvider)
}
