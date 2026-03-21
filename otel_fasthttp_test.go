package authclient

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"go.opentelemetry.io/otel/attribute"
)

func TestInstrumentedFastHTTPBearerAuth_Success(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "test"}, nil
		},
	}

	mw := InstrumentedFastHTTPBearerAuth(validator, []InstrumentationOption{WithMeterProvider(mp)})
	next := func(ctx *fasthttp.RequestCtx) {
		ctx.SetStatusCode(fasthttp.StatusOK)
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Authorization", "Bearer valid-token")

	mw(next)(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "success"),
		attribute.String("framework", "fasthttp"),
	)
}

func TestInstrumentedFastHTTPBearerAuth_MissingHeader(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			t.Fatal("validator should not be called")
			return nil, nil
		},
	}

	mw := InstrumentedFastHTTPBearerAuth(validator, []InstrumentationOption{WithMeterProvider(mp)})
	next := func(_ *fasthttp.RequestCtx) {
		t.Fatal("next should not be called")
	}

	ctx := &fasthttp.RequestCtx{}

	mw(next)(ctx)

	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "rejected"),
		attribute.String("reason", "missing_header"),
		attribute.String("framework", "fasthttp"),
	)
}

func TestInstrumentedFastHTTPBearerAuth_InvalidFormat(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, nil
		},
	}

	mw := InstrumentedFastHTTPBearerAuth(validator, []InstrumentationOption{WithMeterProvider(mp)})
	next := func(_ *fasthttp.RequestCtx) {}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Authorization", "Basic abc123")

	mw(next)(ctx)

	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "rejected"),
		attribute.String("reason", "invalid_format"),
		attribute.String("framework", "fasthttp"),
	)
}

func TestInstrumentedFastHTTPBearerAuth_ValidationFailed(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return nil, ErrTokenInvalid
		},
	}

	mw := InstrumentedFastHTTPBearerAuth(validator, []InstrumentationOption{WithMeterProvider(mp)})
	next := func(_ *fasthttp.RequestCtx) {}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Authorization", "Bearer bad-token")

	mw(next)(ctx)

	assert.Equal(t, fasthttp.StatusUnauthorized, ctx.Response.StatusCode())

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "rejected"),
		attribute.String("reason", "validation_failed"),
		attribute.String("framework", "fasthttp"),
	)
}

func TestInstrumentedFastHTTPBearerAuth_NilValidatorPanics(t *testing.T) {
	assert.PanicsWithValue(t, "InstrumentedFastHTTPBearerAuth: validator cannot be nil", func() {
		InstrumentedFastHTTPBearerAuth(nil, nil)
	})
}

func TestInstrumentedFastHTTPBearerAuth_CustomClaimsKey(t *testing.T) {
	_, _, mp, reader := setupTestOTel(t)

	validator := &mockTokenValidator{
		ValidateTokenFunc: func(_ context.Context, _ string) (*Claims, error) {
			return &Claims{ClientID: "test"}, nil
		},
	}

	customKey := "custom_claims"
	mw := InstrumentedFastHTTPBearerAuth(validator,
		[]InstrumentationOption{WithMeterProvider(mp)},
		WithClaimsKey(customKey),
	)

	next := func(ctx *fasthttp.RequestCtx) {
		// Verify claims are stored under custom key
		assert.NotNil(t, ctx.UserValue(customKey))
		ctx.SetStatusCode(fasthttp.StatusOK)
	}

	ctx := &fasthttp.RequestCtx{}
	ctx.Request.Header.Set("Authorization", "Bearer valid-token")

	mw(next)(ctx)

	assert.Equal(t, fasthttp.StatusOK, ctx.Response.StatusCode())

	rm := collectMetrics(t, reader)
	assertCounterValue(t, rm, "authclient.middleware.auth.total", 1,
		attribute.String("result", "success"),
		attribute.String("framework", "fasthttp"),
	)
}
