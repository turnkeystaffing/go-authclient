package authclient

import (
	"log/slog"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func newTestIntrospectionClient(t *testing.T, otelTransport bool) *IntrospectionClient {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	cfg := IntrospectionClientConfig{
		IntrospectionURL:  "https://example.com/introspect",
		ClientID:          "test-client",
		ClientSecret:      "test-secret",
		OTelHTTPTransport: otelTransport,
	}
	return NewIntrospectionClient(cfg, logger)
}

func TestOTelHTTPTransport_Disabled(t *testing.T) {
	client := newTestIntrospectionClient(t, false)
	// Default transport is nil (Go's DefaultTransport used implicitly)
	assert.Nil(t, client.httpClient.Transport)
}

func TestOTelHTTPTransport_Enabled(t *testing.T) {
	client := newTestIntrospectionClient(t, true)
	require.NotNil(t, client.httpClient.Transport)
	// Verify it's an otelhttp transport by type assertion
	_, ok := client.httpClient.Transport.(*otelhttp.Transport)
	assert.True(t, ok, "expected transport to be *otelhttp.Transport")
}

func TestOTelHTTPTransport_CheckRedirectPreserved(t *testing.T) {
	client := newTestIntrospectionClient(t, true)
	// CheckRedirect should still reject redirects
	require.NotNil(t, client.httpClient.CheckRedirect)
	err := client.httpClient.CheckRedirect(&http.Request{}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "redirects are not allowed")
}
