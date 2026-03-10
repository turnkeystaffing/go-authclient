package authclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- AC-1: Config Validation Tests ---

func TestOAuthTokenProviderConfig_Validate_MissingClientID(t *testing.T) {
	cfg := OAuthTokenProviderConfig{
		ClientSecret: "secret",
		TokenURL:     "https://auth.example.com/token",
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "client ID is required") {
		t.Fatalf("expected client ID error, got: %v", err)
	}
}

func TestOAuthTokenProviderConfig_Validate_MissingClientSecret(t *testing.T) {
	cfg := OAuthTokenProviderConfig{
		ClientID: "id",
		TokenURL: "https://auth.example.com/token",
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "client secret is required") {
		t.Fatalf("expected client secret error, got: %v", err)
	}
}

func TestOAuthTokenProviderConfig_Validate_MissingTokenURL(t *testing.T) {
	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "token URL is required") {
		t.Fatalf("expected token URL error, got: %v", err)
	}
}

func TestOAuthTokenProviderConfig_Validate_InvalidURLScheme(t *testing.T) {
	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     "ftp://auth.example.com/token",
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "scheme must be http or https") {
		t.Fatalf("expected scheme error, got: %v", err)
	}
}

func TestOAuthTokenProviderConfig_Validate_MissingHost(t *testing.T) {
	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     "https:///token",
	}
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "must include a host") {
		t.Fatalf("expected host error, got: %v", err)
	}
}

func TestOAuthTokenProviderConfig_Validate_ClampsTimeout(t *testing.T) {
	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     "https://auth.example.com/token",
		HTTPTimeout:  -5 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HTTPTimeout != 10*time.Second {
		t.Fatalf("expected timeout clamped to 10s, got %v", cfg.HTTPTimeout)
	}
}

func TestOAuthTokenProviderConfig_Validate_Valid(t *testing.T) {
	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     "https://auth.example.com/token",
		HTTPTimeout:  30 * time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HTTPTimeout != 30*time.Second {
		t.Fatalf("expected timeout 30s, got %v", cfg.HTTPTimeout)
	}
}

func TestDefaultOAuthTokenProviderConfig(t *testing.T) {
	cfg := DefaultOAuthTokenProviderConfig()
	if cfg.HTTPTimeout != 10*time.Second {
		t.Fatalf("expected default timeout 10s, got %v", cfg.HTTPTimeout)
	}
}

// --- AC-1: Constructor Tests ---

func TestNewOAuthTokenProvider_NilLoggerPanics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for nil logger")
		}
		msg, ok := r.(string)
		if !ok || !strings.Contains(msg, "logger cannot be nil") {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     "https://auth.example.com/token",
	}
	_, _ = NewOAuthTokenProvider(cfg, nil)
}

func TestNewOAuthTokenProvider_InvalidConfig(t *testing.T) {
	cfg := OAuthTokenProviderConfig{}
	_, err := NewOAuthTokenProvider(cfg, testLogger())
	if err == nil {
		t.Fatal("expected error for invalid config")
	}
}

func TestNewOAuthTokenProvider_Valid(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     srv.URL + "/token",
	}
	p, err := NewOAuthTokenProvider(cfg, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer p.Close()
}

func TestNewOAuthTokenProvider_HTTPSchemeWarning(t *testing.T) {
	// This test verifies construction succeeds with http:// URL (warning is logged).
	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     "http://auth.example.com/token",
	}
	p, err := NewOAuthTokenProvider(cfg, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer p.Close()
}

// --- AC-2: Token Acquisition Tests ---

func tokenServer(t *testing.T, expiresIn int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		ct := r.Header.Get("Content-Type")
		if ct != "application/x-www-form-urlencoded" {
			t.Errorf("expected form content type, got %s", ct)
		}
		accept := r.Header.Get("Accept")
		if accept != "application/json" {
			t.Errorf("expected Accept: application/json, got %s", accept)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			t.Errorf("expected Basic auth, got %s", auth)
		}

		if err := r.ParseForm(); err != nil {
			t.Errorf("parse form error: %v", err)
		}
		if r.FormValue("grant_type") != "client_credentials" {
			t.Errorf("expected grant_type=client_credentials, got %s", r.FormValue("grant_type"))
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"access_token": "test-token-abc",
			"token_type":   "Bearer",
			"expires_in":   expiresIn,
			"scope":        "read write",
		}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("failed to encode token response: %v", err)
		}
	}))
}

func TestToken_SuccessfulGrant(t *testing.T) {
	srv := tokenServer(t, 3600)
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	token, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "test-token-abc" {
		t.Fatalf("expected test-token-abc, got %s", token)
	}
}

func TestToken_Non200Response(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	_, err := p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "status 401") {
		t.Fatalf("expected status code in error, got: %v", err)
	}
	// G10: response body must NOT appear in error
	if strings.Contains(err.Error(), "invalid_client") {
		t.Fatal("response body leaked in error message")
	}
}

func TestToken_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	_, err := p.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid token response") {
		t.Fatalf("expected invalid token response error, got: %v", err)
	}
}

func TestToken_MissingAccessToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token_type": "Bearer",
			"expires_in": 3600,
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	_, err := p.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "empty access_token") {
		t.Fatalf("expected empty access_token error, got: %v", err)
	}
}

func TestToken_WrongTokenType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "MAC",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	_, err := p.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unsupported token_type") {
		t.Fatalf("expected unsupported token_type error, got: %v", err)
	}
}

func TestToken_BearerCaseInsensitive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "bEaReR",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	token, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if token != "tok" {
		t.Fatalf("expected tok, got %s", token)
	}
}

func TestToken_InvalidExpiresIn(t *testing.T) {
	for _, expiresIn := range []int{0, -1, -100} {
		t.Run(fmt.Sprintf("expires_in=%d", expiresIn), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]interface{}{
					"access_token": "tok",
					"token_type":   "Bearer",
					"expires_in":   expiresIn,
				})
			}))
			defer srv.Close()

			p := mustProvider(t, srv.URL+"/token")
			defer p.Close()

			_, err := p.Token(context.Background())
			if err == nil || !strings.Contains(err.Error(), "invalid expires_in") {
				t.Fatalf("expected invalid expires_in error, got: %v", err)
			}
		})
	}
}

// --- AC-3: Caching Tests ---

func TestToken_CacheHit(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "cached-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	// First call fetches
	tok1, err := p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Second call should use cache
	tok2, err := p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if tok1 != tok2 || tok1 != "cached-token" {
		t.Fatalf("expected cached-token, got %q and %q", tok1, tok2)
	}
	if c := calls.Load(); c != 1 {
		t.Fatalf("expected 1 HTTP call (cache hit), got %d", c)
	}
}

func TestToken_ProactiveRefresh(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("token-%d", n),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	// First fetch
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "token-1" {
		t.Fatalf("expected token-1, got %s", tok)
	}

	// Simulate 80% lifetime passed by adjusting refreshAt
	p.mu.Lock()
	p.refreshAt = time.Now().Add(-1 * time.Second)
	p.mu.Unlock()

	// This should trigger async refresh but return cached token
	tok, err = p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "token-1" {
		t.Fatalf("expected token-1 (cached), got %s", tok)
	}

	// Wait for async refresh to complete
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if c := calls.Load(); c < 2 {
		t.Fatalf("expected async refresh call, got %d calls", c)
	}

	// Next call should return refreshed token
	tok, err = p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "token-2" {
		t.Fatalf("expected token-2 (refreshed), got %s", tok)
	}
}

func TestToken_ExpiredSynchronousFetch(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("token-%d", n),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	// First fetch
	_, err := p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Expire the token
	p.mu.Lock()
	p.expiresAt = time.Now().Add(-1 * time.Second)
	p.refreshAt = time.Now().Add(-2 * time.Second)
	p.mu.Unlock()

	// Should do synchronous fetch
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "token-2" {
		t.Fatalf("expected token-2, got %s", tok)
	}
}

func TestToken_ConcurrentExpiredDoubleCheckedLocking(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		// Small delay to increase contention window
		time.Sleep(10 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("token-%d", n),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	// Prime the cache then expire it
	_, err := p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.expiresAt = time.Now().Add(-1 * time.Second)
	p.refreshAt = time.Now().Add(-2 * time.Second)
	p.mu.Unlock()

	// Launch concurrent callers — all should get a token without error
	const goroutines = 10
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := p.Token(context.Background())
			if err != nil {
				errs <- err
				return
			}
			if tok == "" {
				errs <- fmt.Errorf("got empty token")
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent error: %v", err)
	}

	// Double-checked locking: first goroutine fetches, rest reuse — expect initial + 1 refresh
	c := calls.Load()
	if c > 2 {
		t.Fatalf("expected double-checked locking to limit calls, got %d (expected <=2)", c)
	}
}

// --- AC-3: Single-Flight Guard ---

func TestToken_SingleFlightGuard(t *testing.T) {
	var refreshCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		refreshCalls.Add(1)
		time.Sleep(50 * time.Millisecond) // slow response
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "refreshed",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	// Prime cache and set to need refresh
	_, _ = p.Token(context.Background())
	p.mu.Lock()
	p.refreshAt = time.Now().Add(-1 * time.Second)
	p.mu.Unlock()

	initialCalls := refreshCalls.Load()

	// Trigger multiple refreshes rapidly
	for i := 0; i < 5; i++ {
		p.triggerAsyncRefresh()
	}

	// Wait for async to finish
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !p.refreshing.Load() && refreshCalls.Load() > initialCalls {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Should have done only 1 additional refresh (single-flight)
	extraCalls := refreshCalls.Load() - initialCalls
	if extraCalls != 1 {
		t.Fatalf("expected 1 additional refresh call (single-flight), got %d", extraCalls)
	}
}

// --- AC-4: Security Tests ---

func TestToken_ErrorDoesNotLeakToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`secret-token-value-leaked`))
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	_, err := p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "secret-token-value") {
		t.Fatal("error message leaks response body")
	}
}

func TestToken_RedirectRejection(t *testing.T) {
	redirectTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("redirect target should never be reached")
	}))
	defer redirectTarget.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, redirectTarget.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	_, err := p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error on redirect")
	}
	if !strings.Contains(err.Error(), "network error") {
		t.Fatalf("expected network error wrapping redirect rejection, got: %v", err)
	}
}

func TestToken_ResponseBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Write >1MB of data
		bigBody := strings.Repeat("x", 2<<20)
		w.Write([]byte(bigBody))
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	// Should not panic or hang — read is bounded to 1MB
	_, err := p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for oversized non-JSON body")
	}
}

func TestToken_ScopesInRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		scope := r.FormValue("scope")
		if scope != "read write" {
			t.Errorf("expected scope 'read write', got %q", scope)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     srv.URL + "/token",
		Scopes:       "read write",
	}
	p, err := NewOAuthTokenProvider(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	_, err = p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

// --- AC-5: Close & Lifecycle Tests ---

func TestClose_TokenReturnsError(t *testing.T) {
	srv := tokenServer(t, 3600)
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")

	// Fetch a token first
	_, err := p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	p.Close()

	_, err = p.Token(context.Background())
	if !errors.Is(err, ErrTokenProviderClosed) {
		t.Fatalf("expected ErrTokenProviderClosed, got: %v", err)
	}
}

func TestClose_Idempotent(t *testing.T) {
	srv := tokenServer(t, 3600)
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")

	// Close multiple times — should not panic
	for i := 0; i < 5; i++ {
		if err := p.Close(); err != nil {
			t.Fatalf("Close() returned error on call %d: %v", i, err)
		}
	}
}

func TestClose_ClearsToken(t *testing.T) {
	srv := tokenServer(t, 3600)
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	_, _ = p.Token(context.Background())

	p.Close()

	p.mu.RLock()
	tok := p.accessToken
	p.mu.RUnlock()
	if tok != "" {
		t.Fatalf("expected token cleared after close, got %q", tok)
	}
}

// --- AC-7: OTel HTTP Transport ---

func TestNewOAuthTokenProvider_OTelTransport(t *testing.T) {
	srv := tokenServer(t, 3600)
	defer srv.Close()

	cfg := OAuthTokenProviderConfig{
		ClientID:          "id",
		ClientSecret:      "secret",
		TokenURL:          srv.URL + "/token",
		OTelHTTPTransport: true,
	}
	p, err := NewOAuthTokenProvider(cfg, testLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer p.Close()

	// Verify the transport is wrapped (non-nil and not default)
	if p.client.Transport == nil {
		t.Fatal("expected OTel transport to be set, got nil")
	}

	// Verify token acquisition works through OTel-instrumented transport
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error with OTel transport: %v", err)
	}
	if tok != "test-token-abc" {
		t.Fatalf("expected test-token-abc, got %s", tok)
	}
}

// --- AC-2: Cancelled Context ---

func TestToken_CancelledContext(t *testing.T) {
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Block until test signals — channel-based gate (P4: no time.Sleep)
		<-gate
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()
	defer close(gate)

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := p.Token(ctx)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

// --- AC-2: Long Lifetime Warning ---

func TestToken_LongLifetimeWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   100000, // > 86400
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	// Should succeed (warning is logged but not an error)
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "tok" {
		t.Fatalf("expected tok, got %s", tok)
	}
}

// --- QA: Config Edge Cases ---

func TestOAuthTokenProviderConfig_Validate_ZeroTimeoutClamped(t *testing.T) {
	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     "https://auth.example.com/token",
		HTTPTimeout:  0, // zero, not negative
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HTTPTimeout != 10*time.Second {
		t.Fatalf("expected zero timeout clamped to 10s, got %v", cfg.HTTPTimeout)
	}
}

// --- QA: Request Format Verification ---

func TestToken_NoScopesOmitsParam(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.FormValue("scope") != "" {
			t.Errorf("expected no scope parameter, got %q", r.FormValue("scope"))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	// mustProvider uses no scopes by default
	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	_, err := p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

func TestToken_BasicAuthFormat(t *testing.T) {
	const clientID = "test-client-id"
	const clientSecret = "test-client-secret"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			t.Fatalf("expected Basic auth, got %q", auth)
		}
		decoded, err := base64.StdEncoding.DecodeString(auth[len("Basic "):])
		if err != nil {
			t.Fatalf("failed to decode Basic auth: %v", err)
		}
		expected := clientID + ":" + clientSecret
		if string(decoded) != expected {
			t.Fatalf("expected %q, got %q", expected, string(decoded))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	cfg := OAuthTokenProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     srv.URL + "/token",
	}
	p, err := NewOAuthTokenProvider(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	_, err = p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

// --- QA: Async Refresh Edge Cases ---

func TestToken_AsyncRefreshFailure_PreservesCachedToken(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n > 1 {
			// Subsequent calls (async refresh) fail
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "original-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	// First fetch succeeds
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "original-token" {
		t.Fatalf("expected original-token, got %s", tok)
	}

	// Move past 80% lifetime to trigger async refresh
	p.mu.Lock()
	p.refreshAt = time.Now().Add(-1 * time.Second)
	p.mu.Unlock()

	// This triggers async refresh (which will fail) and returns cached
	tok, err = p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "original-token" {
		t.Fatalf("expected original-token (cached), got %s", tok)
	}

	// Wait for async refresh to complete (it will fail)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// The cached token should still be the original
	p.mu.RLock()
	cachedToken := p.accessToken
	p.mu.RUnlock()
	if cachedToken != "original-token" {
		t.Fatalf("expected cached token preserved after failed refresh, got %q", cachedToken)
	}
}

func TestToken_CloseDuringAsyncRefresh(t *testing.T) {
	var reqStarted sync.WaitGroup
	reqStarted.Add(1)
	var reqRelease sync.WaitGroup
	reqRelease.Add(1)
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := calls.Add(1)
		if n > 1 {
			// Signal that async refresh request has started
			reqStarted.Done()
			// Wait until Close() has been called
			reqRelease.Wait()
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": fmt.Sprintf("token-%d", n),
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")

	// Prime cache
	_, err := p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// Move past 80% lifetime
	p.mu.Lock()
	p.refreshAt = time.Now().Add(-1 * time.Second)
	p.mu.Unlock()

	// Trigger async refresh
	p.triggerAsyncRefresh()

	// Wait for the refresh HTTP request to begin
	reqStarted.Wait()

	// Close while refresh is in flight
	p.Close()

	// Let the refresh HTTP response complete
	reqRelease.Done()

	// Wait for the refresh goroutine to finish
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !p.refreshing.Load() {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// After Close(), the cached token must be empty (not overwritten by async refresh)
	p.mu.RLock()
	cachedToken := p.accessToken
	p.mu.RUnlock()
	if cachedToken != "" {
		t.Fatalf("expected empty token after Close() during async refresh, got %q", cachedToken)
	}
}

// --- QA: Network Error ---

func TestToken_NetworkError_ServerUnreachable(t *testing.T) {
	// Create a server and immediately close it to get an unreachable URL
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	unreachableURL := srv.URL + "/token"
	srv.Close()

	p := mustProvider(t, unreachableURL)
	defer p.Close()

	_, err := p.Token(context.Background())
	if err == nil {
		t.Fatal("expected error for unreachable server")
	}
	if !strings.Contains(err.Error(), "network error") {
		t.Fatalf("expected network error, got: %v", err)
	}
}

// --- QA: Cache Threshold Verification ---

func TestToken_RefreshAtThreshold(t *testing.T) {
	const expiresIn = 1000 // seconds
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   expiresIn,
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	before := time.Now()
	_, err := p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	after := time.Now()

	p.mu.RLock()
	refreshAt := p.refreshAt
	expiresAt := p.expiresAt
	p.mu.RUnlock()

	// expiresAt should be approximately now + 1000s
	expectedExpiry := before.Add(time.Duration(expiresIn) * time.Second)
	if expiresAt.Before(expectedExpiry) || expiresAt.After(after.Add(time.Duration(expiresIn)*time.Second)) {
		t.Fatalf("expiresAt %v outside expected range", expiresAt)
	}

	// refreshAt should be at 80% of lifetime (800s from fetch time)
	expectedRefresh := before.Add(time.Duration(float64(expiresIn)*0.8) * time.Second)
	// Allow 2s tolerance for test execution time
	tolerance := 2 * time.Second
	if refreshAt.Before(expectedRefresh.Add(-tolerance)) || refreshAt.After(expectedRefresh.Add(tolerance)) {
		t.Fatalf("refreshAt %v not at 80%% lifetime (expected ~%v)", refreshAt, expectedRefresh)
	}
}

// --- Adversarial: maxExpiresIn Overflow Prevention ---

func TestToken_ExpiresInExceedsMax(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   31536001, // 1 year + 1 second — exceeds maxExpiresIn
		})
	}))
	defer srv.Close()

	p := mustProvider(t, srv.URL+"/token")
	defer p.Close()

	_, err := p.Token(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected exceeds maximum error, got: %v", err)
	}
}

// --- Adversarial: RFC 6749 Percent-Encoding in Basic Auth ---

func TestToken_BasicAuthPercentEncoding(t *testing.T) {
	// ClientID and ClientSecret with special characters that require percent-encoding
	const clientID = "client:with:colons"
	const clientSecret = "secret/with spaces&special=chars"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic ") {
			t.Fatalf("expected Basic auth, got %q", auth)
		}
		decoded, err := base64.StdEncoding.DecodeString(auth[len("Basic "):])
		if err != nil {
			t.Fatalf("failed to decode Basic auth: %v", err)
		}
		// Per RFC 6749 Section 2.3.1, credentials must be percent-encoded before Base64
		expected := url.QueryEscape(clientID) + ":" + url.QueryEscape(clientSecret)
		if string(decoded) != expected {
			t.Fatalf("expected percent-encoded %q, got %q", expected, string(decoded))
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()

	cfg := OAuthTokenProviderConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     srv.URL + "/token",
	}
	p, err := NewOAuthTokenProvider(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	_, err = p.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
}

// --- Adversarial: Scope Mismatch Warning ---

func TestToken_ScopeMismatchWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "read write admin", // broader than requested
		})
	}))
	defer srv.Close()

	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     srv.URL + "/token",
		Scopes:       "read write",
	}
	p, err := NewOAuthTokenProvider(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Should succeed (warning is logged but not an error)
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "tok" {
		t.Fatalf("expected tok, got %s", tok)
	}
}

// --- AC-5: Close During Synchronous Fetch ---

func TestToken_CloseDuringSynchronousFetch(t *testing.T) {
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Block until test signals — simulates slow token endpoint
		<-gate
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer srv.Close()
	defer close(gate)

	p := mustProvider(t, srv.URL+"/token")

	// Start Token() in a goroutine — it will block on the slow server (write lock held)
	tokenDone := make(chan error, 1)
	go func() {
		_, err := p.Token(context.Background())
		tokenDone <- err
	}()

	// Give Token() time to acquire the write lock and start the HTTP request
	time.Sleep(50 * time.Millisecond)

	// Close() while synchronous fetch is in progress — blocks on write lock
	closeDone := make(chan struct{})
	go func() {
		p.Close()
		close(closeDone)
	}()

	// Release the server to let the fetch complete
	gate <- struct{}{}

	// Both operations should complete without panic
	select {
	case err := <-tokenDone:
		// Token() may succeed or fail depending on timing — either is acceptable
		_ = err
	case <-time.After(5 * time.Second):
		t.Fatal("Token() did not complete within timeout")
	}

	select {
	case <-closeDone:
		// Close() completed
	case <-time.After(5 * time.Second):
		t.Fatal("Close() did not complete within timeout")
	}

	// After Close(), Token() must return ErrTokenProviderClosed
	_, err := p.Token(context.Background())
	if !errors.Is(err, ErrTokenProviderClosed) {
		t.Fatalf("expected ErrTokenProviderClosed after close, got: %v", err)
	}
}

// --- Adversarial: Set-Based Scope Comparison ---

func TestToken_ScopeReorderingNoWarning(t *testing.T) {
	// Server returns scopes in different order than requested — should NOT trigger warning
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"scope":        "write read", // reversed order
		})
	}))
	defer srv.Close()

	cfg := OAuthTokenProviderConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		TokenURL:     srv.URL + "/token",
		Scopes:       "read write",
	}
	p, err := NewOAuthTokenProvider(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()

	// Should succeed — reordered scopes are semantically equal
	tok, err := p.Token(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "tok" {
		t.Fatalf("expected tok, got %s", tok)
	}
}

// --- Compile-time assertions verified ---

func TestCompileTimeAssertions(t *testing.T) {
	// These are compile-time checks — if they fail, the code won't compile.
	// Including a runtime test for documentation purposes.
	var _ TokenProvider = (*OAuthTokenProvider)(nil)
	var _ io.Closer = (*OAuthTokenProvider)(nil)
}

// --- Helpers ---

func mustProvider(t *testing.T, tokenURL string) *OAuthTokenProvider {
	t.Helper()
	cfg := OAuthTokenProviderConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		TokenURL:     tokenURL,
	}
	p, err := NewOAuthTokenProvider(cfg, testLogger())
	if err != nil {
		t.Fatalf("failed to create provider: %v", err)
	}
	return p
}
