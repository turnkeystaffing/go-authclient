package authclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- Constructor tests ---

func TestNewIntrospectionClient_NilLoggerPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for nil logger")
		}
	}()
	NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: "http://example.com/introspect",
	}, nil)
}

func TestNewIntrospectionClient_EmptyURLPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty URL")
		}
	}()
	NewIntrospectionClient(IntrospectionClientConfig{}, testLogger())
}

func TestNewIntrospectionClient_EmptyClientIDPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty ClientID")
		}
	}()
	NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: "http://example.com/introspect",
		ClientSecret:     "s",
	}, testLogger())
}

func TestNewIntrospectionClient_EmptyClientSecretPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for empty ClientSecret")
		}
	}()
	NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: "http://example.com/introspect",
		ClientID:         "c",
	}, testLogger())
}

// --- 8.2: Active token — verify Basic Auth, Content-Type, form body, response parsing ---

func TestIntrospectionClient_ActiveToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST method, got %s", r.Method)
		}
		user, pass, ok := r.BasicAuth()
		if !ok || user != "test-client" || pass != "test-secret" {
			t.Errorf("unexpected basic auth: user=%s pass=%s ok=%v", user, pass, ok)
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
			t.Errorf("unexpected content type: %s", ct)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("token") != "valid-token" {
			t.Errorf("unexpected token: %s", r.Form.Get("token"))
		}
		if r.Form.Get("token_type_hint") != "access_token" {
			t.Errorf("unexpected token_type_hint: %s", r.Form.Get("token_type_hint"))
		}

		resp := IntrospectionResponse{
			Active:   true,
			Sub:      "user-123",
			Scope:    "audit:read openid",
			Email:    "admin@example.com",
			Username: "admin@example.com",
			ClientID: "service-uuid",
			Exp:      time.Now().Add(time.Hour).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
	}, testLogger())

	resp, err := client.Introspect(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Active {
		t.Error("expected active=true")
	}
	if resp.Sub != "user-123" {
		t.Errorf("expected sub=user-123, got %s", resp.Sub)
	}
	if resp.ClientID != "service-uuid" {
		t.Errorf("expected client_id=service-uuid, got %s", resp.ClientID)
	}
	scopes := resp.Scopes()
	if len(scopes) != 2 || scopes[0] != "audit:read" || scopes[1] != "openid" {
		t.Errorf("unexpected scopes: %v", scopes)
	}
}

// --- 8.3: Inactive token — returns active: false, no caching ---

func TestIntrospectionClient_InactiveToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active":false}`))
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
	}, testLogger())

	resp, err := client.Introspect(context.Background(), "expired-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Active {
		t.Error("expected active=false")
	}
}

// --- 8.4: Server error (500) — returns error with status code, no token in error ---

func TestIntrospectionClient_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`internal server error`))
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
	}, testLogger())

	_, err := client.Introspect(context.Background(), "some-token")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Errorf("expected ErrIntrospectionFailed, got: %v", err)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("expected error to contain status code 500, got: %v", err)
	}
	// No token in error message.
	if strings.Contains(err.Error(), "some-token") {
		t.Errorf("token leaked in error message: %v", err)
	}
	// No response body in error message (F3 fix).
	if strings.Contains(err.Error(), "internal server error") {
		t.Errorf("response body leaked in error message: %v", err)
	}
}

// --- 8.5: Malformed JSON response ---

func TestIntrospectionClient_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active": true, "sub": "user-`))
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
	}, testLogger())

	_, err := client.Introspect(context.Background(), "some-token")
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Errorf("expected ErrIntrospectionFailed, got: %v", err)
	}
}

// --- 8.6: Empty body response ---

func TestIntrospectionClient_EmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
	}, testLogger())

	_, err := client.Introspect(context.Background(), "some-token")
	if err == nil {
		t.Fatal("expected error for empty body")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Errorf("expected ErrIntrospectionFailed, got: %v", err)
	}
}

// --- 8.7: Cache hit — second call skips HTTP ---

func TestIntrospectionClient_CacheHit(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		resp := IntrospectionResponse{
			Active:   true,
			Sub:      "user-123",
			Scope:    "audit:read",
			ClientID: "service-uuid",
			Exp:      time.Now().Add(time.Hour).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cache := NewInMemoryCache(1000)
	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
		Cache:            cache,
		CacheTTL:         5 * time.Minute,
	}, testLogger())

	ctx := context.Background()

	resp1, err := client.Introspect(ctx, "cached-token")
	if err != nil {
		t.Fatalf("first call error: %v", err)
	}
	if !resp1.Active {
		t.Error("expected active=true")
	}
	if callCount.Load() != 1 {
		t.Errorf("expected 1 server call, got %d", callCount.Load())
	}

	resp2, err := client.Introspect(ctx, "cached-token")
	if err != nil {
		t.Fatalf("second call error: %v", err)
	}
	if !resp2.Active {
		t.Error("expected active=true on cache hit")
	}
	if callCount.Load() != 1 {
		t.Errorf("expected still 1 server call after cache hit, got %d", callCount.Load())
	}
}

// --- 8.8: Cache TTL respects token exp (short-lived token) ---

func TestIntrospectionClient_CacheTTL_RespectsTokenExp(t *testing.T) {
	shortExp := time.Now().Add(30 * time.Second).Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := IntrospectionResponse{
			Active: true,
			Sub:    "user-short",
			Scope:  "audit:read",
			Exp:    shortExp,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	underlying := NewInMemoryCache(1000)
	cache := &ttlCapturingCache{IntrospectionCache: underlying}
	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
		Cache:            cache,
		CacheTTL:         5 * time.Minute,
	}, testLogger())

	_, err := client.Introspect(context.Background(), "short-lived-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify cache entry was set.
	key := client.cacheKey("short-lived-token")
	result, _ := underlying.Get(context.Background(), key)
	if !result.Hit {
		t.Fatal("expected cache entry to be set")
	}

	// TTL should be ~30s (token remaining lifetime), NOT 5 minutes (configured TTL).
	if cache.lastTTL > 31*time.Second || cache.lastTTL < 28*time.Second {
		t.Errorf("expected TTL ~30s (token remaining), got %v", cache.lastTTL)
	}
}

// --- 8.9: Cache TTL uses configured TTL when token lives longer ---

func TestIntrospectionClient_CacheTTL_UsesConfigWhenTokenLonger(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := IntrospectionResponse{
			Active: true,
			Sub:    "user-long",
			Scope:  "audit:read",
			Exp:    time.Now().Add(time.Hour).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	underlying := NewInMemoryCache(1000)
	cache := &ttlCapturingCache{IntrospectionCache: underlying}
	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
		Cache:            cache,
		CacheTTL:         5 * time.Minute,
	}, testLogger())

	_, err := client.Introspect(context.Background(), "long-lived-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	key := client.cacheKey("long-lived-token")
	result, _ := underlying.Get(context.Background(), key)
	if !result.Hit {
		t.Fatal("expected cache entry to be set")
	}

	// TTL should be 5 minutes (configured TTL), NOT 1 hour (token remaining).
	if cache.lastTTL > 5*time.Minute+time.Second || cache.lastTTL < 5*time.Minute-time.Second {
		t.Errorf("expected TTL ~5m (configured), got %v", cache.lastTTL)
	}
}

// --- 8.10: Expired cached entry triggers re-introspection and cache deletion ---

func TestIntrospectionClient_ExpiredCacheEntry(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		resp := IntrospectionResponse{
			Active: true,
			Sub:    "user-fresh",
			Scope:  "audit:read",
			Exp:    time.Now().Add(time.Hour).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cache := NewInMemoryCache(1000)
	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
		Cache:            cache,
		CacheTTL:         5 * time.Minute,
	}, testLogger())

	// Pre-populate cache with an expired entry.
	key := client.cacheKey("refresh-token")
	expiredResp := IntrospectionResponse{
		Active: true,
		Sub:    "user-stale",
		Exp:    time.Now().Add(-10 * time.Second).Unix(), // expired 10 seconds ago
	}
	data, _ := json.Marshal(expiredResp)
	cache.Set(context.Background(), key, string(data), time.Hour)

	resp, err := client.Introspect(context.Background(), "refresh-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Sub != "user-fresh" {
		t.Errorf("expected fresh response sub=user-fresh, got %s", resp.Sub)
	}
	if callCount.Load() != 1 {
		t.Errorf("expected 1 server call for expired cache, got %d", callCount.Load())
	}
}

// --- 8.11: Inactive token deletes stale cache entry ---

func TestIntrospectionClient_InactiveDeletesCache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active":false}`))
	}))
	defer server.Close()

	cache := NewInMemoryCache(1000)
	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
		Cache:            cache,
		CacheTTL:         5 * time.Minute,
	}, testLogger())

	// Pre-populate cache with a stale active entry that has expired (exp in the past).
	// This forces a re-introspection which returns inactive, triggering cache deletion.
	key := client.cacheKey("revoked-token")
	staleResp := IntrospectionResponse{Active: true, Sub: "user-stale", Exp: time.Now().Add(-10 * time.Second).Unix()}
	data, _ := json.Marshal(staleResp)
	cache.Set(context.Background(), key, string(data), time.Hour)

	// Verify the stale entry exists before introspection.
	preResult, _ := cache.Get(context.Background(), key)
	if !preResult.Hit {
		t.Fatal("expected stale cache entry to exist before introspection")
	}

	resp, err := client.Introspect(context.Background(), "revoked-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Active {
		t.Error("expected active=false")
	}

	// Stale entry should be deleted after inactive response.
	result, _ := cache.Get(context.Background(), key)
	if result.Hit {
		t.Error("expected stale cache entry to be deleted for inactive token")
	}
}

// --- 8.12: No Redis (nil) — every call hits endpoint ---

func TestIntrospectionClient_NoRedis(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		resp := IntrospectionResponse{Active: true, Sub: "user-123", Exp: time.Now().Add(time.Hour).Unix()}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
		// Cache is nil — noop
	}, testLogger())

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		_, err := client.Introspect(ctx, "same-token")
		if err != nil {
			t.Fatalf("call %d error: %v", i+1, err)
		}
	}
	if callCount.Load() != 3 {
		t.Errorf("expected 3 server calls without Redis, got %d", callCount.Load())
	}
}

// --- 8.13: ValidateToken — active token returns Claims ---

func TestValidateToken_Introspection_ActiveTokenReturnsClaims(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := IntrospectionResponse{
			Active:   true,
			Sub:      "user-456",
			Scope:    "audit:read audit:write",
			ClientID: "my-service",
			Exp:      time.Now().Add(time.Hour).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
	}, testLogger())

	claims, err := client.ValidateToken(context.Background(), "valid-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims.ClientID != "my-service" {
		t.Errorf("expected ClientID=my-service, got %s", claims.ClientID)
	}
	if claims.UserID != "user-456" {
		t.Errorf("expected UserID=user-456, got %s", claims.UserID)
	}
	if len(claims.Scopes) != 2 || claims.Scopes[0] != "audit:read" || claims.Scopes[1] != "audit:write" {
		t.Errorf("unexpected scopes: %v", claims.Scopes)
	}
	if claims.Subject != "user-456" {
		t.Errorf("expected Subject=user-456, got %s", claims.Subject)
	}
}

// --- 8.14: ValidateToken — inactive token returns ErrTokenInvalid ---

func TestValidateToken_Introspection_InactiveTokenReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active":false}`))
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
	}, testLogger())

	_, err := client.ValidateToken(context.Background(), "inactive-token")
	if err == nil {
		t.Fatal("expected error for inactive token")
	}
	if !errors.Is(err, ErrTokenInactive) {
		t.Errorf("expected ErrTokenInactive, got: %v", err)
	}
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("expected errors.Is(err, ErrTokenInvalid) to be true via chain, got: %v", err)
	}
}

// --- 8.15: ValidateToken — oversized token returns ErrTokenOversized ---

func TestValidateToken_Introspection_OversizedToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("server should not be called for oversized token")
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
	}, testLogger())

	oversized := strings.Repeat("a", MaxBearerTokenLength+1)
	_, err := client.ValidateToken(context.Background(), oversized)
	if err == nil {
		t.Fatal("expected error for oversized token")
	}
	if !errors.Is(err, ErrTokenOversized) {
		t.Errorf("expected ErrTokenOversized, got: %v", err)
	}
}

// --- 8.16: ValidateToken — introspection error with fallback triggers JWKS validation ---

func TestValidateToken_Introspection_FallbackOnNetworkError(t *testing.T) {
	// Use a server that immediately closes connections.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Force connection close to simulate network error.
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server doesn't support hijacking")
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer server.Close()

	fallbackCalled := false
	mockFallback := &mockTokenValidator{
		validateFunc: func(_ context.Context, token string) (*Claims, error) {
			fallbackCalled = true
			return &Claims{ClientID: "fallback-service", UserID: "fallback-user"}, nil
		},
	}

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL:  server.URL,
		ClientID:          "test-client",
		ClientSecret:      "test-secret",
		FallbackValidator: mockFallback,
	}, testLogger())

	claims, err := client.ValidateToken(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("expected fallback to succeed, got error: %v", err)
	}
	if !fallbackCalled {
		t.Error("expected fallback to be called on network error")
	}
	if claims.ClientID != "fallback-service" {
		t.Errorf("expected fallback claims, got ClientID=%s", claims.ClientID)
	}
}

// --- 8.17: ValidateToken — introspection error without fallback returns error ---

func TestValidateToken_Introspection_NoFallbackReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server doesn't support hijacking")
		}
		conn, _, _ := hj.Hijack()
		conn.Close()
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
		// No fallback configured
	}, testLogger())

	_, err := client.ValidateToken(context.Background(), "some-token")
	if err == nil {
		t.Fatal("expected error without fallback")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Errorf("expected ErrIntrospectionFailed, got: %v", err)
	}
}

// --- 8.18: No token leakage in error messages ---

func TestIntrospectionClient_NoTokenLeakageInErrors(t *testing.T) {
	token := "super-secret-token-value-12345"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`bad request`))
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "test-client",
		ClientSecret:     "test-secret",
	}, testLogger())

	_, err := client.Introspect(context.Background(), token)
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), token) {
		t.Errorf("token value leaked in error message: %v", err)
	}
}

// --- 8.19: No client credential leakage in error messages ---

func TestIntrospectionClient_NoCredentialLeakageInErrors(t *testing.T) {
	clientID := "my-confidential-client-id"
	clientSecret := "my-super-secret-password"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`unauthorized`))
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         clientID,
		ClientSecret:     clientSecret,
	}, testLogger())

	_, err := client.Introspect(context.Background(), "some-token")
	if err == nil {
		t.Fatal("expected error")
	}
	errMsg := err.Error()
	if strings.Contains(errMsg, clientID) {
		t.Errorf("client_id leaked in error message: %v", err)
	}
	if strings.Contains(errMsg, clientSecret) {
		t.Errorf("client_secret leaked in error message: %v", err)
	}
}

// --- 8.20: Default behavior — minimal config ---

func TestIntrospectionClient_DefaultBehavior(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := IntrospectionResponse{
			Active:   true,
			Sub:      "default-user",
			ClientID: "default-client",
			Exp:      time.Now().Add(time.Hour).Unix(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "c",
		ClientSecret:     "s",
	}, testLogger())

	resp, err := client.Introspect(context.Background(), "t")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.Active || resp.Sub != "default-user" {
		t.Errorf("unexpected response: active=%v sub=%s", resp.Active, resp.Sub)
	}
}

// --- 8.21: Fallback NOT triggered on HTTP 500 ---

func TestValidateToken_Introspection_FallbackNotTriggeredOnHTTP500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`server error`))
	}))
	defer server.Close()

	fallbackCalled := false
	mockFallback := &mockTokenValidator{
		validateFunc: func(_ context.Context, token string) (*Claims, error) {
			fallbackCalled = true
			return &Claims{}, nil
		},
	}

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL:  server.URL,
		ClientID:          "test-client",
		ClientSecret:      "test-secret",
		FallbackValidator: mockFallback,
	}, testLogger())

	_, err := client.ValidateToken(context.Background(), "some-token")
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if fallbackCalled {
		t.Error("fallback should NOT be triggered for HTTP 500 (server responded)")
	}
}

// --- 8.5 (via ValidateToken): Fallback NOT triggered on active: false ---

func TestValidateToken_Introspection_FallbackNotTriggeredOnInactive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active":false}`))
	}))
	defer server.Close()

	fallbackCalled := false
	mockFallback := &mockTokenValidator{
		validateFunc: func(_ context.Context, _ string) (*Claims, error) {
			fallbackCalled = true
			return &Claims{}, nil
		},
	}

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL:  server.URL,
		ClientID:          "test-client",
		ClientSecret:      "test-secret",
		FallbackValidator: mockFallback,
	}, testLogger())

	_, err := client.ValidateToken(context.Background(), "inactive-token")
	if err == nil {
		t.Fatal("expected ErrTokenInactive")
	}
	if fallbackCalled {
		t.Error("fallback should NOT be triggered on active: false")
	}
}

// --- Close() test ---

func TestIntrospectionClient_Close(t *testing.T) {
	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: "http://example.com/introspect",
		ClientID:         "c",
		ClientSecret:     "s",
	}, testLogger())

	if err := client.Close(); err != nil {
		t.Errorf("expected nil error from Close, got: %v", err)
	}
}

// --- ErrTokenInactive chain test ---

func TestErrTokenInactive_WrapsErrTokenInvalid(t *testing.T) {
	if !errors.Is(ErrTokenInactive, ErrTokenInvalid) {
		t.Error("ErrTokenInactive should wrap ErrTokenInvalid")
	}
}

// --- Compile-time interface assertions are in introspection_client.go ---

// --- mockTokenValidator for fallback tests ---

type mockTokenValidator struct {
	validateFunc func(ctx context.Context, token string) (*Claims, error)
}

func (m *mockTokenValidator) ValidateToken(ctx context.Context, token string) (*Claims, error) {
	return m.validateFunc(ctx, token)
}

// --- ttlCapturingCache wraps IntrospectionCache to capture TTL values ---

type ttlCapturingCache struct {
	IntrospectionCache
	lastTTL time.Duration
}

func (c *ttlCapturingCache) Set(ctx context.Context, key string, value string, expiration time.Duration) error {
	c.lastTTL = expiration
	return c.IntrospectionCache.Set(ctx, key, value, expiration)
}

// --- 8.22: IntrospectionResponse.Scopes() is already tested in introspection_test.go ---

// --- Additional: cacheKey uses SHA-256 ---

func TestIntrospectionClient_CacheKeyFormat(t *testing.T) {
	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: "http://example.com/introspect",
		ClientID:         "c",
		ClientSecret:     "s",
	}, testLogger())

	key := client.cacheKey("test-token")
	if !strings.HasPrefix(key, "introspect:") {
		t.Errorf("expected cache key to start with 'introspect:', got: %s", key)
	}
	// SHA-256 hex is 64 chars.
	parts := strings.SplitN(key, ":", 2)
	if len(parts[1]) != 64 {
		t.Errorf("expected SHA-256 hex (64 chars), got %d chars: %s", len(parts[1]), parts[1])
	}
	// Token value should NOT appear in key.
	if strings.Contains(key, "test-token") {
		t.Error("token value should not appear in cache key")
	}
}

// --- Additional: network error detection ---

func TestIsNetworkError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"network error (root sentinel)", fmt.Errorf("wrap: %w", ErrIntrospectionFailed), true},
		{"http error (rejected)", fmt.Errorf("wrap: %w", ErrIntrospectionRejected), false},
		{"parse error", fmt.Errorf("wrap: %w", ErrIntrospectionParse), false},
		{"non-introspection error", fmt.Errorf("some other error"), false},
		{"double-wrapped network", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", ErrIntrospectionFailed)), true},
		{"double-wrapped rejected", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", ErrIntrospectionRejected)), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNetworkError(tt.err); got != tt.expected {
				t.Errorf("isNetworkError(%v) = %v, want %v", tt.err, got, tt.expected)
			}
		})
	}
}

// --- QA: ClaimsFromIntrospection tests (6-2 originals) ---
// Canonical comprehensive tests are in claims_conversion_test.go (Story 6-3).
// These subtests are retained from Story 6-2 for regression coverage.

func TestClaimsFromIntrospection(t *testing.T) {
	t.Run("all fields mapped", func(t *testing.T) {
		exp := time.Now().Add(time.Hour).Unix()
		resp := &IntrospectionResponse{
			Active:   true,
			Sub:      "user-789",
			Scope:    "read write admin",
			Email:    "test@example.com",
			Username: "testuser",
			ClientID: "service-abc",
			Exp:      exp,
		}
		claims := ClaimsFromIntrospection(resp)
		if claims.ClientID != "service-abc" {
			t.Errorf("ClientID = %s, want service-abc", claims.ClientID)
		}
		if claims.UserID != "user-789" {
			t.Errorf("UserID = %s, want user-789", claims.UserID)
		}
		if claims.Subject != "user-789" {
			t.Errorf("Subject = %s, want user-789", claims.Subject)
		}
		if len(claims.Scopes) != 3 || claims.Scopes[0] != "read" || claims.Scopes[1] != "write" || claims.Scopes[2] != "admin" {
			t.Errorf("Scopes = %v, want [read write admin]", claims.Scopes)
		}
		if claims.ExpiresAt == nil {
			t.Fatal("ExpiresAt should not be nil when Exp > 0")
		}
		if claims.ExpiresAt.Unix() != exp {
			t.Errorf("ExpiresAt = %d, want %d", claims.ExpiresAt.Unix(), exp)
		}
		if claims.Email != "test@example.com" {
			t.Errorf("Email = %s, want test@example.com", claims.Email)
		}
		if claims.Username != "testuser" {
			t.Errorf("Username = %s, want testuser", claims.Username)
		}
	})

	t.Run("zero exp omits ExpiresAt", func(t *testing.T) {
		resp := &IntrospectionResponse{
			Active:   true,
			Sub:      "user-no-exp",
			ClientID: "svc",
			Exp:      0,
		}
		claims := ClaimsFromIntrospection(resp)
		if claims.ExpiresAt != nil {
			t.Errorf("ExpiresAt should be nil when Exp == 0, got %v", claims.ExpiresAt)
		}
	})

	t.Run("empty scope returns nil scopes", func(t *testing.T) {
		resp := &IntrospectionResponse{
			Active:   true,
			Sub:      "user-no-scope",
			ClientID: "svc",
			Scope:    "",
		}
		claims := ClaimsFromIntrospection(resp)
		if claims.Scopes != nil {
			t.Errorf("Scopes should be nil for empty scope, got %v", claims.Scopes)
		}
	})
}

// --- QA: ValidateToken empty token ---

func TestValidateToken_Introspection_EmptyToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"active":false}`))
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "c",
		ClientSecret:     "s",
	}, testLogger())

	_, err := client.ValidateToken(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
}

// --- QA: ValidateToken boundary at MaxBearerTokenLength ---

func TestValidateToken_Introspection_BoundaryTokenLength(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := IntrospectionResponse{Active: true, Sub: "u", ClientID: "c", Exp: time.Now().Add(time.Hour).Unix()}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "c",
		ClientSecret:     "s",
	}, testLogger())

	// Exactly at limit — should pass.
	exactToken := strings.Repeat("a", MaxBearerTokenLength)
	_, err := client.ValidateToken(context.Background(), exactToken)
	if err != nil {
		t.Fatalf("expected no error for token at exact limit, got: %v", err)
	}

	// One over limit — should fail.
	overToken := strings.Repeat("a", MaxBearerTokenLength+1)
	_, err = client.ValidateToken(context.Background(), overToken)
	if !errors.Is(err, ErrTokenOversized) {
		t.Errorf("expected ErrTokenOversized for token over limit, got: %v", err)
	}
}

// --- QA: Cache Get() error — endpoint still called ---

func TestIntrospectionClient_CacheGetError(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		resp := IntrospectionResponse{Active: true, Sub: "user-1", ClientID: "svc", Exp: time.Now().Add(time.Hour).Unix()}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cache := &errorCache{getErr: fmt.Errorf("redis connection refused")}
	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "c",
		ClientSecret:     "s",
		Cache:            cache,
		CacheTTL:         5 * time.Minute,
	}, testLogger())

	resp, err := client.Introspect(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("expected no error despite cache.Get failure, got: %v", err)
	}
	if !resp.Active {
		t.Error("expected active response")
	}
	if callCount.Load() != 1 {
		t.Errorf("expected endpoint to be called once after cache.Get error, got %d", callCount.Load())
	}
}

// --- QA: Cache Set() error — response still returned ---

func TestIntrospectionClient_CacheSetError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := IntrospectionResponse{Active: true, Sub: "user-1", ClientID: "svc", Exp: time.Now().Add(time.Hour).Unix()}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cache := &errorCache{setErr: fmt.Errorf("redis write error")}
	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "c",
		ClientSecret:     "s",
		Cache:            cache,
		CacheTTL:         5 * time.Minute,
	}, testLogger())

	resp, err := client.Introspect(context.Background(), "some-token")
	if err != nil {
		t.Fatalf("expected no error despite cache.Set failure, got: %v", err)
	}
	if !resp.Active || resp.Sub != "user-1" {
		t.Errorf("expected active response with sub=user-1, got active=%v sub=%s", resp.Active, resp.Sub)
	}
}

// --- QA: Cached JSON unmarshal failure — endpoint re-called ---

func TestIntrospectionClient_CacheUnmarshalFailure(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		resp := IntrospectionResponse{Active: true, Sub: "user-fresh", ClientID: "svc", Exp: time.Now().Add(time.Hour).Unix()}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cache := NewInMemoryCache(1000)
	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "c",
		ClientSecret:     "s",
		Cache:            cache,
		CacheTTL:         5 * time.Minute,
	}, testLogger())

	// Pre-populate cache with corrupt JSON.
	key := client.cacheKey("corrupt-token")
	cache.Set(context.Background(), key, "not-valid-json{{{", time.Hour)

	resp, err := client.Introspect(context.Background(), "corrupt-token")
	if err != nil {
		t.Fatalf("expected no error after cache unmarshal failure, got: %v", err)
	}
	if resp.Sub != "user-fresh" {
		t.Errorf("expected fresh response from endpoint, got sub=%s", resp.Sub)
	}
	if callCount.Load() != 1 {
		t.Errorf("expected endpoint called once after unmarshal failure, got %d", callCount.Load())
	}
}

// --- QA: Cache TTL with Exp==0 and zero CacheTTL — cache skipped ---

func TestIntrospectionClient_CacheTTL_ZeroExpZeroConfig(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		resp := IntrospectionResponse{Active: true, Sub: "user-noexp", ClientID: "svc", Exp: 0}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	cache := NewInMemoryCache(1000)
	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "c",
		ClientSecret:     "s",
		Cache:            cache,
		// CacheTTL: 0 (zero)
	}, testLogger())

	_, err := client.Introspect(context.Background(), "no-exp-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// With Exp=0 and CacheTTL=0, ttl stays 0 => cache.Set is skipped.
	key := client.cacheKey("no-exp-token")
	result, _ := cache.Get(context.Background(), key)
	if result.Hit {
		t.Error("expected cache entry NOT to be set when both Exp and CacheTTL are zero")
	}

	// Second call should hit endpoint again.
	_, err = client.Introspect(context.Background(), "no-exp-token")
	if err != nil {
		t.Fatalf("unexpected error on second call: %v", err)
	}
	if callCount.Load() != 2 {
		t.Errorf("expected 2 endpoint calls when caching is effectively disabled, got %d", callCount.Load())
	}
}

// --- QA: noopIntrospectionCache direct tests ---

func TestNoopIntrospectionCache(t *testing.T) {
	cache := noopIntrospectionCache{}
	ctx := context.Background()

	t.Run("Get returns miss with no error", func(t *testing.T) {
		result, err := cache.Get(ctx, "any-key")
		if err != nil {
			t.Errorf("expected nil error, got: %v", err)
		}
		if result.Hit {
			t.Error("expected cache miss from noop cache")
		}
		if result.Value != "" {
			t.Errorf("expected empty value, got: %s", result.Value)
		}
	})

	t.Run("Set returns no error", func(t *testing.T) {
		err := cache.Set(ctx, "key", "value", time.Minute)
		if err != nil {
			t.Errorf("expected nil error, got: %v", err)
		}
	})

	t.Run("Del returns zero with no error", func(t *testing.T) {
		n, err := cache.Del(ctx, "key1", "key2")
		if err != nil {
			t.Errorf("expected nil error, got: %v", err)
		}
		if n != 0 {
			t.Errorf("expected 0 deleted, got: %d", n)
		}
	})

	t.Run("Get after Set still returns miss", func(t *testing.T) {
		_ = cache.Set(ctx, "stored-key", "stored-value", time.Hour)
		result, _ := cache.Get(ctx, "stored-key")
		if result.Hit {
			t.Error("noop cache should never return a hit, even after Set")
		}
	})
}

// --- QA: errorCache helper for cache error testing ---

type errorCache struct {
	getErr error
	setErr error
	delErr error
}

func (c *errorCache) Get(_ context.Context, _ string) (CacheResult, error) {
	if c.getErr != nil {
		return CacheResult{}, c.getErr
	}
	return CacheResult{}, nil
}

func (c *errorCache) Set(_ context.Context, _ string, _ string, _ time.Duration) error {
	return c.setErr
}

func (c *errorCache) Del(_ context.Context, _ ...string) (int64, error) {
	if c.delErr != nil {
		return 0, c.delErr
	}
	return 0, nil
}

// --- Adversarial: F1 — Redirect rejection test ---

func TestIntrospectionClient_RedirectRejected(t *testing.T) {
	// Set up a redirect target that would capture credentials.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("redirect target should never be reached")
	}))
	defer target.Close()

	// Set up the introspection endpoint that redirects.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "c",
		ClientSecret:     "s",
	}, testLogger())

	_, err := client.Introspect(context.Background(), "test-token")
	if err == nil {
		t.Fatal("expected error for redirect, got nil")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Errorf("expected ErrIntrospectionFailed, got: %v", err)
	}
}

// --- Adversarial: F2 — Introspect() rejects oversized tokens ---

func TestIntrospect_OversizedTokenRejected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("server should not be called for oversized token")
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "c",
		ClientSecret:     "s",
	}, testLogger())

	oversized := strings.Repeat("a", MaxBearerTokenLength+1)
	_, err := client.Introspect(context.Background(), oversized)
	if err == nil {
		t.Fatal("expected error for oversized token via Introspect()")
	}
	if !errors.Is(err, ErrTokenOversized) {
		t.Errorf("expected ErrTokenOversized, got: %v", err)
	}
}

// --- Adversarial: F10 — Context cancellation test ---

func TestIntrospectionClient_ContextCancelled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		resp := IntrospectionResponse{Active: true, Sub: "user", Exp: time.Now().Add(time.Hour).Unix()}
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewIntrospectionClient(IntrospectionClientConfig{
		IntrospectionURL: server.URL,
		ClientID:         "c",
		ClientSecret:     "s",
	}, testLogger())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, err := client.Introspect(ctx, "some-token")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, ErrIntrospectionFailed) {
		t.Errorf("expected ErrIntrospectionFailed, got: %v", err)
	}
}
