package authclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// rsaPublicKeyToJWKS creates a minimal JWKS JSON from an RSA public key with the given kid.
func rsaPublicKeyToJWKS(t *testing.T, key *rsa.PublicKey, kid string) []byte {
	t.Helper()
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": kid,
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			},
		},
	}
	data, err := json.Marshal(jwks)
	require.NoError(t, err)
	return data
}

// newTestJWKSServer creates an httptest.Server serving the given JWKS JSON.
func newTestJWKSServer(t *testing.T, jwksJSON []byte) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON)
	}))
	t.Cleanup(server.Close)
	return server
}

func signTestToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.Claims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func TestNewJWKSProvider_Success(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	server := newTestJWKSServer(t, rsaPublicKeyToJWKS(t, &key.PublicKey, kid))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	provider, err := NewJWKSProvider(ctx, JWKSConfig{
		Endpoint:        server.URL,
		RefreshInterval: 5 * time.Minute,
		HTTPTimeout:     10 * time.Second,
	}, testLogger())
	require.NoError(t, err)
	defer provider.Close()

	assert.NotNil(t, provider.Keyfunc())
}

func TestNewJWKSProvider_UnreachableEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	_, err := NewJWKSProvider(ctx, JWKSConfig{
		Endpoint:        "http://127.0.0.1:1/nonexistent",
		RefreshInterval: 5 * time.Minute,
		HTTPTimeout:     1 * time.Second,
	}, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authclient: create JWKS provider")
}

func TestNewJWKSProvider_EmptyEndpoint(t *testing.T) {
	_, err := NewJWKSProvider(context.Background(), JWKSConfig{}, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JWKS endpoint is required")
}

func TestNewJWKSProvider_NilLoggerPanics(t *testing.T) {
	assert.PanicsWithValue(t, "authclient.NewJWKSProvider: logger cannot be nil", func() {
		NewJWKSProvider(context.Background(), JWKSConfig{Endpoint: "http://example.com"}, nil)
	})
}

func TestNewJWKSProvider_DefaultConfig(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	server := newTestJWKSServer(t, rsaPublicKeyToJWKS(t, &key.PublicKey, kid))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Zero RefreshInterval and HTTPTimeout should use defaults
	provider, err := NewJWKSProvider(ctx, JWKSConfig{
		Endpoint: server.URL,
	}, testLogger())
	require.NoError(t, err)
	defer provider.Close()

	assert.NotNil(t, provider.Keyfunc())
}

func TestJWKSProvider_ValidateToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	server := newTestJWKSServer(t, rsaPublicKeyToJWKS(t, &key.PublicKey, kid))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	provider, err := NewJWKSProvider(ctx, JWKSConfig{
		Endpoint:        server.URL,
		RefreshInterval: 5 * time.Minute,
		HTTPTimeout:     10 * time.Second,
	}, testLogger())
	require.NoError(t, err)
	defer provider.Close()

	claims := jwt.RegisteredClaims{
		Issuer:    "test-issuer",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tokenString := signTestToken(t, key, kid, claims)

	parsed, err := jwt.Parse(tokenString, provider.Keyfunc())
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
}

func TestJWKSProvider_WrongKey(t *testing.T) {
	servedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	server := newTestJWKSServer(t, rsaPublicKeyToJWKS(t, &servedKey.PublicKey, kid))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	provider, err := NewJWKSProvider(ctx, JWKSConfig{
		Endpoint:        server.URL,
		RefreshInterval: 5 * time.Minute,
		HTTPTimeout:     10 * time.Second,
	}, testLogger())
	require.NoError(t, err)
	defer provider.Close()

	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tokenString := signTestToken(t, signingKey, kid, claims)

	_, err = jwt.Parse(tokenString, provider.Keyfunc())
	require.Error(t, err)
}

func TestJWKSProvider_KeyRotation(t *testing.T) {
	key1, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	key2, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid1 := fmt.Sprintf("key1-%s", t.Name())
	kid2 := fmt.Sprintf("key2-%s", t.Name())

	var mu sync.Mutex
	currentJWKS := rsaPublicKeyToJWKS(t, &key1.PublicKey, kid1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		data := currentJWKS
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	provider, err := NewJWKSProvider(ctx, JWKSConfig{
		Endpoint:        server.URL,
		RefreshInterval: 100 * time.Millisecond,
		HTTPTimeout:     10 * time.Second,
	}, testLogger())
	require.NoError(t, err)
	defer provider.Close()

	// Token signed with key1 validates
	claims := jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tokenString1 := signTestToken(t, key1, kid1, claims)
	parsed1, err := jwt.Parse(tokenString1, provider.Keyfunc())
	require.NoError(t, err)
	assert.True(t, parsed1.Valid)

	// Rotate to key2
	mu.Lock()
	currentJWKS = rsaPublicKeyToJWKS(t, &key2.PublicKey, kid2)
	mu.Unlock()

	// Wait for refresh cycle
	time.Sleep(300 * time.Millisecond)

	// Token signed with key2 validates after rotation
	tokenString2 := signTestToken(t, key2, kid2, claims)
	parsed2, err := jwt.Parse(tokenString2, provider.Keyfunc())
	require.NoError(t, err)
	assert.True(t, parsed2.Valid)
}

func TestJWKSProvider_Close(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	server := newTestJWKSServer(t, rsaPublicKeyToJWKS(t, &key.PublicKey, kid))

	provider, err := NewJWKSProvider(context.Background(), JWKSConfig{
		Endpoint:        server.URL,
		RefreshInterval: 5 * time.Minute,
		HTTPTimeout:     10 * time.Second,
	}, testLogger())
	require.NoError(t, err)

	err = provider.Close()
	assert.NoError(t, err)
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal URL unchanged",
			input:    "https://auth.example.com/.well-known/jwks.json",
			expected: "https://auth.example.com/.well-known/jwks.json",
		},
		{
			name:     "strips credentials",
			input:    "https://user:password@auth.example.com/jwks",
			expected: "https://auth.example.com/jwks",
		},
		{
			name:     "strips query params",
			input:    "https://auth.example.com/jwks?token=secret&key=value",
			expected: "https://auth.example.com/jwks",
		},
		{
			name:     "strips fragment",
			input:    "https://auth.example.com/jwks#section",
			expected: "https://auth.example.com/jwks",
		},
		{
			name:     "strips credentials and query params",
			input:    "https://admin:s3cret@auth.example.com/jwks?api_key=abc",
			expected: "https://auth.example.com/jwks",
		},
		{
			name:     "invalid URL returns placeholder",
			input:    "://not-a-url",
			expected: "<invalid-url>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeURL(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewJWKSProvider_NegativeDurations(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	server := newTestJWKSServer(t, rsaPublicKeyToJWKS(t, &key.PublicKey, kid))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Negative RefreshInterval and HTTPTimeout should use defaults (not panic or fail)
	provider, err := NewJWKSProvider(ctx, JWKSConfig{
		Endpoint:        server.URL,
		RefreshInterval: -5 * time.Minute,
		HTTPTimeout:     -10 * time.Second,
	}, testLogger())
	require.NoError(t, err)
	defer provider.Close()

	assert.NotNil(t, provider.Keyfunc())
}

func TestJWKSProvider_ContextCancellation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	server := newTestJWKSServer(t, rsaPublicKeyToJWKS(t, &key.PublicKey, kid))

	ctx, cancel := context.WithCancel(context.Background())

	provider, err := NewJWKSProvider(ctx, JWKSConfig{
		Endpoint:        server.URL,
		RefreshInterval: 5 * time.Minute,
		HTTPTimeout:     10 * time.Second,
	}, testLogger())
	require.NoError(t, err)

	// Cancel parent context — stops background refresh
	cancel()

	// Cached keyfunc still available
	assert.NotNil(t, provider.Keyfunc())
}
