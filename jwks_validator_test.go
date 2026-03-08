package authclient

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestValidator creates a JWKSValidator backed by a test JWKS server.
func newTestValidator(t *testing.T, key *rsa.PrivateKey, kid, issuer string, audience []string) *JWKSValidator {
	t.Helper()

	jwksJSON := rsaPublicKeyToJWKS(t, &key.PublicKey, kid)
	server := newTestJWKSServer(t, jwksJSON)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	v, err := NewJWKSValidator(ctx, JWKSValidatorConfig{
		Issuer:   issuer,
		Audience: audience,
		JWKS: JWKSConfig{
			Endpoint:        server.URL,
			RefreshInterval: 5 * time.Minute,
			HTTPTimeout:     10 * time.Second,
		},
	}, testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { v.Close() })
	return v
}

func newValidClaims(issuer string, audience []string) *Claims {
	return &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Audience:  audience,
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
		ClientID: "client-test-uuid",
		Scopes:   []string{"audit:write", "audit:read"},
	}
}

func TestNewJWKSValidator_NilLoggerPanics(t *testing.T) {
	assert.PanicsWithValue(t, "authclient.NewJWKSValidator: logger cannot be nil", func() {
		NewJWKSValidator(context.Background(), JWKSValidatorConfig{}, nil)
	})
}

func TestNewJWKSValidator_UnreachableEndpoint(t *testing.T) {
	_, err := NewJWKSValidator(context.Background(), JWKSValidatorConfig{
		Issuer: "test-issuer",
		JWKS: JWKSConfig{
			Endpoint:    "http://127.0.0.1:1/nonexistent",
			HTTPTimeout: 1 * time.Second,
		},
	}, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "authclient: create JWKS validator")
}

func TestValidateToken_ValidToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", []string{"audit-service"})

	claims := newValidClaims("test-issuer", jwt.ClaimStrings{"audit-service"})
	tokenString := signTestToken(t, key, kid, claims)

	result, err := v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, "client-test-uuid", result.ClientID)
	assert.Equal(t, []string{"audit:write", "audit:read"}, result.Scopes)
	assert.Equal(t, "test-issuer", result.Issuer)
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
		ClientID: "client-expired",
	}
	tokenString := signTestToken(t, key, kid, claims)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

func TestValidateToken_WrongIssuer(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "expected-issuer", nil)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "wrong-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientID: "client-wrong-iss",
	}
	tokenString := signTestToken(t, key, kid, claims)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestValidateToken_WrongAudience(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", []string{"audit-service"})

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"other-service"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientID: "client-wrong-aud",
	}
	tokenString := signTestToken(t, key, kid, claims)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestValidateToken_MalformedToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	_, err = v.ValidateToken(context.Background(), "not.a.valid.token")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestValidateToken_OversizedToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	oversized := strings.Repeat("a", MaxBearerTokenLength+1)
	_, err = v.ValidateToken(context.Background(), oversized)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenOversized)
}

func TestValidateToken_ExactMaxSizeNotRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	// Exactly MaxBearerTokenLength should NOT trigger oversized error
	// It will fail for other reasons (malformed) but not oversized
	exactSize := strings.Repeat("a", MaxBearerTokenLength)
	_, err = v.ValidateToken(context.Background(), exactSize)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrTokenOversized)
}

func TestValidateToken_EmptyClientID(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientID: "",
		Scopes:   []string{"audit:write"},
	}
	tokenString := signTestToken(t, key, kid, claims)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingClientID)
}

func TestValidateToken_MissingExpiration(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "test-issuer",
		},
		ClientID: "client-no-exp",
	}
	tokenString := signTestToken(t, key, kid, claims)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestValidateToken_WrongSigningKey(t *testing.T) {
	servedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, servedKey, kid, "test-issuer", nil)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientID: "client-wrong-key",
	}
	tokenString := signTestToken(t, signingKey, kid, claims)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestValidateToken_NoneAlgorithmRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	claims := jwt.RegisteredClaims{
		Issuer:    "test-issuer",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestValidateToken_HMACAlgorithmRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	secret := []byte("test-hmac-secret-key-for-hs256!!")
	claims := jwt.RegisteredClaims{
		Issuer:    "test-issuer",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secret)
	require.NoError(t, err)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.Error(t, err, "HMAC algorithm must be rejected")
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestValidateToken_NoAudienceValidationWhenEmpty(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil) // no audience configured

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientID: "client-no-aud",
		Scopes:   []string{"audit:write"},
	}
	tokenString := signTestToken(t, key, kid, claims)

	result, err := v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, []string{"audit:write"}, result.Scopes)
}

func TestValidateToken_WithUserID(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientID: "client-with-user",
		Scopes:   []string{"audit:read"},
		UserID:   "user-123",
	}
	tokenString := signTestToken(t, key, kid, claims)

	result, err := v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, "client-with-user", result.ClientID)
	assert.Equal(t, "user-123", result.UserID)
}

func TestJWKSValidator_Close(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	err = v.Close()
	assert.NoError(t, err)
}

func TestJWKSValidator_DoubleClose(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	// First close should succeed.
	err = v.Close()
	assert.NoError(t, err)

	// Second close must not panic — context.CancelFunc is idempotent.
	assert.NotPanics(t, func() {
		err = v.Close()
		assert.NoError(t, err)
	})
}

func TestValidateToken_NotYetValid(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(2 * time.Hour)),
			NotBefore: jwt.NewNumericDate(time.Now().Add(time.Hour)), // not valid yet
		},
		ClientID: "client-nbf",
	}
	tokenString := signTestToken(t, key, kid, claims)

	_, err = v.ValidateToken(context.Background(), tokenString)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenNotYetValid)
}

func TestValidateToken_EmptyToken(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	v := newTestValidator(t, key, kid, "test-issuer", nil)

	_, err = v.ValidateToken(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenMalformed)
}

func TestNewJWKSValidator_EmptyIssuerRejected(t *testing.T) {
	_, err := NewJWKSValidator(context.Background(), JWKSValidatorConfig{
		Issuer: "",
		JWKS: JWKSConfig{
			Endpoint: "http://example.com/.well-known/jwks.json",
		},
	}, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "issuer is required")
}

func TestValidateToken_MultipleAudiences(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := fmt.Sprintf("test-key-%s", t.Name())
	// Validator expects either "svc-a" or "svc-b"
	v := newTestValidator(t, key, kid, "test-issuer", []string{"svc-a", "svc-b"})

	// Token with audience "svc-b" should pass (matches one of expected)
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"svc-b"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientID: "client-multi-aud",
		Scopes:   []string{"read"},
	}
	tokenString := signTestToken(t, key, kid, claims)

	result, err := v.ValidateToken(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, "client-multi-aud", result.ClientID)

	// Token with audience "svc-c" should fail (not in expected list)
	claimsBad := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "test-issuer",
			Audience:  jwt.ClaimStrings{"svc-c"},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		ClientID: "client-bad-aud",
		Scopes:   []string{"read"},
	}
	tokenStringBad := signTestToken(t, key, kid, claimsBad)

	_, err = v.ValidateToken(context.Background(), tokenStringBad)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}
