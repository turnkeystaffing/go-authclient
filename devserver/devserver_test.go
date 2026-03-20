package devserver

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func testServer() *Server {
	return New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Users: []User{
			{Name: "admin", Email: "admin@test.local", Scope: "app:admin openid profile email"},
			{Name: "viewer", Email: "viewer@test.local", Scope: "app:read"},
		},
	})
}

func postForm(t *testing.T, srv *Server, path string, user, pass string, data url.Values) *httptest.ResponseRecorder {
	t.Helper()
	body := data.Encode()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func getRequest(t *testing.T, srv *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	return w
}

func parseJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("parse json: %v (body: %s)", err, w.Body.String())
	}
	return m
}

func TestToken_ClientCredentials(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"client_credentials"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := parseJSON(t, w)
	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %v", resp["token_type"])
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("expected non-empty access_token")
	}
	if resp["scope"] == nil {
		t.Error("expected scope in response")
	}
}

func TestToken_IsJWT(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"client_credentials"},
	})

	token := parseJSON(t, w)["access_token"].(string)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected JWT with 3 parts, got %d parts", len(parts))
	}
}

func TestToken_JWTValidatesWithPublicKey(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"client_credentials"},
		"audience":   {"test-aud"},
	})

	tokenStr := parseJSON(t, w)["access_token"].(string)

	// Parse and validate with the server's public key.
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return &srv.privateKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}
	if !token.Valid {
		t.Fatal("JWT is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}
	if claims["iss"] != "devserver" {
		t.Errorf("expected iss=devserver, got %v", claims["iss"])
	}
	if claims["client_id"] != "test-client" {
		t.Errorf("expected client_id=test-client, got %v", claims["client_id"])
	}
	if claims["gty"] != "client_credentials" {
		t.Errorf("expected gty=client_credentials, got %v", claims["gty"])
	}
}

func TestToken_PasswordGrant(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"password"},
		"username":   {"viewer"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	resp := parseJSON(t, w)
	if resp["scope"] != "app:read" {
		t.Errorf("expected scope=app:read, got %v", resp["scope"])
	}
}

func TestToken_InvalidClient(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/token", "wrong", "wrong", url.Values{
		"grant_type": {"client_credentials"},
	})

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestToken_NoAuth(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/token", "", "", url.Values{
		"grant_type": {"client_credentials"},
	})

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestToken_UnsupportedGrant(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"authorization_code"},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	resp := parseJSON(t, w)
	if resp["error"] != "unsupported_grant_type" {
		t.Errorf("expected unsupported_grant_type, got %v", resp["error"])
	}
}

func TestToken_UnknownUser(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"password"},
		"username":   {"nonexistent"},
	})

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestToken_ScopeMatching(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"app:read"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := parseJSON(t, w)
	if resp["scope"] != "app:read" {
		t.Errorf("expected scope=app:read, got %v", resp["scope"])
	}
}

func TestIntrospect_ValidToken(t *testing.T) {
	srv := testServer()

	// Issue a token first.
	tokenResp := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"client_credentials"},
	})
	token := parseJSON(t, tokenResp)["access_token"].(string)

	// Introspect it.
	w := postForm(t, srv, "/introspect", "test-client", "test-secret", url.Values{
		"token": {token},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp := parseJSON(t, w)
	if resp["active"] != true {
		t.Errorf("expected active=true, got %v", resp["active"])
	}
	if resp["email"] == nil || resp["email"] == "" {
		t.Error("expected non-empty email")
	}
	if resp["sub"] == nil || resp["sub"] == "" {
		t.Error("expected non-empty sub")
	}
	if resp["scope"] == nil || resp["scope"] == "" {
		t.Error("expected non-empty scope")
	}
	if resp["exp"] == nil {
		t.Error("expected exp claim")
	}
	if resp["iat"] == nil {
		t.Error("expected iat claim")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("expected token_type=Bearer, got %v", resp["token_type"])
	}
}

func TestIntrospect_InvalidToken(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/introspect", "test-client", "test-secret", url.Values{
		"token": {"bogus-token"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp := parseJSON(t, w)
	if resp["active"] != false {
		t.Errorf("expected active=false, got %v", resp["active"])
	}
}

func TestIntrospect_EmptyToken(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/introspect", "test-client", "test-secret", url.Values{
		"token": {""},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	resp := parseJSON(t, w)
	if resp["active"] != false {
		t.Errorf("expected active=false")
	}
}

func TestIntrospect_InvalidClient(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/introspect", "wrong", "wrong", url.Values{
		"token": {"any"},
	})

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestIndex_ReturnsHTML(t *testing.T) {
	srv := testServer()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("expected text/html, got %s", ct)
	}
	if !strings.Contains(w.Body.String(), "Dev Auth Server") {
		t.Error("expected dashboard content")
	}
}

func TestJWKS_Endpoint(t *testing.T) {
	srv := testServer()
	w := getRequest(t, srv, "/.well-known/jwks.json")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}

	var jwks struct {
		Keys []struct {
			Kty string `json:"kty"`
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("failed to parse JWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	key := jwks.Keys[0]
	if key.Kty != "RSA" {
		t.Errorf("expected kty=RSA, got %s", key.Kty)
	}
	if key.Kid != "devserver-1" {
		t.Errorf("expected kid=devserver-1, got %s", key.Kid)
	}
	if key.Alg != "RS256" {
		t.Errorf("expected alg=RS256, got %s", key.Alg)
	}
}

func TestJWKS_RoundTrip(t *testing.T) {
	srv := testServer()

	// Get JWKS.
	jwksResp := getRequest(t, srv, "/.well-known/jwks.json")
	var jwks struct {
		Keys []struct {
			N string `json:"n"`
			E string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwksResp.Body.Bytes(), &jwks); err != nil {
		t.Fatalf("failed to parse JWKS: %v", err)
	}

	// Reconstruct public key from JWKS.
	nBytes, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].N)
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwks.Keys[0].E)
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}

	// Issue a token.
	tokenResp := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"client_credentials"},
		"audience":   {"my-api"},
	})
	tokenStr := parseJSON(t, tokenResp)["access_token"].(string)

	// Validate with reconstructed public key.
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return pubKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("JWT validation failed: %v", err)
	}
	if !token.Valid {
		t.Fatal("JWT is not valid")
	}
}

func TestDiscovery_Endpoint(t *testing.T) {
	srv := testServer()
	w := getRequest(t, srv, "/.well-known/oauth-authorization-server")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	resp := parseJSON(t, w)
	if resp["issuer"] != "devserver" {
		t.Errorf("expected issuer=devserver, got %v", resp["issuer"])
	}
	if resp["jwks_uri"] != "devserver/.well-known/jwks.json" {
		t.Errorf("unexpected jwks_uri: %v", resp["jwks_uri"])
	}
	grants, ok := resp["grant_types_supported"].([]any)
	if !ok || len(grants) != 2 {
		t.Errorf("expected 2 grant types, got %v", resp["grant_types_supported"])
	}
}

func TestRouteAliases(t *testing.T) {
	srv := testServer()

	// /api/v1/oauth/token should work.
	w := postForm(t, srv, "/api/v1/oauth/token", "test-client", "test-secret", url.Values{
		"grant_type": {"client_credentials"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("/api/v1/oauth/token: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	token := parseJSON(t, w)["access_token"].(string)

	// /api/v1/oauth/introspect should work.
	w = postForm(t, srv, "/api/v1/oauth/introspect", "test-client", "test-secret", url.Values{
		"token": {token},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("/api/v1/oauth/introspect: expected 200, got %d", w.Code)
	}
	resp := parseJSON(t, w)
	if resp["active"] != true {
		t.Errorf("expected active=true via alias")
	}
}

func TestPerServiceUsers(t *testing.T) {
	srv := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Services: []ServiceConfig{
			{
				Audience: "api-a",
				Users:    []User{{Name: "alice", Email: "alice@a.local", Scope: "a:admin"}},
			},
			{
				Audience: "api-b",
				Users:    []User{{Name: "bob", Email: "bob@b.local", Scope: "b:read"}},
			},
		},
	})

	// alice should be found for api-a.
	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"audience":   {"api-a"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp := parseJSON(t, w)
	if resp["scope"] != "a:admin" {
		t.Errorf("expected scope=a:admin, got %v", resp["scope"])
	}

	// alice should NOT be found for api-b.
	w = postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"password"},
		"username":   {"alice"},
		"audience":   {"api-b"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong audience, got %d", w.Code)
	}

	// bob should be found for api-b via client_credentials.
	w = postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"client_credentials"},
		"audience":   {"api-b"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	resp = parseJSON(t, w)
	if resp["scope"] != "b:read" {
		t.Errorf("expected scope=b:read, got %v", resp["scope"])
	}
}

func TestPerServiceUsers_UnknownAudience(t *testing.T) {
	srv := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Services: []ServiceConfig{
			{
				Audience: "api-a",
				Users:    []User{{Name: "alice", Email: "alice@a.local", Scope: "a:admin"}},
			},
		},
	})

	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"client_credentials"},
		"audience":   {"unknown-api"},
	})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unknown audience, got %d", w.Code)
	}
}

func TestBackwardCompat_UsersWithoutServices(t *testing.T) {
	// When only Users is set (no Services), all audiences should use the global user set.
	srv := testServer()

	// With audience parameter — should still find admin from global users.
	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"password"},
		"username":   {"admin"},
		"audience":   {"some-api"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Without audience parameter — should also work.
	w = postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"password"},
		"username":   {"viewer"},
	})
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestToken_JWTContainsAudience(t *testing.T) {
	srv := testServer()
	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"client_credentials"},
		"audience":   {"my-api"},
	})

	tokenStr := parseJSON(t, w)["access_token"].(string)
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return &srv.privateKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}

	aud, err := token.Claims.GetAudience()
	if err != nil {
		t.Fatalf("failed to get audience: %v", err)
	}
	if len(aud) != 1 || aud[0] != "my-api" {
		t.Errorf("expected audience=[my-api], got %v", aud)
	}
}

func TestParseUsersEnv(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"single user", "admin|admin@test.local|app:admin", 1},
		{"multiple users", "admin|a@t.l|app:admin;viewer|v@t.l|app:read", 2},
		{"trailing semicolon", "admin|a@t.l|app:admin;", 1},
		{"empty string", "", 0},
		{"invalid format", "bad-entry", 0},
		{"mixed valid and invalid", "admin|a@t.l|app:admin;bad;viewer|v@t.l|app:read", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := ParseUsersEnv(tt.input)
			if len(users) != tt.want {
				t.Errorf("ParseUsersEnv(%q) returned %d users, want %d", tt.input, len(users), tt.want)
			}
		})
	}
}

func TestParseServicesEnv(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantSvcs int
	}{
		{"single service", "api-a:admin|a@t.l|a:admin", 1},
		{"two services", "api-a:admin|a@t.l|a:admin;api-b:bob|b@t.l|b:read", 2},
		{"multiple users per service", "api-a:admin|a@t.l|a:admin,viewer|v@t.l|a:read", 1},
		{"trailing semicolon", "api-a:admin|a@t.l|a:admin;", 1},
		{"empty string", "", 0},
		{"no colon", "bad-entry", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svcs := ParseServicesEnv(tt.input)
			if len(svcs) != tt.wantSvcs {
				t.Errorf("ParseServicesEnv(%q) returned %d services, want %d", tt.input, len(svcs), tt.wantSvcs)
			}
		})
	}

	// Verify user details.
	svcs := ParseServicesEnv("api-a:admin|a@t.l|a:admin,viewer|v@t.l|a:read")
	if len(svcs) != 1 {
		t.Fatal("expected 1 service")
	}
	if svcs[0].Audience != "api-a" {
		t.Errorf("expected audience=api-a, got %s", svcs[0].Audience)
	}
	if len(svcs[0].Users) != 2 {
		t.Errorf("expected 2 users, got %d", len(svcs[0].Users))
	}
}

func TestNew_PanicsOnInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"empty client_id", Config{ClientID: "", ClientSecret: "s", Users: []User{{Name: "a", Email: "a@t", Scope: "s"}}}},
		{"empty client_secret", Config{ClientID: "c", ClientSecret: "", Users: []User{{Name: "a", Email: "a@t", Scope: "s"}}}},
		{"no users or services", Config{ClientID: "c", ClientSecret: "s"}},
		{"empty user name", Config{ClientID: "c", ClientSecret: "s", Users: []User{{Name: "", Email: "a@t", Scope: "s"}}}},
		{"empty service audience", Config{ClientID: "c", ClientSecret: "s", Services: []ServiceConfig{{Audience: "", Users: []User{{Name: "a", Email: "a@t", Scope: "s"}}}}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("expected panic")
				}
			}()
			New(tt.cfg)
		})
	}
}

func TestRoundTrip_TokenThenIntrospect(t *testing.T) {
	srv := testServer()

	// Get viewer token via password grant.
	tokenResp := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"password"},
		"username":   {"viewer"},
	})
	if tokenResp.Code != http.StatusOK {
		t.Fatalf("token: expected 200, got %d", tokenResp.Code)
	}
	token := parseJSON(t, tokenResp)["access_token"].(string)

	// Introspect — should return viewer's claims.
	introResp := postForm(t, srv, "/introspect", "test-client", "test-secret", url.Values{
		"token": {token},
	})
	if introResp.Code != http.StatusOK {
		t.Fatalf("introspect: expected 200, got %d", introResp.Code)
	}

	resp := parseJSON(t, introResp)
	if resp["active"] != true {
		t.Fatal("expected active=true")
	}
	if resp["sub"] != "dev-viewer" {
		t.Errorf("expected sub=dev-viewer, got %v", resp["sub"])
	}
	if resp["scope"] != "app:read" {
		t.Errorf("expected scope=app:read, got %v", resp["scope"])
	}
	if resp["email"] != "viewer@test.local" {
		t.Errorf("expected email=viewer@test.local, got %v", resp["email"])
	}
}

func TestCustomIssuer(t *testing.T) {
	srv := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Users:        []User{{Name: "admin", Email: "admin@test.local", Scope: "app:admin"}},
		Issuer:       "http://localhost:9091",
	})

	// Check JWT has custom issuer.
	w := postForm(t, srv, "/token", "test-client", "test-secret", url.Values{
		"grant_type": {"client_credentials"},
	})
	tokenStr := parseJSON(t, w)["access_token"].(string)
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		return &srv.privateKey.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer("http://localhost:9091"))
	if err != nil {
		t.Fatalf("failed to parse JWT: %v", err)
	}
	if !token.Valid {
		t.Fatal("JWT is not valid")
	}

	// Check discovery endpoint reflects custom issuer.
	dw := getRequest(t, srv, "/.well-known/oauth-authorization-server")
	dresp := parseJSON(t, dw)
	if dresp["issuer"] != "http://localhost:9091" {
		t.Errorf("expected custom issuer, got %v", dresp["issuer"])
	}
}

func TestIndex_ShowsServicesWhenConfigured(t *testing.T) {
	srv := New(Config{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Services: []ServiceConfig{
			{Audience: "api-a", Users: []User{{Name: "alice", Email: "alice@a.local", Scope: "a:admin"}}},
		},
	})

	w := getRequest(t, srv, "/")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "api-a") {
		t.Error("expected dashboard to show service audience")
	}
	if !strings.Contains(body, "alice") {
		t.Error("expected dashboard to show service user")
	}
}
