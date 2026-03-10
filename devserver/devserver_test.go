package devserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
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
	if resp["token_type"] != "bearer" {
		t.Errorf("expected token_type=bearer, got %v", resp["token_type"])
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("expected non-empty access_token")
	}
	if resp["scope"] == nil {
		t.Error("expected scope in response")
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

func TestNew_PanicsOnInvalidConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{"empty client_id", Config{ClientID: "", ClientSecret: "s", Users: []User{{Name: "a", Email: "a@t", Scope: "s"}}}},
		{"empty client_secret", Config{ClientID: "c", ClientSecret: "", Users: []User{{Name: "a", Email: "a@t", Scope: "s"}}}},
		{"no users", Config{ClientID: "c", ClientSecret: "s", Users: nil}},
		{"empty user name", Config{ClientID: "c", ClientSecret: "s", Users: []User{{Name: "", Email: "a@t", Scope: "s"}}}},
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
