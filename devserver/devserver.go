// Package devserver provides a mock OAuth2 server for local development and testing.
//
// It implements two RFC-compliant endpoints:
//   - POST /token — issues opaque bearer tokens (RFC 6749 client_credentials and password grants)
//   - POST /introspect — validates tokens (RFC 7662 token introspection)
//   - GET / — HTML dashboard showing available users and usage examples
//
// Tokens are stored in memory and expire after a configurable TTL.
// This server is NOT intended for production use.
package devserver

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// User represents a pre-configured dev identity that can obtain tokens.
type User struct {
	Name  string // Unique identifier used as subject prefix (e.g. "admin")
	Email string // Email claim returned in introspection
	Scope string // Space-delimited OAuth2 scopes (e.g. "bgcheck:admin openid")
}

// Config configures the dev auth server.
type Config struct {
	// ClientID and ClientSecret are used to authenticate /token and /introspect
	// requests via HTTP Basic Auth. Both are required.
	ClientID     string
	ClientSecret string

	// Users is the list of pre-configured identities. At least one is required.
	Users []User

	// TokenTTL is how long issued tokens remain valid. Defaults to 1 hour.
	TokenTTL time.Duration

	// Logger for request logging. Defaults to slog.Default().
	Logger *slog.Logger
}

type tokenInfo struct {
	User      User
	ExpiresAt time.Time
}

// Server is a mock OAuth2 authorization server for local development.
type Server struct {
	mu           sync.RWMutex
	tokens       map[string]*tokenInfo
	users        map[string]User
	clientID     string
	clientSecret string
	tokenTTL     time.Duration
	log          *slog.Logger
}

// New creates a new dev auth server. Panics if config is invalid.
func New(cfg Config) *Server {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		panic("devserver: ClientID and ClientSecret are required")
	}
	if len(cfg.Users) == 0 {
		panic("devserver: at least one User is required")
	}

	ttl := cfg.TokenTTL
	if ttl == 0 {
		ttl = time.Hour
	}

	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	users := make(map[string]User, len(cfg.Users))
	for _, u := range cfg.Users {
		if u.Name == "" {
			panic("devserver: User.Name is required")
		}
		users[u.Name] = u
	}

	return &Server{
		tokens:       make(map[string]*tokenInfo),
		users:        users,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		tokenTTL:     ttl,
		log:          log,
	}
}

// Handler returns an http.Handler with all dev-auth routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("POST /introspect", s.handleIntrospect)
	mux.HandleFunc("GET /", s.handleIndex)
	return mux
}

// handleToken implements a simplified OAuth2 token endpoint.
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	if !s.checkClientAuth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	grantType := r.Form.Get("grant_type")
	var user User
	var found bool

	switch grantType {
	case "client_credentials":
		scope := r.Form.Get("scope")
		user, found = s.matchUser(scope)
	case "password":
		username := r.Form.Get("username")
		user, found = s.users[username]
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": "supported: client_credentials, password",
		})
		return
	}

	if !found {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "invalid_request",
			"error_description": "no matching dev user found",
		})
		return
	}

	token := s.issueToken(user)
	s.log.Info("token issued", "user", user.Name, "grant_type", grantType)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "bearer",
		"expires_in":   int(s.tokenTTL.Seconds()),
		"scope":        user.Scope,
	})
}

// handleIntrospect implements RFC 7662 token introspection.
func (s *Server) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if !s.checkClientAuth(r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}

	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	token := r.Form.Get("token")
	if token == "" {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	s.mu.RLock()
	info, exists := s.tokens[token]
	s.mu.RUnlock()

	if !exists || time.Now().After(info.ExpiresAt) {
		if exists {
			s.mu.Lock()
			delete(s.tokens, token)
			s.mu.Unlock()
		}
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active":     true,
		"sub":        "dev-" + info.User.Name,
		"scope":      info.User.Scope,
		"email":      info.User.Email,
		"username":   info.User.Email,
		"client_id":  s.clientID,
		"token_type": "bearer",
		"exp":        info.ExpiresAt.Unix(),
	})
}

// handleIndex renders an HTML dashboard with available users and usage examples.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Dev Auth Server</title>
<style>body{font-family:monospace;max-width:700px;margin:2em auto;padding:0 1em}
pre{background:#f4f4f4;padding:1em;overflow-x:auto}code{background:#f4f4f4;padding:2px 4px}
table{border-collapse:collapse;width:100%%%%}td,th{border:1px solid #ccc;padding:8px;text-align:left}</style>
</head><body>
<h2>Dev Auth Server</h2>
<p>Client credentials: <code>%s</code> / <code>%s</code></p>
<h3>Available Users</h3>
<table><tr><th>Name</th><th>Email</th><th>Scope</th></tr>`, s.clientID, s.clientSecret)

	for name, u := range s.users {
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>", name, u.Email, u.Scope)
	}

	fmt.Fprintf(w, `</table>
<h3>Get a Token</h3>
<pre>curl -s -X POST http://localhost:PORT/token \
  -u %s:%s \
  -d "grant_type=client_credentials"</pre>
<pre>curl -s -X POST http://localhost:PORT/token \
  -u %s:%s \
  -d "grant_type=password&amp;username=admin"</pre>
</body></html>`, s.clientID, s.clientSecret, s.clientID, s.clientSecret)
}

func (s *Server) checkClientAuth(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	return ok && user == s.clientID && pass == s.clientSecret
}

func (s *Server) issueToken(user User) string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	token := hex.EncodeToString(b)

	s.mu.Lock()
	s.tokens[token] = &tokenInfo{
		User:      user,
		ExpiresAt: time.Now().Add(s.tokenTTL),
	}
	s.mu.Unlock()

	return token
}

func (s *Server) matchUser(scope string) (User, bool) {
	if scope != "" {
		for _, u := range s.users {
			if strings.Contains(u.Scope, scope) {
				return u, true
			}
		}
	}
	for _, u := range s.users {
		return u, true
	}
	return User{}, false
}

// ParseUsersEnv parses the "name|email|scopes;name2|email2|scopes2" environment variable format
// into a slice of User values. Entries with invalid format are silently skipped.
func ParseUsersEnv(raw string) []User {
	var users []User
	for _, entry := range strings.Split(raw, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "|", 3)
		if len(parts) != 3 {
			continue
		}
		users = append(users, User{
			Name:  strings.TrimSpace(parts[0]),
			Email: strings.TrimSpace(parts[1]),
			Scope: strings.TrimSpace(parts[2]),
		})
	}
	return users
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
