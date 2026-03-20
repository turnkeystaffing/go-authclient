// Package devserver provides a mock OAuth2 server for local development and testing.
//
// It implements the following endpoints:
//   - POST /token — issues JWT bearer tokens (RFC 6749 client_credentials and password grants)
//   - POST /introspect — validates tokens (RFC 7662 token introspection)
//   - GET /.well-known/jwks.json — serves the JWKS public key set
//   - GET /.well-known/oauth-authorization-server — OAuth2 discovery metadata
//   - POST /api/v1/oauth/token — alias for /token
//   - POST /api/v1/oauth/introspect — alias for /introspect
//   - GET / — HTML dashboard showing available users and usage examples
//
// Tokens are JWTs signed with an ephemeral RSA key pair and expire after a configurable TTL.
// This server is NOT intended for production use.
package devserver

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// User represents a pre-configured dev identity that can obtain tokens.
type User struct {
	Name  string // Unique identifier used as subject prefix (e.g. "admin")
	Email string // Email claim returned in introspection
	Scope string // Space-delimited OAuth2 scopes (e.g. "bgcheck:admin openid")
}

// ServiceConfig defines a set of users for a specific audience.
type ServiceConfig struct {
	Audience string
	Users    []User
}

// Config configures the dev auth server.
type Config struct {
	// ClientID and ClientSecret are used to authenticate /token and /introspect
	// requests via HTTP Basic Auth. Both are required.
	ClientID     string
	ClientSecret string

	// Users is the list of pre-configured identities. Used for all audiences
	// when Services is empty. At least one of Users or Services is required.
	Users []User

	// TokenTTL is how long issued tokens remain valid. Defaults to 1 hour.
	TokenTTL time.Duration

	// Logger for request logging. Defaults to slog.Default().
	Logger *slog.Logger

	// Issuer is the JWT issuer claim. Defaults to "devserver".
	Issuer string

	// Services provides per-audience user sets. When populated, user resolution
	// is based on the audience from the token request instead of the global Users list.
	Services []ServiceConfig
}

// devClaims mirrors authclient.Claims with identical JSON tags.
type devClaims struct {
	jwt.RegisteredClaims
	ClientID  string   `json:"client_id"`
	Scopes    []string `json:"scopes"`
	UserID    string   `json:"user_id,omitempty"`
	Email     string   `json:"email,omitempty"`
	Username  string   `json:"username,omitempty"`
	GrantType string   `json:"gty,omitempty"`
	AuthTime  int64    `json:"auth_time,omitempty"`
}

type tokenInfo struct {
	User      User
	Audience  string
	GrantType string
	ExpiresAt time.Time
	IssuedAt  time.Time
}

// Server is a mock OAuth2 authorization server for local development.
type Server struct {
	mu           sync.RWMutex
	tokens       map[string]*tokenInfo
	users        map[string]User            // global users (backward compat)
	services     map[string]map[string]User // audience -> name -> User
	clientID     string
	clientSecret string
	tokenTTL     time.Duration
	log          *slog.Logger
	issuer       string
	privateKey   *rsa.PrivateKey
	jwksJSON     []byte
}

const kid = "devserver-1"

// New creates a new dev auth server. Panics if config is invalid.
func New(cfg Config) *Server {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		panic("devserver: ClientID and ClientSecret are required")
	}
	if len(cfg.Users) == 0 && len(cfg.Services) == 0 {
		panic("devserver: at least one User or Service is required")
	}

	ttl := cfg.TokenTTL
	if ttl == 0 {
		ttl = time.Hour
	}

	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}

	issuer := cfg.Issuer
	if issuer == "" {
		issuer = "devserver"
	}

	// Build global users map.
	users := make(map[string]User, len(cfg.Users))
	for _, u := range cfg.Users {
		if u.Name == "" {
			panic("devserver: User.Name is required")
		}
		users[u.Name] = u
	}

	// Build per-service users map.
	services := make(map[string]map[string]User, len(cfg.Services))
	for _, svc := range cfg.Services {
		if svc.Audience == "" {
			panic("devserver: ServiceConfig.Audience is required")
		}
		m := make(map[string]User, len(svc.Users))
		for _, u := range svc.Users {
			if u.Name == "" {
				panic("devserver: User.Name is required")
			}
			m[u.Name] = u
		}
		services[svc.Audience] = m
	}

	// Generate ephemeral RSA key pair.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("devserver: failed to generate RSA key: " + err.Error())
	}

	// Precompute JWKS JSON.
	jwksJSON := buildJWKSJSON(&privateKey.PublicKey)

	return &Server{
		tokens:       make(map[string]*tokenInfo),
		users:        users,
		services:     services,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		tokenTTL:     ttl,
		log:          log,
		issuer:       issuer,
		privateKey:   privateKey,
		jwksJSON:     jwksJSON,
	}
}

func buildJWKSJSON(pub *rsa.PublicKey) []byte {
	jwks := map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": kid,
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
	data, err := json.Marshal(jwks)
	if err != nil {
		panic("devserver: failed to marshal JWKS: " + err.Error())
	}
	return data
}

// Handler returns an http.Handler with all dev-auth routes registered.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", s.handleToken)
	mux.HandleFunc("POST /introspect", s.handleIntrospect)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.handleDiscovery)
	mux.HandleFunc("POST /api/v1/oauth/token", s.handleToken)
	mux.HandleFunc("POST /api/v1/oauth/introspect", s.handleIntrospect)
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
	audience := r.Form.Get("audience")
	var user User
	var found bool

	switch grantType {
	case "client_credentials":
		scope := r.Form.Get("scope")
		user, found = s.matchUser(scope, audience)
	case "password":
		username := r.Form.Get("username")
		user, found = s.lookupUser(username, audience)
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

	token := s.issueJWT(user, audience, grantType)
	s.log.Info("token issued", "user", user.Name, "grant_type", grantType, "audience", audience)

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
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
		"token_type": "Bearer",
		"exp":        info.ExpiresAt.Unix(),
		"iat":        info.IssuedAt.Unix(),
	})
}

// handleJWKS serves the precomputed JWKS JSON.
func (s *Server) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(s.jwksJSON) //nolint:errcheck
}

// handleDiscovery serves OAuth2 authorization server metadata (RFC 8414).
func (s *Server) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.issuer,
		"token_endpoint":                        s.issuer + "/token",
		"introspection_endpoint":                s.issuer + "/introspect",
		"jwks_uri":                              s.issuer + "/.well-known/jwks.json",
		"grant_types_supported":                 []string{"client_credentials", "password"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic"},
	})
}

// handleIndex renders an HTML dashboard with available users and usage examples.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><title>Dev Auth Server</title>
<style>body{font-family:monospace;max-width:700px;margin:2em auto;padding:0 1em}
pre{background:#f4f4f4;padding:1em;overflow-x:auto}code{background:#f4f4f4;padding:2px 4px}
table{border-collapse:collapse;width:100%%%%}td,th{border:1px solid #ccc;padding:8px;text-align:left}
h4{margin:1em 0 0.3em}</style>
</head><body>
<h2>Dev Auth Server</h2>
<p>Issuer: <code>%s</code></p>
<p>Client credentials: <code>%s</code> / <code>%s</code></p>
<p>JWKS endpoint: <code>%s/.well-known/jwks.json</code></p>`, s.issuer, s.clientID, s.clientSecret, s.issuer)

	if len(s.services) > 0 {
		for aud, users := range s.services {
			fmt.Fprintf(w, `<h3>Service: <code>%s</code></h3>
<table><tr><th>Name</th><th>Email</th><th>Scope</th></tr>`, aud)
			for name, u := range users {
				fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td><td>%s</td></tr>", name, u.Email, u.Scope)
			}
			fmt.Fprint(w, `</table>
<h4>Get a Token</h4>
<pre>curl -s -X POST http://localhost:PORT/token \
  -u `+s.clientID+`:`+s.clientSecret+` \
  -d "grant_type=client_credentials&amp;audience=`+aud+`"</pre>`)
		}
	} else {
		fmt.Fprint(w, `<h3>Available Users</h3>
<table><tr><th>Name</th><th>Email</th><th>Scope</th></tr>`)
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
  -d "grant_type=password&amp;username=admin"</pre>`, s.clientID, s.clientSecret, s.clientID, s.clientSecret)
	}

	fmt.Fprint(w, `</body></html>`)
}

func (s *Server) checkClientAuth(r *http.Request) bool {
	user, pass, ok := r.BasicAuth()
	return ok && user == s.clientID && pass == s.clientSecret
}

func (s *Server) issueJWT(user User, audience, grantType string) string {
	now := time.Now()
	exp := now.Add(s.tokenTTL)

	scopes := strings.Fields(user.Scope)

	claims := devClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   "dev-" + user.Name,
			ExpiresAt: jwt.NewNumericDate(exp),
			IssuedAt:  jwt.NewNumericDate(now),
		},
		ClientID:  s.clientID,
		Scopes:    scopes,
		UserID:    "dev-" + user.Name,
		Email:     user.Email,
		Username:  user.Email,
		GrantType: grantType,
		AuthTime:  now.Unix(),
	}

	if audience != "" {
		claims.Audience = jwt.ClaimStrings{audience}
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		panic("devserver: failed to sign JWT: " + err.Error())
	}

	// Store in memory for introspection lookup.
	s.mu.Lock()
	s.tokens[signed] = &tokenInfo{
		User:      user,
		Audience:  audience,
		GrantType: grantType,
		ExpiresAt: exp,
		IssuedAt:  now,
	}
	s.mu.Unlock()

	return signed
}

// lookupUser finds a user by name, considering per-service config.
func (s *Server) lookupUser(name, audience string) (User, bool) {
	if len(s.services) > 0 && audience != "" {
		if svcUsers, ok := s.services[audience]; ok {
			u, found := svcUsers[name]
			return u, found
		}
		return User{}, false
	}
	u, found := s.users[name]
	return u, found
}

// matchUser finds a user by scope, considering per-service config.
func (s *Server) matchUser(scope, audience string) (User, bool) {
	userSet := s.users
	if len(s.services) > 0 && audience != "" {
		if svcUsers, ok := s.services[audience]; ok {
			userSet = svcUsers
		} else {
			return User{}, false
		}
	}

	if scope != "" {
		for _, u := range userSet {
			if strings.Contains(u.Scope, scope) {
				return u, true
			}
		}
	}
	for _, u := range userSet {
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

// ParseServicesEnv parses per-audience user definitions from the format:
// "audience:name|email|scopes,name2|email2|scopes2;audience2:name|email|scopes"
func ParseServicesEnv(raw string) []ServiceConfig {
	var services []ServiceConfig
	for _, svcEntry := range strings.Split(raw, ";") {
		svcEntry = strings.TrimSpace(svcEntry)
		if svcEntry == "" {
			continue
		}
		colonIdx := strings.Index(svcEntry, ":")
		if colonIdx < 1 {
			continue
		}
		audience := strings.TrimSpace(svcEntry[:colonIdx])
		usersStr := svcEntry[colonIdx+1:]

		var users []User
		for _, userEntry := range strings.Split(usersStr, ",") {
			userEntry = strings.TrimSpace(userEntry)
			if userEntry == "" {
				continue
			}
			parts := strings.SplitN(userEntry, "|", 3)
			if len(parts) != 3 {
				continue
			}
			users = append(users, User{
				Name:  strings.TrimSpace(parts[0]),
				Email: strings.TrimSpace(parts[1]),
				Scope: strings.TrimSpace(parts[2]),
			})
		}

		if len(users) > 0 {
			services = append(services, ServiceConfig{
				Audience: audience,
				Users:    users,
			})
		}
	}
	return services
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}
