# go-authclient

A framework-agnostic Go library for OAuth 2.0 token validation, introspection, and acquisition. Supports local JWT validation via JWKS, remote token introspection (RFC 7662), and client_credentials token acquisition with proactive refresh.

## Features

- **JWKS Validation** — Local JWT validation with background key refresh, RSA-only algorithm enforcement
- **Token Introspection** — RFC 7662 remote validation with caching (in-memory or Redis) and JWKS fallback
- **Token Acquisition** — OAuth 2.0 `client_credentials` grant with proactive refresh and thundering-herd prevention
- **Framework Middleware** — Drop-in auth middleware for `net/http`, Gin, and FastHTTP
- **Scope Authorization** — `RequireScope` / `RequireAnyScope` middleware and utility functions
- **OpenTelemetry** — Optional tracing and metrics for validation and introspection
- **Dev Server** — Mock OAuth2 server for local development and testing

## Install

```bash
go get github.com/turnkeystaffing/go-authclient
```

## Quick Start

### Validate tokens with JWKS

```go
validator, err := authclient.NewJWKSValidator(ctx, authclient.JWKSValidatorConfig{
    Issuer: "https://auth.example.com",
    JWKS: authclient.JWKSConfig{
        Endpoint: "https://auth.example.com/.well-known/jwks.json",
    },
}, slog.Default())
if err != nil {
    log.Fatal(err)
}
defer validator.Close()

claims, err := validator.ValidateToken(ctx, bearerToken)
```

### Protect HTTP endpoints

```go
mux := http.NewServeMux()

// Require a valid token
mux.Handle("/api/resource",
    authclient.HTTPBearerAuth(validator)(resourceHandler))

// Require a valid token + specific scope
mux.Handle("/api/admin",
    authclient.HTTPBearerAuth(validator)(
        authclient.HTTPRequireScope("admin")(adminHandler)))
```

### Protect Gin endpoints

```go
r := gin.Default()
r.Use(authclient.GinBearerAuth(validator))

admin := r.Group("/admin")
admin.Use(authclient.GinRequireScope("admin"))
```

### Protect FastHTTP endpoints

```go
handler := authclient.FastHTTPBearerAuth(validator)(protectedHandler)
handler = authclient.FastHTTPRequireScope("read")(handler)
```

### Token introspection with caching and fallback

```go
client := authclient.NewIntrospectionClient(authclient.IntrospectionClientConfig{
    IntrospectionURL:  "https://auth.example.com/token/introspect",
    ClientID:          "my-service",
    ClientSecret:      "secret",
    Cache:             authclient.NewInMemoryCache(1000),
    CacheTTL:          5 * time.Minute,
    FallbackValidator: validator, // fall back to JWKS on network errors
}, slog.Default())
defer client.Close()

// Use as a TokenValidator — same interface as JWKSValidator
claims, err := client.ValidateToken(ctx, token)
```

For distributed caching with Redis:

```go
cache := authclient.NewRedisIntrospectionCache(redisClient)
```

### Acquire tokens for outbound calls

```go
provider, err := authclient.NewOAuthTokenProvider(authclient.OAuthTokenProviderConfig{
    ClientID:     "my-service",
    ClientSecret: "secret",
    TokenURL:     "https://auth.example.com/token",
    Scopes:       "api:read api:write",
}, slog.Default())
if err != nil {
    log.Fatal(err)
}
defer provider.Close()

token, err := provider.Token(ctx)
// token is cached and proactively refreshed at 80% of its lifetime
```

### OpenTelemetry instrumentation

```go
instrumented := authclient.NewInstrumentedValidator(validator,
    authclient.WithTracerProvider(tp),
    authclient.WithMeterProvider(mp),
)
```

Emits:
- `authclient.validate_token.total` counter
- `authclient.validate_token.duration` histogram (ms)
- Trace spans with `client_id`, `scope_count`, and error attributes

### Development with NoopValidator

Skip real auth during local development:

```go
devValidator := authclient.NewNoopValidator(&authclient.Claims{
    ClientID: "dev-client",
    Scopes:   []string{"admin", "read", "write"},
}, slog.Default())

mux.Handle("/api/", authclient.HTTPBearerAuth(devValidator)(handler))
```

Or use noop middleware directly:

```go
mux.Handle("/api/", authclient.HTTPNoopAuth(&authclient.Claims{
    ClientID: "dev",
})(handler))
```

### Dev Server

A mock OAuth2 server for local development that implements token and introspection endpoints.

```go
srv := devserver.New(devserver.Config{
    ClientID:     "dev-client",
    ClientSecret: "dev-secret",
    Users: []devserver.User{
        {Name: "admin", Email: "admin@example.com", Scope: "admin read write"},
        {Name: "viewer", Email: "viewer@example.com", Scope: "read"},
    },
    TokenTTL: time.Hour,
})

http.ListenAndServe(":9090", srv.Handler())
```

Or run the standalone binary:

```bash
go run ./cmd/dev-server
```

Endpoints:
- `POST /token` — OAuth 2.0 token endpoint
- `POST /introspect` — RFC 7662 introspection
- `GET /` — HTML dashboard

## Context & Scope Utilities

```go
// Store/retrieve claims from context
ctx = authclient.ContextWithClaims(ctx, claims)
claims, ok := authclient.ClaimsFromContext(ctx)

// Check scopes
if authclient.HasScope(claims, "admin") { ... }
if authclient.HasAnyScope(claims, "read", "write") { ... }
```

## Core Interfaces

```go
// TokenValidator validates bearer tokens
type TokenValidator interface {
    ValidateToken(ctx context.Context, token string) (*Claims, error)
}

// TokenProvider obtains tokens for outbound requests
type TokenProvider interface {
    Token(ctx context.Context) (string, error)
}

// IntrospectionCache for pluggable cache backends
type IntrospectionCache interface {
    Get(ctx context.Context, key string) (CacheResult, error)
    Set(ctx context.Context, key string, value string, expiration time.Duration) error
    Del(ctx context.Context, keys ...string) (int64, error)
}
```

## Security Notes

- Only RSA signing algorithms accepted (RS256, RS384, RS512); HMAC and `none` are rejected
- Bearer tokens limited to 4096 bytes
- Token values are never logged
- HTTP redirects are rejected on token and introspection endpoints
- `Claims.Email` and `Claims.Username` are **not sanitized** — consumers must sanitize before use in SQL, HTML, or logs
- Non-HTTPS endpoints produce log warnings

## License

See [LICENSE](LICENSE) for details.