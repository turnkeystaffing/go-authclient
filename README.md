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
    Issuer:   "https://auth.example.com",
    Audience: []string{"my-service"},
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

A mock OAuth2 server for local development that issues real RS256 JWTs and exposes JWKS, introspection, and discovery
endpoints — a drop-in replacement for the real auth service.

```go
srv := devserver.New(devserver.Config{
    ClientID:     "dev-client",
    ClientSecret: "dev-secret",
	Issuer:       "http://localhost:9090",
    Users: []devserver.User{
        {Name: "admin", Email: "admin@example.com", Scope: "admin read write"},
        {Name: "viewer", Email: "viewer@example.com", Scope: "read"},
    },
    TokenTTL: time.Hour,
})

http.ListenAndServe(":9090", srv.Handler())
```

Tokens are RS256 JWTs signed with an ephemeral key pair generated at startup. They contain the same claims as the real
auth service (`client_id`, `scopes`, `user_id`, `email`, `username`, `gty`, `auth_time`), so `JWKSValidator` can
validate them via the JWKS endpoint.

#### Per-service user sets

Configure different users for different audiences:

```go
srv := devserver.New(devserver.Config{
ClientID:     "dev-client",
ClientSecret: "dev-secret",
Issuer:       "http://localhost:9090",
Services: []devserver.ServiceConfig{
{
Audience: "api-a",
Users:    []devserver.User{{Name: "alice", Email: "alice@a.local", Scope: "a:admin"}},
},
{
Audience: "api-b",
Users:    []devserver.User{{Name: "bob", Email: "bob@b.local", Scope: "b:read"}},
},
},
})
```

Pass `audience` as a form parameter when requesting a token:

```bash
curl -s -X POST http://localhost:9090/token \
  -u dev-client:dev-secret \
  -d "grant_type=client_credentials&audience=api-a"
```

When `Services` is configured, user resolution is scoped to the matching audience. When only `Users` is set, those users
serve all audiences (backward compatible).

#### Endpoints

| Route                                         | Description                                              |
|-----------------------------------------------|----------------------------------------------------------|
| `POST /token`                                 | OAuth 2.0 token endpoint (client_credentials, password)  |
| `POST /introspect`                            | RFC 7662 token introspection                             |
| `GET /.well-known/jwks.json`                  | JWKS public key set                                      |
| `GET /.well-known/oauth-authorization-server` | Discovery metadata (issuer, endpoints, supported grants) |
| `POST /api/v1/oauth/token`                    | Alias for `/token`                                       |
| `POST /api/v1/oauth/introspect`               | Alias for `/introspect`                                  |
| `GET /`                                       | HTML dashboard                                           |

#### Discovery

The `/.well-known/oauth-authorization-server` endpoint returns RFC 8414 metadata:

```json
{
  "issuer": "http://localhost:9090",
  "token_endpoint": "http://localhost:9090/token",
  "introspection_endpoint": "http://localhost:9090/introspect",
  "jwks_uri": "http://localhost:9090/.well-known/jwks.json",
  "grant_types_supported": [
    "client_credentials",
    "password"
  ],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic"
  ],
  "introspection_endpoint_auth_methods_supported": [
    "client_secret_basic"
  ]
}
```

#### JWKS validation round-trip

Point `JWKSValidator` at the dev server's JWKS endpoint for local JWT validation:

```go
validator, _ := authclient.NewJWKSValidator(ctx, authclient.JWKSValidatorConfig{
Issuer:   "http://localhost:9090",
Audience: []string{"my-service"},
JWKS: authclient.JWKSConfig{
Endpoint: "http://localhost:9090/.well-known/jwks.json",
},
}, slog.Default())
```

#### Standalone binary

```bash
go run ./cmd/dev-server
```

Environment variables:

| Variable                 | Default                                              | Description                                      |
|--------------------------|------------------------------------------------------|--------------------------------------------------|
| `DEV_AUTH_PORT`          | `9091`                                               | Listen port                                      |
| `DEV_AUTH_CLIENT_ID`     | `dev`                                                | Basic Auth client ID                             |
| `DEV_AUTH_CLIENT_SECRET` | `dev`                                                | Basic Auth client secret                         |
| `DEV_AUTH_USERS`         | `admin\|admin@dev.local\|admin openid profile email` | User definitions (see format below)              |
| `DEV_AUTH_ISSUER`        | `http://localhost:<port>`                            | JWT issuer claim                                 |
| `DEV_AUTH_SERVICES`      | _(empty)_                                            | Per-audience user definitions (see format below) |

**`DEV_AUTH_USERS`** defines the users available for token issuance. Use this when you have a single service or don't
need audience-scoped users. Each user has three fields separated by `|` (pipe). Multiple users are separated by `;` (
semicolon).

```
<name>|<email>|<scopes>
```

| Field    | Description                                                                                                                | Example                      |
|----------|----------------------------------------------------------------------------------------------------------------------------|------------------------------|
| `name`   | Unique identifier. Becomes `sub: "dev-<name>"` in the JWT. Also used as the `username` parameter for the `password` grant. | `admin`                      |
| `email`  | Populates the `email` claim in the JWT and introspection response.                                                         | `admin@dev.local`            |
| `scopes` | Space-delimited OAuth2 scopes assigned to this user.                                                                       | `admin openid profile email` |

Single user:

```bash
DEV_AUTH_USERS="admin|admin@dev.local|admin openid profile email"
```

Multiple users — separate with `;`:

```bash
DEV_AUTH_USERS="admin|admin@dev.local|admin openid profile email;viewer|viewer@dev.local|read"
```

When `DEV_AUTH_SERVICES` is set, `DEV_AUTH_USERS` is ignored.

---

**`DEV_AUTH_SERVICES`** defines per-audience user sets. Use this when you run multiple services locally and each service
needs its own users.

In the real auth service, the `aud` claim is set server-side based on the client registration — it is not part of the
token request. The devserver simulates this with a devserver-specific `audience` form parameter on `/token` that selects
which service's users to resolve and sets the JWT `aud` claim. Use the service UUID from the auth service dashboard —
the same value you configure in `JWKSValidatorConfig.Audience`.

Format — each service block is `<audience>:<users>`, separated by `;`. Users within a service are separated by `,`:

```
<audience>:<user>,<user> ; <audience>:<user>,<user>
           │                          │
           └─ name|email|scopes       └─ name|email|scopes
```

| Separator | Separates                                    |
|-----------|----------------------------------------------|
| `;`       | Service blocks                               |
| `:`       | Audience from its users                      |
| `,`       | Users within a service                       |
| `\|`      | Fields within a user (`name\|email\|scopes`) |

Example — two services, each keyed by its service UUID:

```bash
# Copy these UUIDs from the auth service dashboard for each service
BGCHECK_AUD="d290f1ee-6c54-4b01-90e6-d701748f0851"
USERAPI_AUD="7c9e6679-7425-40de-944b-e07fc1f90ae7"

DEV_AUTH_SERVICES="${BGCHECK_AUD}:admin|admin@dev.local|bgcheck:admin,viewer|viewer@dev.local|bgcheck:read;${USERAPI_AUD}:svc|svc@dev.local|users:read users:write"
```

Broken down:

| Service  | Audience (UUID)    | Users                                            |
|----------|--------------------|--------------------------------------------------|
| bgcheck  | `d290f1ee-...0851` | `admin` (bgcheck:admin), `viewer` (bgcheck:read) |
| user-api | `7c9e6679-...0ae7` | `svc` (users:read users:write)                   |

Request a token for a specific service using the devserver-specific `audience` parameter (not part of the real auth
service API):

```bash
curl -s -X POST http://localhost:9091/token \
  -u dev:dev \
  -d "grant_type=client_credentials&audience=d290f1ee-6c54-4b01-90e6-d701748f0851"
```

The issued JWT will have `"aud": "d290f1ee-6c54-4b01-90e6-d701748f0851"`, matching what `JWKSValidator` expects. Users
from one service are not visible to another.

### Step-up authentication (sensitive operations)

Use `AuthenticatedWithin` to require recent credential proof before sensitive operations. This checks the `auth_time` claim — distinct from token expiry.

```go
claims, _ := authclient.ClaimsFromContext(r.Context())

// Use the auth server default (15 minutes)
if !claims.AuthenticatedWithin(0) {
    http.Error(w, "recent authentication required", http.StatusForbidden)
    return
}

// Or specify a tighter window for extra-sensitive operations
if !claims.AuthenticatedWithin(5 * time.Minute) {
    http.Error(w, "recent authentication required", http.StatusForbidden)
    return
}
```

With Gin:

```go
func handleDeleteAccount(c *gin.Context) {
    claims, _ := authclient.ClaimsFromContext(c.Request.Context())
    if !claims.AuthenticatedWithin(0) {
        c.JSON(http.StatusForbidden, gin.H{"error": "recent authentication required"})
        return
    }
    // proceed with sensitive operation
}
```

`AuthenticatedWithin` returns `false` when `auth_time` is absent (e.g., client_credentials tokens), so only user tokens with recent credential proof pass the check. The default of `authclient.DefaultReauthMaxAge` (15 minutes) matches the auth server's `reauth_max_age` setting.

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