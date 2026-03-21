# go-authclient

A framework-agnostic Go library for OAuth 2.0 token validation, introspection, and acquisition. Supports local JWT validation via JWKS, remote token introspection (RFC 7662), and client_credentials token acquisition with proactive refresh.

## Features

- **JWKS Validation** — Local JWT validation with background key refresh, RSA-only algorithm enforcement
- **Token Introspection** — RFC 7662 remote validation with caching (in-memory or Redis) and JWKS fallback
- **Token Acquisition** — OAuth 2.0 `client_credentials` grant with proactive refresh and thundering-herd prevention
- **Framework Middleware** — Drop-in auth middleware for `net/http`, Gin, and FastHTTP
- **Scope Authorization** — `RequireScope` / `RequireAnyScope` middleware and utility functions
- **OpenTelemetry** — Optional tracing and metrics for validation and introspection
- **Scope Discovery** — Declare service scopes and templates via `ScopeManifest`; serve them as JSON for auth service sync
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

All components support opt-in OTel tracing and metrics via decorator wrappers. If your service
uses [go-opentelemetry](https://github.com/turnkeystaffing/go-opentelemetry) with global providers, no options are
needed — just wrap and go.

#### JWKS-only (no cache)

```go
validator := authclient.InstrumentValidator(jwksValidator)
provider := authclient.InstrumentTokenProvider(oauthProvider)
```

#### Introspection with cache (wiring order matters)

The cache is captured by reference inside `IntrospectionClient` at construction time. It **must be instrumented before**
being passed to the constructor — instrumenting after has no effect.

```go
// 1. Cache FIRST — it goes INTO the client
cache := authclient.InstrumentCache(fallbackCache)

// 2. Build client with the instrumented cache
client := authclient.NewIntrospectionClient(authclient.IntrospectionClientConfig{
Cache: cache,
// ...
}, logger)

// 3. Wrap the client itself
validator := authclient.InstrumentValidator(client)

// 4. Token provider is independent — any order
provider := authclient.InstrumentTokenProvider(oauthProvider)
```

#### Explicit providers (tests or non-global setup)

```go
opts := []authclient.InstrumentationOption{
    authclient.WithTracerProvider(tp),
    authclient.WithMeterProvider(mp),
}
cache := authclient.InstrumentCache(fallbackCache, opts...)
validator := authclient.InstrumentValidator(client, opts...)
provider := authclient.InstrumentTokenProvider(oauthProvider, opts...)
```

#### Instrumented middleware

Drop-in replacements for the standard middleware that add request counters with rejection reasons:

```go
// net/http
mux.Handle("/api/", authclient.InstrumentedHTTPBearerAuth(validator, otelOpts)(handler))

// Gin
r.Use(authclient.InstrumentedGinBearerAuth(validator, otelOpts))
r.Use(authclient.InstrumentedGinRequireScope("read", otelOpts))

// FastHTTP
handler = authclient.InstrumentedFastHTTPBearerAuth(validator, otelOpts)(handler)
```

#### Discovery handler

```go
handler := authclient.NewInstrumentedDiscoveryHandler(discoveryHandler)
```

#### Metrics emitted

| Metric                                | Type           | Attributes                      |
|---------------------------------------|----------------|---------------------------------|
| `authclient.validate_token.total`     | Counter        | `result`                        |
| `authclient.validate_token.duration`  | Histogram (ms) | `result`                        |
| `authclient.cache.ops.total`          | Counter        | `operation`, `result`           |
| `authclient.cache.ops.duration`       | Histogram (ms) | `operation`, `result`           |
| `authclient.token_provider.total`     | Counter        | `result`                        |
| `authclient.token_provider.duration`  | Histogram (ms) | `result`                        |
| `authclient.middleware.auth.total`    | Counter        | `result`, `reason`, `framework` |
| `authclient.middleware.scope.total`   | Counter        | `result`, `scope`, `framework`  |
| `authclient.discovery.requests.total` | Counter        | `method`, `status`              |
| `authclient.discovery.reload.total`   | Counter        | `result`                        |

Trace spans are created for validation (`authclient.validate_token`), introspection (`authclient.introspect`), cache
operations (`authclient.cache.get/set/del`), and token acquisition (`authclient.token_provider.get_token`). Token values
are never recorded in spans or metrics.

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

A mock OAuth2 server for local development. Issues RS256 JWTs with the same claims as the real auth service, so both
`JWKSValidator` and `IntrospectionClient` work against it.

At startup, generates an ephemeral 2048-bit RSA key pair (key ID `devserver-1`). The private key signs tokens; the
public key is served via the JWKS endpoint.

#### Endpoints

| Route                                         | Description                                                        |
|-----------------------------------------------|--------------------------------------------------------------------|
| `POST /token`                                 | Issue a JWT via `client_credentials` or `password` grant           |
| `POST /introspect`                            | RFC 7662 token introspection (looks up token from in-memory store) |
| `GET /.well-known/jwks.json`                  | JWKS public key set (single RSA key, `kid: "devserver-1"`)         |
| `GET /.well-known/oauth-authorization-server` | OAuth2 discovery metadata (RFC 8414)                               |
| `POST /api/v1/oauth/token`                    | Alias for `/token`                                                 |
| `POST /api/v1/oauth/introspect`               | Alias for `/introspect`                                            |
| `GET /`                                       | HTML dashboard                                                     |

Both `/token` and `/introspect` require HTTP Basic Auth using the configured `ClientID` / `ClientSecret`.

#### Token request parameters

`POST /token` accepts these form parameters:

| Parameter    | Required             | Description                                                                                                                                                                                                                         |
|--------------|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `grant_type` | yes                  | `client_credentials` or `password`                                                                                                                                                                                                  |
| `scope`      | no                   | For `client_credentials`: match a user by scope                                                                                                                                                                                     |
| `username`   | for `password` grant | Select user by name                                                                                                                                                                                                                 |
| `audience`   | no                   | Devserver-only. Sets the `aud` claim and selects the service user set (see [per-service user sets](#per-service-user-sets)). In the real auth service, `aud` is set server-side from client registration — not a request parameter. |

#### Token response

```json
{
  "access_token": "<RS256 JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "admin openid profile email"
}
```

#### JWT claims

The issued JWT contains these claims (matching `authclient.Claims`):

| Claim       | Source                                   | Example                   |
|-------------|------------------------------------------|---------------------------|
| `iss`       | `Config.Issuer` (default `"devserver"`)  | `"http://localhost:9091"` |
| `sub`       | `"dev-"` + user name                     | `"dev-admin"`             |
| `aud`       | `audience` form param (omitted if empty) | `"d290f1ee-..."`          |
| `exp`       | now + `TokenTTL`                         | `1711036800`              |
| `iat`       | now                                      | `1711033200`              |
| `client_id` | `Config.ClientID`                        | `"dev"`                   |
| `scopes`    | user scope split by spaces               | `["admin", "openid"]`     |
| `user_id`   | `"dev-"` + user name                     | `"dev-admin"`             |
| `email`     | user email                               | `"admin@dev.local"`       |
| `username`  | user email                               | `"admin@dev.local"`       |
| `gty`       | grant type                               | `"client_credentials"`    |
| `auth_time` | now (unix)                               | `1711033200`              |

#### Introspection response

`POST /introspect` with `token=<jwt>` returns:

```json
{
  "active": true,
  "sub": "dev-admin",
  "scope": "admin openid profile email",
  "email": "admin@dev.local",
  "username": "admin@dev.local",
  "client_id": "dev",
  "token_type": "Bearer",
  "exp": 1711036800,
  "iat": 1711033200
}
```

Introspection looks up the token from an in-memory map (no JWT parsing) — expired or unknown tokens return
`{"active": false}`.

#### Discovery

`GET /.well-known/oauth-authorization-server` returns RFC 8414 metadata. All URLs are built from the configured`Issuer`:

```json
{
  "issuer": "http://localhost:9091",
  "token_endpoint": "http://localhost:9091/token",
  "introspection_endpoint": "http://localhost:9091/introspect",
  "jwks_uri": "http://localhost:9091/.well-known/jwks.json",
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

#### Usage as a library

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

To validate tokens with `JWKSValidator`, the JWT must have an `aud` claim matching `JWKSValidatorConfig.Audience`. Pass
the `audience` form parameter when requesting the token:

```go
// JWKSValidator configured to expect a specific audience
validator, _ := authclient.NewJWKSValidator(ctx, authclient.JWKSValidatorConfig{
Issuer:   "http://localhost:9090",
Audience: []string{"d290f1ee-6c54-4b01-90e6-d701748f0851"},
JWKS: authclient.JWKSConfig{
Endpoint: "http://localhost:9090/.well-known/jwks.json",
},
}, slog.Default())
```

```bash
# Token must include audience to pass JWKSValidator
curl -s -X POST http://localhost:9090/token \
  -u dev-client:dev-secret \
  -d "grant_type=client_credentials&audience=d290f1ee-6c54-4b01-90e6-d701748f0851"
```

#### Per-service user sets

Use `Services` to give each audience its own set of users. In the real auth service, the `aud` claim is set server-side
from the client registration. The devserver simulates this with the `audience` form parameter, which both sets the JWT
`aud` claim and selects which service's users to resolve against.

```go
srv := devserver.New(devserver.Config{
ClientID:     "dev-client",
ClientSecret: "dev-secret",
Issuer:       "http://localhost:9090",
Services: []devserver.ServiceConfig{
{
Audience: "d290f1ee-6c54-4b01-90e6-d701748f0851",
Users: []devserver.User{
{Name: "admin", Email: "admin@dev.local", Scope: "bgcheck:admin"},
{Name: "viewer", Email: "viewer@dev.local", Scope: "bgcheck:read"},
},
},
{
Audience: "7c9e6679-7425-40de-944b-e07fc1f90ae7",
Users: []devserver.User{
{Name: "svc", Email: "svc@dev.local", Scope: "users:read users:write"},
},
},
},
})
```

When `Services` is configured, a token request must include a matching `audience` — users from one service are not
visible to another. When only `Users` is set (no `Services`), those users serve all audiences.

#### Standalone binary

```bash
go run ./cmd/dev-server
```

| Variable                 | Default                                              | Description                                                           |
|--------------------------|------------------------------------------------------|-----------------------------------------------------------------------|
| `DEV_AUTH_PORT`          | `9091`                                               | Listen port                                                           |
| `DEV_AUTH_CLIENT_ID`     | `dev`                                                | Basic Auth client ID                                                  |
| `DEV_AUTH_CLIENT_SECRET` | `dev`                                                | Basic Auth client secret                                              |
| `DEV_AUTH_ISSUER`        | `http://localhost:<port>`                            | JWT `iss` claim. Discovery URLs are built from this.                  |
| `DEV_AUTH_USERS`         | `admin\|admin@dev.local\|admin openid profile email` | Global user definitions                                               |
| `DEV_AUTH_SERVICES`      | _(empty)_                                            | Per-audience user definitions. When set, `DEV_AUTH_USERS` is ignored. |

#### `DEV_AUTH_USERS` format

Each user is `name|email|scopes`. Multiple users separated by `;`.

| Field    | What it becomes                                                                   | Example                      |
|----------|-----------------------------------------------------------------------------------|------------------------------|
| `name`   | JWT `sub` = `"dev-<name>"`. Also the `username` param for password grant.         | `admin`                      |
| `email`  | JWT `email` and `username` claims, introspection `email`                          | `admin@dev.local`            |
| `scopes` | Space-delimited. JWT `scopes` claim (as array), introspection `scope` (as string) | `admin openid profile email` |

```bash
DEV_AUTH_USERS="admin|admin@dev.local|admin openid profile email;viewer|viewer@dev.local|read"
```

#### `DEV_AUTH_SERVICES` format

Each service block: `<audience>:<user>,<user>`. Service blocks separated by `;`. The audience is the service UUID — the
same value you configure in `JWKSValidatorConfig.Audience`.

| Separator | Separates                                    |
|-----------|----------------------------------------------|
| `;`       | Service blocks                               |
| `:`       | Audience from its users                      |
| `,`       | Users within a service                       |
| `\|`      | Fields within a user (`name\|email\|scopes`) |

```bash
DEV_AUTH_SERVICES="d290f1ee-6c54-4b01-90e6-d701748f0851:admin|admin@dev.local|bgcheck:admin,viewer|viewer@dev.local|bgcheck:read;7c9e6679-7425-40de-944b-e07fc1f90ae7:svc|svc@dev.local|users:read users:write"
```

| Audience UUID                          | Users                                            |
|----------------------------------------|--------------------------------------------------|
| `d290f1ee-6c54-4b01-90e6-d701748f0851` | `admin` (bgcheck:admin), `viewer` (bgcheck:read) |
| `7c9e6679-7425-40de-944b-e07fc1f90ae7` | `svc` (users:read users:write)                   |

#### Getting a token

```bash
# client_credentials — returns first matching user
curl -s -X POST http://localhost:9091/token \
  -u dev:dev \
  -d "grant_type=client_credentials"

# client_credentials with audience — required when using Services or JWKSValidator
curl -s -X POST http://localhost:9091/token \
  -u dev:dev \
  -d "grant_type=client_credentials&audience=d290f1ee-6c54-4b01-90e6-d701748f0851"

# password grant — select user by name
curl -s -X POST http://localhost:9091/token \
  -u dev:dev \
  -d "grant_type=password&username=admin"
```

### Scope Discovery

Services declare their scopes and templates in a `ScopeManifest`, which the auth service syncs to manage permissions. The manifest can be defined in code or loaded from a YAML/JSON file, then served as a JSON endpoint via `DiscoveryHandler`.

#### Manifest format

```yaml
# scopes.yaml
service_code: bgc
scopes:
  - name: bgc:contractors:read
    description: Read contractors
  - name: bgc:contractors:write
    description: Write contractors
templates:
  - name: viewer
    description: Read-only access
    scopes:
      - bgc:contractors:read
  - name: admin
    scopes:
      - bgc:contractors:read
      - bgc:contractors:write
    replaces: old_admin  # supersedes an external template in the auth service
```

Scope names must match the pattern `service_code:resource:action` (2-3 colon-separated lowercase segments). The first segment must equal the `service_code`.

#### Serve from a file

```go
handler, err := authclient.NewDiscoveryHandlerFromFile("scopes.yaml")
if err != nil {
    log.Fatal(err)
}
defer handler.Close()

mux.Handle("GET /scopes/discovery", authclient.HTTPBearerAuth(validator)(handler))
```

The manifest is loaded, validated, and pre-serialized to JSON once. Subsequent requests serve the cached bytes with no per-request marshaling.

#### Serve from code

```go
manifest := &authclient.ScopeManifest{
    ServiceCode: "bgc",
    Scopes: []authclient.ScopeDefinition{
        {Name: "bgc:contractors:read", Description: "Read contractors"},
        {Name: "bgc:contractors:write", Description: "Write contractors"},
    },
    Templates: []authclient.TemplateDefinition{
        {Name: "viewer", Scopes: []string{"bgc:contractors:read"}},
    },
}
handler := authclient.NewDiscoveryHandler(manifest)
```

#### Hot reload

File-based handlers support reloading the manifest without restart:

```go
// Manual reload
err := handler.Reload()

// Automatic reload on SIGHUP
handler, err := authclient.NewDiscoveryHandlerFromFile("scopes.yaml", authclient.WithReloadOnSignal())
```

If reload fails (invalid file, parse error), the previous manifest is preserved.

#### Framework support

`DiscoveryHandler` implements `http.Handler` and also provides:

- `handler.GinHandler()` — returns `gin.HandlerFunc`
- `handler.FastHTTPHandler()` — returns `fasthttp.RequestHandler`

All handlers enforce GET-only access (405 for other methods) and set `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.

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