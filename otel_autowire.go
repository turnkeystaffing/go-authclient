package authclient

// # Instrumentation Wiring Order
//
// Components have dependencies that dictate the order they must be instrumented.
// The cache is captured by reference inside IntrospectionClient at construction
// time, so it must be instrumented BEFORE being passed to the constructor.
//
// Dependency graph:
//
//	InstrumentCache(cache)
//	        │
//	        ▼  pass as config.Cache
//	NewIntrospectionClient(cfg)
//	        │
//	        ▼  wraps the client
//	InstrumentValidator(client)
//
//	InstrumentTokenProvider(provider)   ← independent, any order
//
// JWKS-only (no cache, no introspection):
//
//	validator := authclient.InstrumentValidator(jwksValidator, opts...)
//	provider  := authclient.InstrumentTokenProvider(oauthProvider, opts...)
//
// Introspection with cache:
//
//	opts := []authclient.InstrumentationOption{
//	    authclient.WithTracerProvider(tp),
//	    authclient.WithMeterProvider(mp),
//	}
//
//	// 1. Cache FIRST — it is captured inside the client
//	cache := authclient.InstrumentCache(fallbackCache, opts...)
//
//	// 2. Build client with the instrumented cache
//	client := authclient.NewIntrospectionClient(authclient.IntrospectionClientConfig{
//	    Cache: cache,
//	    // ...
//	}, logger)
//
//	// 3. Wrap the client itself
//	validator := authclient.InstrumentValidator(client, opts...)
//
//	// 4. Token provider is independent
//	provider := authclient.InstrumentTokenProvider(oauthProvider, opts...)
//
// If no InstrumentationOption is passed, global OTel providers are used
// (whatever was registered via otel.SetTracerProvider / otel.SetMeterProvider).
// Services using go-opentelemetry's InitializeProvider set these globals
// automatically, so no options are needed:
//
//	cache     := authclient.InstrumentCache(fallbackCache)
//	validator := authclient.InstrumentValidator(client)
//	provider  := authclient.InstrumentTokenProvider(oauthProvider)

// InstrumentValidator wraps a TokenValidator with OTel instrumentation.
// Returns nil for nil input. See wiring order above.
func InstrumentValidator(v TokenValidator, opts ...InstrumentationOption) TokenValidator {
	if v == nil {
		return nil
	}
	return NewInstrumentedValidator(v, opts...)
}

// InstrumentCache wraps an IntrospectionCache with OTel instrumentation.
// Returns nil for nil input.
//
// IMPORTANT: Must be called BEFORE NewIntrospectionClient. The client captures
// the cache reference at construction time — instrumenting after has no effect.
func InstrumentCache(c IntrospectionCache, opts ...InstrumentationOption) IntrospectionCache {
	if c == nil {
		return nil
	}
	return NewInstrumentedCache(c, opts...)
}

// InstrumentTokenProvider wraps a TokenProvider with OTel instrumentation.
// Returns nil for nil input. Independent of other components — can be called
// at any point in the wiring sequence.
func InstrumentTokenProvider(p TokenProvider, opts ...InstrumentationOption) TokenProvider {
	if p == nil {
		return nil
	}
	return NewInstrumentedTokenProvider(p, opts...)
}
