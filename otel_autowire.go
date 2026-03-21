package authclient

// InstrumentValidator wraps a TokenValidator with OTel instrumentation if it is
// not nil. Returns nil for nil input. Nil-safe convenience wrapper around
// NewInstrumentedValidator.
//
// Usage in the typical wiring order (cache must be instrumented BEFORE being
// passed to NewIntrospectionClient):
//
//	// 1. Instrument cache first — it goes INTO the client
//	cache := authclient.InstrumentCache(rawCache, opts...)
//
//	// 2. Build client with instrumented cache
//	client := authclient.NewIntrospectionClient(authclient.IntrospectionClientConfig{
//	    Cache: cache,
//	}, logger)
//
//	// 3. Instrument the client (which implements TokenValidator)
//	validator := authclient.InstrumentValidator(client, opts...)
//
//	// 4. Token provider is independent — instrument anytime
//	provider := authclient.InstrumentTokenProvider(oauthProvider, opts...)
func InstrumentValidator(v TokenValidator, opts ...InstrumentationOption) TokenValidator {
	if v == nil {
		return nil
	}
	return NewInstrumentedValidator(v, opts...)
}

// InstrumentCache wraps an IntrospectionCache with OTel instrumentation if it is
// not nil. Returns nil for nil input. Nil-safe convenience wrapper around
// NewInstrumentedCache.
//
// IMPORTANT: The instrumented cache must be passed to NewIntrospectionClient's
// config.Cache field. Instrumenting the cache AFTER the client is constructed
// has no effect — the client already holds a reference to the unwrapped cache.
func InstrumentCache(c IntrospectionCache, opts ...InstrumentationOption) IntrospectionCache {
	if c == nil {
		return nil
	}
	return NewInstrumentedCache(c, opts...)
}

// InstrumentTokenProvider wraps a TokenProvider with OTel instrumentation if it is
// not nil. Returns nil for nil input. Nil-safe convenience wrapper around
// NewInstrumentedTokenProvider.
//
// TokenProvider is independent of other components and can be instrumented at any point.
func InstrumentTokenProvider(p TokenProvider, opts ...InstrumentationOption) TokenProvider {
	if p == nil {
		return nil
	}
	return NewInstrumentedTokenProvider(p, opts...)
}
