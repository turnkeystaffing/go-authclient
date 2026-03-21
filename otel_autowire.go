package authclient

// InstrumentAll wraps a TokenValidator, IntrospectionCache, and TokenProvider
// with OTel instrumentation in a single call. Nil arguments are skipped.
//
// This is the recommended way to add observability to an authclient stack.
// Each non-nil component is wrapped with its corresponding instrumented decorator
// using the shared InstrumentationOption set.
//
// Usage:
//
//	validator, cache, tokenProvider := authclient.InstrumentAll(
//	    jwksValidator,
//	    fallbackCache,
//	    oauthProvider,
//	    authclient.WithTracerProvider(tp),
//	    authclient.WithMeterProvider(mp),
//	)
//
// Returns the (possibly wrapped) components. If a component is nil, the
// corresponding return value is nil. If no InstrumentationOptions are provided,
// global OTel providers are used (via otel.GetTracerProvider/otel.GetMeterProvider).
//
// Do not pass already-instrumented components — this will produce duplicate spans and metrics.
func InstrumentAll(
	validator TokenValidator,
	cache IntrospectionCache,
	tokenProvider TokenProvider,
	opts ...InstrumentationOption,
) (TokenValidator, IntrospectionCache, TokenProvider) {
	var iv TokenValidator
	var ic IntrospectionCache
	var itp TokenProvider

	if validator != nil {
		iv = NewInstrumentedValidator(validator, opts...)
	}
	if cache != nil {
		ic = NewInstrumentedCache(cache, opts...)
	}
	if tokenProvider != nil {
		itp = NewInstrumentedTokenProvider(tokenProvider, opts...)
	}

	return iv, ic, itp
}

// InstrumentValidator wraps a TokenValidator with OTel instrumentation if it is
// not nil. Returns nil for nil input. Convenience wrapper around NewInstrumentedValidator
// that is nil-safe.
func InstrumentValidator(v TokenValidator, opts ...InstrumentationOption) TokenValidator {
	if v == nil {
		return nil
	}
	return NewInstrumentedValidator(v, opts...)
}

// InstrumentCache wraps an IntrospectionCache with OTel instrumentation if it is
// not nil. Returns nil for nil input. Convenience wrapper around NewInstrumentedCache
// that is nil-safe.
func InstrumentCache(c IntrospectionCache, opts ...InstrumentationOption) IntrospectionCache {
	if c == nil {
		return nil
	}
	return NewInstrumentedCache(c, opts...)
}

// InstrumentTokenProvider wraps a TokenProvider with OTel instrumentation if it is
// not nil. Returns nil for nil input. Convenience wrapper around NewInstrumentedTokenProvider
// that is nil-safe.
func InstrumentTokenProvider(p TokenProvider, opts ...InstrumentationOption) TokenProvider {
	if p == nil {
		return nil
	}
	return NewInstrumentedTokenProvider(p, opts...)
}
