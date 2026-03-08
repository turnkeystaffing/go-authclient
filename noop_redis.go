package authclient

import (
	"context"
	"time"
)

// noopIntrospectionCache implements IntrospectionCache with no-op behavior.
// Used internally when no cache is configured — eliminates nil checks in hot path.
type noopIntrospectionCache struct{}

var _ IntrospectionCache = (*noopIntrospectionCache)(nil)

func (noopIntrospectionCache) Get(context.Context, string) (CacheResult, error) {
	return CacheResult{}, nil
}

func (noopIntrospectionCache) Set(context.Context, string, string, time.Duration) error {
	return nil
}

func (noopIntrospectionCache) Del(context.Context, ...string) (int64, error) {
	return 0, nil
}
