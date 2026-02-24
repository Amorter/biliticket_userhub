package repository

import (
	"context"
	"time"
)

// StateStore abstracts ephemeral key-value state.
// Implementations: Redis (production) or in-memory (local dev / FC single-instance).
type StateStore interface {
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
}
