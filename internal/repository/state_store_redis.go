package repository

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type redisStateStore struct {
	client *redis.Client
}

func NewRedisStateStore(client *redis.Client) StateStore {
	return &redisStateStore{client: client}
}

func (s *redisStateStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.client.Set(ctx, key, value, ttl).Err()
}

func (s *redisStateStore) Get(ctx context.Context, key string) ([]byte, error) {
	val, err := s.client.Get(ctx, key).Bytes()
	if err == redis.Nil {
		return nil, nil
	}
	return val, err
}

func (s *redisStateStore) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, key).Err()
}

func (s *redisStateStore) Exists(ctx context.Context, key string) (bool, error) {
	n, err := s.client.Exists(ctx, key).Result()
	return n > 0, err
}
