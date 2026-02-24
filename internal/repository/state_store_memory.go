package repository

import (
	"context"
	"sync"
	"time"
)

type memEntry struct {
	value     []byte
	expiresAt time.Time
	hasTTL    bool
}

func (e memEntry) isExpired() bool {
	return e.hasTTL && time.Now().After(e.expiresAt)
}

type memoryStateStore struct {
	mu      sync.RWMutex
	entries map[string]memEntry
}

func NewMemoryStateStore() StateStore {
	return &memoryStateStore{
		entries: make(map[string]memEntry),
	}
}

func (s *memoryStateStore) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := memEntry{value: value}
	if ttl > 0 {
		entry.hasTTL = true
		entry.expiresAt = time.Now().Add(ttl)
	}
	s.entries[key] = entry
	return nil
}

func (s *memoryStateStore) Get(_ context.Context, key string) ([]byte, error) {
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok || entry.isExpired() {
		if ok && entry.isExpired() {
			s.mu.Lock()
			delete(s.entries, key)
			s.mu.Unlock()
		}
		return nil, nil
	}
	return entry.value, nil
}

func (s *memoryStateStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, key)
	return nil
}

func (s *memoryStateStore) Exists(_ context.Context, key string) (bool, error) {
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()

	if !ok || entry.isExpired() {
		if ok && entry.isExpired() {
			s.mu.Lock()
			delete(s.entries, key)
			s.mu.Unlock()
		}
		return false, nil
	}
	return true, nil
}
