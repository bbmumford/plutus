/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"sync"
	"time"
)

// balanceCacheKey is the lookup key for cached balance results.
type balanceCacheKey struct {
	chainID string
	address string
	token   string
}

// balanceCacheEntry holds a cached BalanceResult and its expiry time.
type balanceCacheEntry struct {
	result   *BalanceResult
	expiresAt time.Time
}

// balanceCache is a thread-safe TTL cache keyed by (chainID, address, token).
// Default TTL is 30s per the witness-balance design spec. Callers can override
// via NewBalanceCache(ttl). The cache avoids hammering the mesh for frequently
// polled addresses (e.g., a wallet UI refreshing on a 30s interval).
//
// Invalidation is TTL-only: balances are eventually consistent in v1. A future
// phase may add push-based invalidation on BalanceSubscribe.
type balanceCache struct {
	ttl time.Duration

	mu      sync.Mutex
	entries map[balanceCacheKey]balanceCacheEntry
}

// newBalanceCache constructs a cache with the given TTL. A zero or negative
// TTL falls back to the 30s default.
func newBalanceCache(ttl time.Duration) *balanceCache {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &balanceCache{
		ttl:     ttl,
		entries: make(map[balanceCacheKey]balanceCacheEntry),
	}
}

// Get returns a non-expired cached result for (chainID, address, token), or
// nil if no valid entry exists. Expired entries are removed on access.
func (c *balanceCache) Get(chainID, address, token string) *BalanceResult {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := balanceCacheKey{chainID: chainID, address: address, token: token}
	entry, ok := c.entries[key]
	if !ok {
		return nil
	}
	if time.Now().After(entry.expiresAt) {
		delete(c.entries, key)
		return nil
	}
	return entry.result
}

// Put stores a BalanceResult with the cache's configured TTL.
func (c *balanceCache) Put(chainID, address, token string, result *BalanceResult) {
	if result == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[balanceCacheKey{chainID: chainID, address: address, token: token}] = balanceCacheEntry{
		result:    result,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Purge removes expired entries. Optional — Get already lazily purges — but
// callers with long-running processes may want to call this periodically to
// reclaim memory from addresses no longer being queried.
func (c *balanceCache) Purge() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	removed := 0
	for k, v := range c.entries {
		if now.After(v.expiresAt) {
			delete(c.entries, k)
			removed++
		}
	}
	return removed
}

// Size returns the current number of cached entries (including expired ones
// that haven't been purged yet). Useful for tests.
func (c *balanceCache) Size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}
