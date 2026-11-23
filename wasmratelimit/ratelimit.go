/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

// Package wasmratelimit implements a per-method token bucket rate limiter
// used by the Plutus and Mercury WASM bridges to defend against a rogue or
// compromised JS page hammering sensitive exports (sendFunds, sendMessage,
// submitReview, etc).
//
// The limiter is self-contained (no dependency on golang.org/x/time/rate) so
// the js/wasm binary stays small and the code path is trivially auditable.
// Algorithm: fractional token bucket with tokens-per-minute refill and a
// burst cap. Each WASM bridge instance owns its own limiter to avoid
// cross-contamination. Limits are per-call-site within the bridge, not
// per-peer — the threat model is rogue JS on the page, not rogue peers.
package wasmratelimit

import (
	"fmt"
	"sync"
	"time"
)

// Category classifies a bridge method into a default-limit bucket.
type Category int

const (
	// CategoryDestructive covers broadcast / value-moving methods:
	// sendFunds, createOrder, completeOrder, disputeOrder, submitReview,
	// registerPasskey. Default: 10/min, burst 3.
	CategoryDestructive Category = iota

	// CategoryStateMutation covers non-broadcast writes:
	// addListing, removeListing, updateProfile, acceptOrder.
	// Default: 30/min, burst 5.
	CategoryStateMutation

	// CategoryRead covers read-only queries:
	// getListings, getListing, getOrders, getMessages, getBalance, etc.
	// Default: 100/min, burst 20.
	CategoryRead

	// CategoryCryptoGated covers identity-material methods:
	// createIdentity, importIdentity, getMnemonic. Default: 5/min, burst 2.
	// Repeated calls strongly suggest compromise.
	CategoryCryptoGated
)

// MethodLimit is the user-overridable limit for a single exported method.
type MethodLimit struct {
	PerMinute int
	Burst     int
}

// DefaultForCategory returns the default MethodLimit for a category.
func DefaultForCategory(c Category) MethodLimit {
	switch c {
	case CategoryDestructive:
		return MethodLimit{PerMinute: 10, Burst: 3}
	case CategoryStateMutation:
		return MethodLimit{PerMinute: 30, Burst: 5}
	case CategoryRead:
		return MethodLimit{PerMinute: 100, Burst: 20}
	case CategoryCryptoGated:
		return MethodLimit{PerMinute: 5, Burst: 2}
	default:
		return MethodLimit{PerMinute: 60, Burst: 10}
	}
}

// bucket is a single per-method token bucket. refillRate is tokens per second.
type bucket struct {
	mu         sync.Mutex
	tokens     float64
	capacity   float64
	refillRate float64 // tokens/sec
	last       time.Time
	perMinute  int // cached limit for error messages
}

func newBucket(limit MethodLimit, now time.Time) *bucket {
	cap := float64(limit.Burst)
	if cap < 1 {
		cap = 1
	}
	return &bucket{
		tokens:     cap,
		capacity:   cap,
		refillRate: float64(limit.PerMinute) / 60.0,
		last:       now,
		perMinute:  limit.PerMinute,
	}
}

// allow consumes one token if available; returns false if the bucket is empty.
func (b *bucket) allow(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.refillRate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens >= 1.0 {
		b.tokens -= 1.0
		return true
	}
	return false
}

// Limiter holds per-method token buckets and the method->category map.
type Limiter struct {
	mu         sync.RWMutex
	buckets    map[string]*bucket
	categories map[string]Category
	// nowFn allows tests to inject a fake clock.
	nowFn func() time.Time
}

// New builds a Limiter with an empty method->category map. Callers should add
// mappings via RegisterMethod (or RegisterMethods) before calling Allow. A
// method with no registered category is treated as read (conservative
// default for unknown methods).
func New() *Limiter {
	return &Limiter{
		buckets:    make(map[string]*bucket),
		categories: make(map[string]Category),
		nowFn:      time.Now,
	}
}

// SetNowFunc overrides the clock source (tests only).
func (r *Limiter) SetNowFunc(fn func() time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if fn == nil {
		fn = time.Now
	}
	r.nowFn = fn
}

// RegisterMethod assigns a method name to a category. Called at bridge startup.
func (r *Limiter) RegisterMethod(method string, cat Category) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.categories[method] = cat
	// Drop any previously-built bucket so the new category's default applies.
	delete(r.buckets, method)
}

// RegisterMethods is a bulk helper for a method->category map.
func (r *Limiter) RegisterMethods(m map[string]Category) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for method, cat := range m {
		r.categories[method] = cat
		delete(r.buckets, method)
	}
}

// SetLimit overrides the per-method limit. Called by JS via initRateLimits.
// A zero PerMinute or Burst disables limiting for the method (bucket of
// impossibly-high cap); callers should not do this in production.
func (r *Limiter) SetLimit(method string, limit MethodLimit) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if limit.PerMinute <= 0 || limit.Burst <= 0 {
		r.buckets[method] = newBucket(MethodLimit{PerMinute: 1_000_000, Burst: 1_000_000}, r.nowFn())
		return
	}
	r.buckets[method] = newBucket(limit, r.nowFn())
}

// Allow returns nil if the call is permitted, else a rate-limit error whose
// message matches the spec:
//
//	"rate limit exceeded: <method> limited to N per minute"
func (r *Limiter) Allow(method string) error {
	r.mu.RLock()
	b, ok := r.buckets[method]
	cat, hasCat := r.categories[method]
	now := r.nowFn()
	r.mu.RUnlock()

	if !ok {
		// Lazily build the bucket from the registered category (or the
		// safest-sane default if the method was never registered).
		var limit MethodLimit
		if hasCat {
			limit = DefaultForCategory(cat)
		} else {
			// Unknown method: use read-level default (visible but not free).
			limit = DefaultForCategory(CategoryRead)
		}
		r.mu.Lock()
		if existing, exists := r.buckets[method]; exists {
			b = existing
		} else {
			b = newBucket(limit, now)
			r.buckets[method] = b
		}
		r.mu.Unlock()
	}

	if b.allow(now) {
		return nil
	}
	return fmt.Errorf("rate limit exceeded: %s limited to %d per minute", method, b.perMinute)
}
