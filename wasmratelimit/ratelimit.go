/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

// Package wasmratelimit is the per-method rate limit of the Plutus and Mercury
// WASM bridges, which defends against a rogue or compromised JS page hammering
// sensitive exports (sendFunds, sendMessage, submitReview, etc).
//
// The bridge declares every method it exports with a Category at startup
// (RegisterMethods), and the page may raise or lower a declared method's limit
// (SetLimit, through the bridge's initRateLimits). A method never declared is
// refused: a bridge that exports a method without declaring it gets an error
// from every call rather than a limit nobody chose. The buckets are
// github.com/bbmumford/ratelimit's Keyed token buckets, one named limit per
// method, refilled continuously at the method's per-minute rate up to its
// burst. Each bridge instance owns its own limiter. Limits are per method, not
// per peer: the threat model is rogue JS on the page, not rogue peers.
package wasmratelimit

import (
	"fmt"
	"sync"
	"time"

	"github.com/bbmumford/ratelimit"
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

// bridgeKey is the one key every method's bucket is spent under: a limiter
// belongs to one bridge instance, so the method name alone tells buckets apart.
const bridgeKey = "bridge"

// keyedMaxAge and keyedMaxKeys bound the Keyed limiter's bucket map: one
// bucket per declaration under bridgeKey, swept after an hour idle.
const (
	keyedMaxAge  = time.Hour
	keyedMaxKeys = 1024
)

// Limiter holds one bridge's declared methods and their limits on a
// ratelimit.Keyed.
type Limiter struct {
	k *ratelimit.Keyed

	mu       sync.RWMutex
	declared map[string]declaredMethod // every method Allow admits
	gen      int                       // counts declarations, so each one names a fresh Keyed limit
}

// declaredMethod is one declared method's limit and the Keyed limit name its
// bucket lives under. A declaration takes a new name, so a changed limit starts
// from a full bucket of its own burst instead of the old limit's bucket.
type declaredMethod struct {
	limit MethodLimit // PerMinute 0 for a method SetLimit left without a limit
	name  string
}

// New builds a Limiter with no method declared; Allow refuses every method
// until RegisterMethod, RegisterMethods or SetLimit declares it.
func New() *Limiter {
	return &Limiter{k: ratelimit.NewKeyed(keyedMaxAge, keyedMaxKeys), declared: make(map[string]declaredMethod)}
}

// RegisterMethod declares a method with its category's default limit. Called
// at bridge startup.
func (r *Limiter) RegisterMethod(method string, cat Category) {
	r.set(method, DefaultForCategory(cat))
}

// RegisterMethods is a bulk helper for a method->category map.
func (r *Limiter) RegisterMethods(m map[string]Category) {
	for method, cat := range m {
		r.RegisterMethod(method, cat)
	}
}

// SetLimit declares method with limit, replacing its category default. Called
// by JS via initRateLimits. A PerMinute or Burst that is not positive leaves
// the method declared without a limit; callers should not do this in
// production.
func (r *Limiter) SetLimit(method string, limit MethodLimit) {
	if limit.PerMinute <= 0 || limit.Burst <= 0 {
		name := r.declare(method, MethodLimit{})
		r.k.Unlimited(name)
		return
	}
	r.set(method, limit)
}

// declare records method at limit under a fresh Keyed limit name and returns
// the name.
func (r *Limiter) declare(method string, limit MethodLimit) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.gen++
	name := fmt.Sprintf("%s#%d", method, r.gen)
	r.declared[method] = declaredMethod{limit: limit, name: name}
	return name
}

// set declares method at limit and gives it a fresh bucket of limit.Burst
// tokens refilled at limit.PerMinute a minute.
func (r *Limiter) set(method string, limit MethodLimit) {
	if limit.Burst < 1 {
		limit.Burst = 1
	}
	r.k.Set(r.declare(method, limit), limit.PerMinute, limit.Burst, time.Minute)
}

// Allow returns nil if the call is permitted, else an error whose message
// names the method: for a declared method whose bucket is empty,
//
//	"rate limit exceeded: <method> limited to N per minute"
//
// and for a method never declared, "rate limit exceeded: <method> is not a
// declared bridge method".
func (r *Limiter) Allow(method string) error {
	r.mu.RLock()
	d, ok := r.declared[method]
	r.mu.RUnlock()
	if !ok {
		return fmt.Errorf("rate limit exceeded: %s is not a declared bridge method", method)
	}
	if allowed, _ := r.k.Allow(d.name, bridgeKey); allowed {
		return nil
	}
	return fmt.Errorf("rate limit exceeded: %s limited to %d per minute", method, d.limit.PerMinute)
}
