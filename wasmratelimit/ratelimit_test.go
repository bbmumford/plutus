/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package wasmratelimit

import (
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeClock returns a function suitable for Limiter.SetNowFunc. Advancing is
// thread-safe.
func fakeClock(start time.Time) (nowFn func() time.Time, advance func(d time.Duration)) {
	var mu sync.Mutex
	cur := start
	nowFn = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return cur
	}
	advance = func(d time.Duration) {
		mu.Lock()
		defer mu.Unlock()
		cur = cur.Add(d)
	}
	return
}

func TestDefaultForCategory(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cat     Category
		perMin  int
		burst   int
	}{
		{CategoryDestructive, 10, 3},
		{CategoryStateMutation, 30, 5},
		{CategoryRead, 100, 20},
		{CategoryCryptoGated, 5, 2},
	}
	for _, tc := range cases {
		lim := DefaultForCategory(tc.cat)
		if lim.PerMinute != tc.perMin || lim.Burst != tc.burst {
			t.Errorf("category %d: got %d/%d, want %d/%d",
				tc.cat, lim.PerMinute, lim.Burst, tc.perMin, tc.burst)
		}
	}
}

func TestAllowWithinBurst(t *testing.T) {
	t.Parallel()
	r := New()
	r.RegisterMethod("sendFunds", CategoryDestructive) // burst 3

	for i := 0; i < 3; i++ {
		if err := r.Allow("sendFunds"); err != nil {
			t.Fatalf("call %d unexpectedly rate-limited: %v", i, err)
		}
	}
	// 4th call within the same tick should be rejected.
	err := r.Allow("sendFunds")
	if err == nil {
		t.Fatal("expected rate-limit error after exhausting burst")
	}
	if !strings.Contains(err.Error(), "rate limit exceeded") {
		t.Errorf("error message = %q, want it to contain 'rate limit exceeded'", err.Error())
	}
	if !strings.Contains(err.Error(), "sendFunds") {
		t.Errorf("error message = %q, want method name", err.Error())
	}
	if !strings.Contains(err.Error(), "10 per minute") {
		t.Errorf("error message = %q, want '10 per minute'", err.Error())
	}
}

func TestRefillOverTime(t *testing.T) {
	t.Parallel()
	r := New()
	r.RegisterMethod("getBalance", CategoryRead) // 100/min, burst 20

	now, advance := fakeClock(time.Unix(1700000000, 0))
	r.SetNowFunc(now)

	// Drain the burst.
	for i := 0; i < 20; i++ {
		if err := r.Allow("getBalance"); err != nil {
			t.Fatalf("drain call %d: %v", i, err)
		}
	}
	if err := r.Allow("getBalance"); err == nil {
		t.Fatal("expected rejection after drain")
	}

	// After 600ms at 100/min (1.666 tokens/sec) we should have ~1 token.
	advance(600 * time.Millisecond)
	if err := r.Allow("getBalance"); err != nil {
		t.Fatalf("expected refill to allow next call: %v", err)
	}
	// But the second call in that tick should be rejected (only ~0 tokens left).
	if err := r.Allow("getBalance"); err == nil {
		t.Fatal("expected rejection — only one token refilled")
	}

	// After a full minute the bucket should be back to capacity.
	advance(60 * time.Second)
	for i := 0; i < 20; i++ {
		if err := r.Allow("getBalance"); err != nil {
			t.Fatalf("post-refill call %d: %v", i, err)
		}
	}
}

func TestCryptoGatedIsStrictest(t *testing.T) {
	t.Parallel()
	r := New()
	r.RegisterMethod("getMnemonic", CategoryCryptoGated) // 5/min, burst 2

	now, advance := fakeClock(time.Unix(1700000000, 0))
	r.SetNowFunc(now)

	if err := r.Allow("getMnemonic"); err != nil {
		t.Fatal(err)
	}
	if err := r.Allow("getMnemonic"); err != nil {
		t.Fatal(err)
	}
	if err := r.Allow("getMnemonic"); err == nil {
		t.Fatal("third call should be rejected — burst is 2")
	}

	// 5/min = one token every 12s. Advance 12s => one token.
	advance(12 * time.Second)
	if err := r.Allow("getMnemonic"); err != nil {
		t.Fatalf("after 12s: %v", err)
	}
	if err := r.Allow("getMnemonic"); err == nil {
		t.Fatal("second call after 12s should be rejected")
	}
}

func TestSetLimitOverride(t *testing.T) {
	t.Parallel()
	r := New()
	r.RegisterMethod("sendFunds", CategoryDestructive) // default: 10/min, burst 3

	// Desktop app raises the limit.
	r.SetLimit("sendFunds", MethodLimit{PerMinute: 120, Burst: 10})

	for i := 0; i < 10; i++ {
		if err := r.Allow("sendFunds"); err != nil {
			t.Fatalf("override call %d: %v", i, err)
		}
	}
	if err := r.Allow("sendFunds"); err == nil {
		t.Fatal("expected rejection after draining override burst")
	}
	// Error reports the NEW per-minute rate.
	err := r.Allow("sendFunds")
	if err == nil || !strings.Contains(err.Error(), "120 per minute") {
		t.Errorf("expected '120 per minute' in %v", err)
	}
}

func TestPerMethodIsolation(t *testing.T) {
	t.Parallel()
	r := New()
	r.RegisterMethod("sendFunds", CategoryDestructive)   // burst 3
	r.RegisterMethod("getBalance", CategoryRead)         // burst 20
	r.RegisterMethod("getMnemonic", CategoryCryptoGated) // burst 2

	// Drain sendFunds.
	for i := 0; i < 3; i++ {
		if err := r.Allow("sendFunds"); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Allow("sendFunds"); err == nil {
		t.Fatal("sendFunds should be rate-limited")
	}

	// Other methods are unaffected.
	if err := r.Allow("getBalance"); err != nil {
		t.Errorf("getBalance affected by sendFunds drain: %v", err)
	}
	if err := r.Allow("getMnemonic"); err != nil {
		t.Errorf("getMnemonic affected by sendFunds drain: %v", err)
	}
}

func TestUnknownMethodDefaultsToRead(t *testing.T) {
	t.Parallel()
	r := New()
	// No RegisterMethod call. Unknown methods get read-level defaults
	// (100/min, burst 20) — visible enough to not break dev workflows but
	// not free.
	for i := 0; i < 20; i++ {
		if err := r.Allow("randomUnmappedMethod"); err != nil {
			t.Fatalf("unknown-method call %d: %v", i, err)
		}
	}
	if err := r.Allow("randomUnmappedMethod"); err == nil {
		t.Fatal("expected read-default rejection after 20 calls")
	}
}

func TestRegisterMethodsBulk(t *testing.T) {
	t.Parallel()
	r := New()
	r.RegisterMethods(map[string]Category{
		"sendFunds":     CategoryDestructive,
		"getBalance":    CategoryRead,
		"createIdentity": CategoryCryptoGated,
	})
	// Sanity: each method uses its assigned category's default burst.
	// Destructive=3, Read=20, CryptoGated=2.
	count := func(method string) int {
		n := 0
		for {
			if err := r.Allow(method); err != nil {
				return n
			}
			n++
			if n > 100 {
				return n // guard
			}
		}
	}
	if got := count("sendFunds"); got != 3 {
		t.Errorf("sendFunds burst = %d, want 3", got)
	}
	if got := count("getBalance"); got != 20 {
		t.Errorf("getBalance burst = %d, want 20", got)
	}
	if got := count("createIdentity"); got != 2 {
		t.Errorf("createIdentity burst = %d, want 2", got)
	}
}

func TestConcurrentAllow(t *testing.T) {
	t.Parallel()
	r := New()
	// Very permissive so we don't race the rate limit: 600/min, burst 100.
	r.RegisterMethod("m", CategoryRead)
	r.SetLimit("m", MethodLimit{PerMinute: 600, Burst: 100})

	var allowed atomic.Int64
	var denied atomic.Int64
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if err := r.Allow("m"); err == nil {
					allowed.Add(1)
				} else {
					denied.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	total := allowed.Load() + denied.Load()
	if total != 400 {
		t.Errorf("total calls = %d, want 400", total)
	}
	// At least the burst worth should have been allowed.
	if allowed.Load() < 100 {
		t.Errorf("allowed = %d, want >=100 (burst)", allowed.Load())
	}
}
