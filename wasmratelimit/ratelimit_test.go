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

func TestDefaultForCategory(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cat    Category
		perMin int
		burst  int
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

// TestRefillOverTime drains a method at 600 a minute (one token every 100ms) and
// waits for the bucket to refill on the real clock, as the bridge's limiter runs.
func TestRefillOverTime(t *testing.T) {
	t.Parallel()
	r := New()
	r.SetLimit("getBalance", MethodLimit{PerMinute: 600, Burst: 2})

	for i := 0; i < 2; i++ {
		if err := r.Allow("getBalance"); err != nil {
			t.Fatalf("drain call %d: %v", i, err)
		}
	}
	if err := r.Allow("getBalance"); err == nil {
		t.Fatal("expected rejection after drain")
	}
	time.Sleep(250 * time.Millisecond) // two tokens' worth at 10 a second, capped at the burst of 2
	for i := 0; i < 2; i++ {
		if err := r.Allow("getBalance"); err != nil {
			t.Fatalf("expected refill to allow call %d: %v", i, err)
		}
	}
}

func TestCryptoGatedIsStrictest(t *testing.T) {
	t.Parallel()
	r := New()
	r.RegisterMethod("getMnemonic", CategoryCryptoGated) // 5/min, burst 2

	if err := r.Allow("getMnemonic"); err != nil {
		t.Fatal(err)
	}
	if err := r.Allow("getMnemonic"); err != nil {
		t.Fatal(err)
	}
	err := r.Allow("getMnemonic")
	if err == nil {
		t.Fatal("third call should be rejected — burst is 2")
	}
	if !strings.Contains(err.Error(), "5 per minute") {
		t.Errorf("error message = %q, want '5 per minute'", err.Error())
	}
}

func TestSetLimitOverride(t *testing.T) {
	t.Parallel()
	r := New()
	r.RegisterMethod("sendFunds", CategoryDestructive) // default: 10/min, burst 3
	if err := r.Allow("sendFunds"); err != nil {
		t.Fatal(err)
	}

	// Desktop app raises the limit; the method starts again from the new burst.
	r.SetLimit("sendFunds", MethodLimit{PerMinute: 120, Burst: 10})

	for i := 0; i < 10; i++ {
		if err := r.Allow("sendFunds"); err != nil {
			t.Fatalf("override call %d: %v", i, err)
		}
	}
	// Error reports the NEW per-minute rate.
	err := r.Allow("sendFunds")
	if err == nil || !strings.Contains(err.Error(), "120 per minute") {
		t.Errorf("expected '120 per minute' in %v", err)
	}
}

// TestSetLimitZeroLeavesTheMethodDeclaredWithoutALimit pins initRateLimits' way to lift a method's limit: the
// method stays declared, so its calls are admitted, every one.
func TestSetLimitZeroLeavesTheMethodDeclaredWithoutALimit(t *testing.T) {
	t.Parallel()
	r := New()
	r.RegisterMethod("getBalance", CategoryRead)
	r.SetLimit("getBalance", MethodLimit{})
	for i := 0; i < 500; i++ {
		if err := r.Allow("getBalance"); err != nil {
			t.Fatalf("call %d of a method declared without a limit: %v", i, err)
		}
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

// TestAnUndeclaredMethodIsRefused pins the fail-closed rule: a method the bridge never declared is refused on its
// first call, so a bridge that exports a method without declaring it finds out at once instead of running it under
// a limit nobody chose.
func TestAnUndeclaredMethodIsRefused(t *testing.T) {
	t.Parallel()
	r := New()
	r.RegisterMethod("getBalance", CategoryRead)
	err := r.Allow("randomUnmappedMethod")
	if err == nil {
		t.Fatal("an undeclared method was admitted")
	}
	if !strings.Contains(err.Error(), "randomUnmappedMethod") || !strings.Contains(err.Error(), "not a declared bridge method") {
		t.Errorf("error message = %q, want the method named as not declared", err.Error())
	}
}

func TestRegisterMethodsBulk(t *testing.T) {
	t.Parallel()
	r := New()
	r.RegisterMethods(map[string]Category{
		"sendFunds":      CategoryDestructive,
		"getBalance":     CategoryRead,
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
