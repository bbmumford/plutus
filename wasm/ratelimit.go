//go:build js && wasm

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package main

import (
	"syscall/js"

	"github.com/bbmumford/plutus/wasmratelimit"
)

// pluginMethodCategories is the default method->category mapping for the
// Plutus JS bridge.
var pluginMethodCategories = map[string]wasmratelimit.Category{
	// Destructive / broadcast
	"sendFunds":        wasmratelimit.CategoryDestructive,
	"broadcastTx":      wasmratelimit.CategoryDestructive,
	"createEscrow":     wasmratelimit.CategoryDestructive,
	"fundEscrow":       wasmratelimit.CategoryDestructive,
	"releaseEscrow":    wasmratelimit.CategoryDestructive,
	"disputeEscrow":    wasmratelimit.CategoryDestructive,
	"settleEscrow":     wasmratelimit.CategoryDestructive,
	"recordReputation": wasmratelimit.CategoryDestructive,
	"registerWitness":  wasmratelimit.CategoryDestructive,

	// State mutation
	"createAccount":        wasmratelimit.CategoryStateMutation,
	"createAccountOnChain": wasmratelimit.CategoryStateMutation,

	// Read
	"walletAddress":     wasmratelimit.CategoryRead,
	"listAccounts":      wasmratelimit.CategoryRead,
	"getAccounts":       wasmratelimit.CategoryRead,
	"getBalance":        wasmratelimit.CategoryRead,
	"getTotalBalance":   wasmratelimit.CategoryRead,
	"getTransactions":   wasmratelimit.CategoryRead,
	"escrowState":       wasmratelimit.CategoryRead,
	"verifyTx":          wasmratelimit.CategoryRead,
	"reputation":        wasmratelimit.CategoryRead,
	"reputationHistory": wasmratelimit.CategoryRead,
	"findArbitrators":   wasmratelimit.CategoryRead,

	// Crypto-gated
	"createWallet": wasmratelimit.CategoryCryptoGated,
}

// newPlutusRateLimiter builds a rate limiter pre-registered with the Plutus
// bridge's method->category defaults.
func newPlutusRateLimiter() *wasmratelimit.Limiter {
	r := wasmratelimit.New()
	r.RegisterMethods(pluginMethodCategories)
	return r
}

// rateLimited wraps a bridge handler with per-method rate limiting. If the
// bucket is empty the returned Promise is rejected with
// "rate limit exceeded: <method> limited to N per minute".
func rateLimited(r *wasmratelimit.Limiter, method string, handler func(this js.Value, args []js.Value) interface{}) func(this js.Value, args []js.Value) interface{} {
	return func(this js.Value, args []js.Value) interface{} {
		if err := r.Allow(method); err != nil {
			return promiseWrapper(func() (interface{}, error) {
				return nil, err
			})
		}
		return handler(this, args)
	}
}

// installInitRateLimits exposes `Plutus.initRateLimits({method: {perMinute, burst}})`
// on the given JS object. Callers use it once at startup to raise or lower the
// defaults (e.g., the desktop app can permit higher throughput; the example
// web page keeps the stock defaults).
func installInitRateLimits(target js.Value, r *wasmratelimit.Limiter) {
	target.Set("initRateLimits", js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		if len(args) == 0 || args[0].IsNull() || args[0].IsUndefined() {
			return nil
		}
		obj := args[0]
		keys := js.Global().Get("Object").Call("keys", obj)
		n := keys.Length()
		for i := 0; i < n; i++ {
			method := keys.Index(i).String()
			entry := obj.Get(method)
			if entry.IsNull() || entry.IsUndefined() {
				continue
			}
			var limit wasmratelimit.MethodLimit
			if v := entry.Get("perMinute"); !v.IsUndefined() && !v.IsNull() {
				limit.PerMinute = v.Int()
			}
			if v := entry.Get("burst"); !v.IsUndefined() && !v.IsNull() {
				limit.Burst = v.Int()
			}
			r.SetLimit(method, limit)
		}
		return nil
	}))
}
