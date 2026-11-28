//go:build js && wasm

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package main

import (
	"syscall/js"

	"github.com/bbmumford/plutus/wasmratelimit"
)

func main() {
	plutus := js.Global().Get("Object").New()

	bridge := newJSBridge()
	limiter := newPlutusRateLimiter()

	registerMethods(plutus, bridge, limiter)

	// Rate-limit configuration hook (called once at startup by JS to raise or
	// lower the bridge defaults). This call itself is NOT rate-limited.
	installInitRateLimits(plutus, limiter)

	js.Global().Set("Plutus", plutus)

	// Install a JS dispatcher shim so the marketplace-style single-arg call
	// Plutus.createAccount("ETH") resolves to createAccountOnChain, while
	// the three-arg createAccount(handle, chainID, name) flow keeps its
	// handle-taking semantics. This is done in JS-land via a wrapper that
	// inspects arguments.
	shim := js.Global().Get("Function").New(
		"plutus",
		`var legacy = plutus.createAccount;
		 var fresh  = plutus.createAccountOnChain;
		 plutus.createAccount = function () {
			if (arguments.length === 1) { return fresh.apply(null, arguments); }
			return legacy.apply(null, arguments);
		 };`,
	)
	shim.Invoke(plutus)

	// Publish initial state synchronously at module load.
	bridge.publishState()

	// Block forever to keep the WASM module alive
	select {}
}

// registerMethods binds every bridge method the page calls onto the plutus
// object, each behind its per-method rate limit. exportIdentity is the only
// method that returns a mnemonic; no method reads one in the clear.
func registerMethods(plutus js.Value, bridge *jsBridge, limiter *wasmratelimit.Limiter) {
	// set binds a handler to a method name with per-method rate limiting.
	set := func(method string, fn func(this js.Value, args []js.Value) interface{}) {
		plutus.Set(method, js.FuncOf(rateLimited(limiter, method, fn)))
	}

	// Wallet operations
	set("createWallet", bridge.createWallet)
	set("exportIdentity", bridge.exportIdentity)
	set("walletAddress", bridge.walletAddress)
	set("createAccount", bridge.createAccount)
	set("listAccounts", bridge.listAccounts)

	// Marketplace-facing wallet exports (no-arg / chain-code variants)
	set("getAccounts", bridge.getAccounts)
	set("createAccountOnChain", bridge.createAccountDefault)
	set("sendFunds", bridge.sendFunds)
	set("getTransactions", bridge.getTransactions)
	set("getTotalBalance", bridge.getTotalBalance)
	set("getBalance", bridge.getBalance)

	// Escrow operations
	set("createEscrow", bridge.createEscrow)
	set("fundEscrow", bridge.fundEscrow)
	set("releaseEscrow", bridge.releaseEscrow)
	set("disputeEscrow", bridge.disputeEscrow)
	set("settleEscrow", bridge.settleEscrow)
	set("escrowState", bridge.escrowState)

	// Verification and broadcast
	set("verifyTx", bridge.verifyTx)
	set("broadcastTx", bridge.broadcastTx)

	// Witness operations
	set("registerWitness", bridge.registerWitness)

	// Reputation and arbitrators
	set("reputation", bridge.reputation)
	set("recordReputation", bridge.recordReputation)
	set("reputationHistory", bridge.reputationHistory)
	set("findArbitrators", bridge.findArbitrators)
}
