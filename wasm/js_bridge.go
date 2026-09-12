//go:build js && wasm

/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"syscall/js"
	"time"

	"github.com/bbmumford/plutus/adapter"
	"github.com/bbmumford/plutus/arbitrator"
	"github.com/bbmumford/plutus/escrow"
	"github.com/bbmumford/plutus/reputation"
	"github.com/bbmumford/plutus/settle"
	"github.com/bbmumford/plutus/wallet"
	"github.com/bbmumford/plutus/witness"

	"github.com/bbmumford/ledger/cache"
	"github.com/bbmumford/whisper"
)

// jsBridge holds the WASM-side state for the JS bridge.
type jsBridge struct {
	mu sync.RWMutex

	// Handle counters
	nextWalletHandle  atomic.Int64
	nextEscrowHandle  atomic.Int64

	// Handle maps
	wallets       map[int64]*walletState
	escrowMgrs    map[int64]*escrowState

	// Shared services
	engine        *whisper.Engine
	dirCache      *cache.DirectoryCache
	witnessReg    *witness.WitnessRegistry
	verifier      *witness.MeshVerifier
	balanceVerif  *witness.BalanceVerifier
	broadcast     *witness.BroadcastService
	arbRegistry   *arbitrator.ArbitratorRegistry
	repService    *reputation.ReputationService

	// In-memory wallet transaction log for getTransactions(). Kept simple:
	// no persistence, cleared on page reload.
	txLog []txRecord
}

// walletState holds per-wallet state on the WASM side.
type walletState struct {
	mnemonic    string
	seed        []byte
	identityKey ed25519.PrivateKey
	signer      *wallet.Signer
	accounts    map[string][]wallet.WalletAccount // chainID -> accounts
}

// escrowState holds per-escrow state on the WASM side.
type escrowState struct {
	walletHandle int64
	manager      *escrow.EscrowManager
	lastInstance *escrow.EscrowInstance
}

func newJSBridge() *jsBridge {
	engine := whisper.NewEngine()
	dirCache := cache.NewDirectoryCache(nil)
	collusionDetector := witness.NewCollusionDetector()
	witnessReg := witness.NewWitnessRegistry(engine, dirCache)
	meshVerifier := witness.NewMeshVerifier(engine, witnessReg, collusionDetector)
	balanceVerifier := witness.NewBalanceVerifier(engine, witness.BalanceVerifierConfig{})
	broadcastSvc := witness.NewBroadcastService(engine)
	arbReg := arbitrator.NewArbitratorRegistry(engine, dirCache)
	repSvc := reputation.NewReputationService(engine, dirCache)

	return &jsBridge{
		wallets:     make(map[int64]*walletState),
		escrowMgrs:  make(map[int64]*escrowState),
		engine:      engine,
		dirCache:    dirCache,
		witnessReg:   witnessReg,
		verifier:     meshVerifier,
		balanceVerif: balanceVerifier,
		broadcast:    broadcastSvc,
		arbRegistry:  arbReg,
		repService:   repSvc,
	}
}

// promiseWrapper wraps an async Go operation as a JS Promise.
func promiseWrapper(fn func() (interface{}, error)) js.Value {
	handler := js.FuncOf(func(this js.Value, args []js.Value) interface{} {
		resolve := args[0]
		reject := args[1]
		go func() {
			result, err := fn()
			if err != nil {
				reject.Invoke(js.Global().Get("Error").New(err.Error()))
				return
			}
			resolve.Invoke(toJSValue(result))
		}()
		return nil
	})
	return js.Global().Get("Promise").New(handler)
}

// createWallet creates a new wallet from config. Config may contain "mnemonic"
// to restore from existing, or will generate a new one.
// Plutus.createWallet(config) -> handle
func (b *jsBridge) createWallet(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		var mnemonic string
		var err error

		if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
			mnemonicVal := args[0].Get("mnemonic")
			if !mnemonicVal.IsUndefined() && !mnemonicVal.IsNull() {
				mnemonic = mnemonicVal.String()
			}
		}

		if mnemonic == "" {
			mnemonic, err = wallet.GenerateMnemonic()
			if err != nil {
				return nil, fmt.Errorf("createWallet: %w", err)
			}
		}

		seed, err := wallet.MnemonicToSeed(mnemonic, "")
		if err != nil {
			return nil, fmt.Errorf("createWallet: %w", err)
		}

		identityKey, err := wallet.DeriveProtocolIdentity(seed)
		if err != nil {
			return nil, fmt.Errorf("createWallet: %w", err)
		}

		prcResolver := wallet.NewPRCResolver(nil, nil)
		signer := wallet.NewSigner(identityKey, prcResolver)

		handle := b.nextWalletHandle.Add(1)

		b.mu.Lock()
		b.wallets[handle] = &walletState{
			mnemonic:    mnemonic,
			seed:        seed,
			identityKey: identityKey,
			signer:      signer,
		}
		b.mu.Unlock()

		b.publishState()
		return handle, nil
	})
}

// walletAddress returns the chain address for a wallet on a specific chain.
// Plutus.walletAddress(handle, chainID)        -> default account address
// Plutus.walletAddress(handle, chainID, 1)     -> account 1 address
func (b *jsBridge) walletAddress(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("walletAddress: requires handle and chainID")
		}
		handle := int64(args[0].Float())
		chainID := args[1].String()

		account := uint32(0)
		if len(args) > 2 && !args[2].IsUndefined() && !args[2].IsNull() {
			account = uint32(args[2].Float())
		}

		b.mu.RLock()
		ws, ok := b.wallets[handle]
		b.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("walletAddress: unknown handle %d", handle)
		}

		// Derive chain-specific key based on chain ID and account index
		coinType := chainIDToCoinType(chainID)
		chainKey, err := wallet.DeriveChainKey(ws.seed, coinType, account)
		if err != nil {
			return nil, fmt.Errorf("walletAddress: %w", err)
		}

		return wallet.ChainAddress(chainKey), nil
	})
}

// createAccount creates a new named account for a chain on a wallet.
// Plutus.createAccount(handle, chainID, name) -> account object (JSON)
func (b *jsBridge) createAccount(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 3 {
			return nil, fmt.Errorf("createAccount: requires handle, chainID, and name")
		}
		handle := int64(args[0].Float())
		chainID := args[1].String()
		name := args[2].String()

		b.mu.RLock()
		ws, ok := b.wallets[handle]
		b.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("createAccount: unknown handle %d", handle)
		}

		// Determine next account index for this chain
		b.mu.Lock()
		if ws.accounts == nil {
			ws.accounts = make(map[string][]wallet.WalletAccount)
		}

		idx := uint32(0)
		if existing := ws.accounts[chainID]; len(existing) > 0 {
			for _, a := range existing {
				if a.Index >= idx {
					idx = a.Index + 1
				}
			}
		}

		coinType := chainIDToCoinType(chainID)
		chainKey, err := wallet.DeriveChainKey(ws.seed, coinType, idx)
		if err != nil {
			b.mu.Unlock()
			return nil, fmt.Errorf("createAccount: %w", err)
		}

		addr := wallet.ChainAddress(chainKey)
		acct := wallet.WalletAccount{
			Index:     idx,
			Name:      name,
			ChainID:   chainID,
			Address:   addr,
			CreatedAt: time.Now(),
		}
		ws.accounts[chainID] = append(ws.accounts[chainID], acct)
		b.mu.Unlock()

		data, err := json.Marshal(acct)
		if err != nil {
			return nil, fmt.Errorf("createAccount: marshal: %w", err)
		}
		return string(data), nil
	})
}

// listAccounts returns all accounts for a chain on a wallet.
// Plutus.listAccounts(handle, chainID) -> array of account objects (JSON)
// If chainID is empty, returns accounts across all chains.
func (b *jsBridge) listAccounts(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("listAccounts: requires handle and chainID")
		}
		handle := int64(args[0].Float())
		chainID := args[1].String()

		b.mu.RLock()
		ws, ok := b.wallets[handle]
		b.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("listAccounts: unknown handle %d", handle)
		}

		b.mu.RLock()
		var result []wallet.WalletAccount
		if chainID != "" {
			if ws.accounts != nil {
				result = make([]wallet.WalletAccount, len(ws.accounts[chainID]))
				copy(result, ws.accounts[chainID])
			}
		} else {
			if ws.accounts != nil {
				for _, accts := range ws.accounts {
					result = append(result, accts...)
				}
			}
		}
		b.mu.RUnlock()

		if result == nil {
			result = []wallet.WalletAccount{}
		}

		data, err := json.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("listAccounts: marshal: %w", err)
		}
		return string(data), nil
	})
}

// walletMnemonic returns the mnemonic for a wallet handle.
// Plutus.walletMnemonic(handle) -> string
func (b *jsBridge) walletMnemonic(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("walletMnemonic: requires handle")
		}
		handle := int64(args[0].Float())

		b.mu.RLock()
		ws, ok := b.wallets[handle]
		b.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("walletMnemonic: unknown handle %d", handle)
		}

		return ws.mnemonic, nil
	})
}

// createEscrow creates an escrow manager bound to a wallet.
// Plutus.createEscrow(walletHandle, params) -> escrowHandle
func (b *jsBridge) createEscrow(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("createEscrow: requires walletHandle and params")
		}
		walletHandle := int64(args[0].Float())

		b.mu.RLock()
		_, ok := b.wallets[walletHandle]
		b.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("createEscrow: unknown wallet handle %d", walletHandle)
		}

		// Create an escrow manager using a bridge adapter resolver and verifier
		bridgeVerifier := &wasmMeshVerifier{bridge: b}
		bridgeWallet := &wasmWallet{bridge: b, walletHandle: walletHandle}
		bridgeAdapters := &wasmAdapterResolver{}

		mgr := escrow.NewEscrowManager(bridgeAdapters, bridgeWallet, bridgeVerifier,
			escrow.WithFeeCalculator(&wasmFeeCalculator{}),
		)

		handle := b.nextEscrowHandle.Add(1)

		b.mu.Lock()
		b.escrowMgrs[handle] = &escrowState{
			walletHandle: walletHandle,
			manager:      mgr,
		}
		b.mu.Unlock()

		return handle, nil
	})
}

// fundEscrow funds an escrow.
// Plutus.fundEscrow(escrowHandle) -> txHash
func (b *jsBridge) fundEscrow(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("fundEscrow: requires escrowHandle")
		}
		handle := int64(args[0].Float())

		b.mu.RLock()
		es, ok := b.escrowMgrs[handle]
		b.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("fundEscrow: unknown handle %d", handle)
		}

		// Extract fund params from JS args
		params := escrow.FundParams{
			Amount:        big.NewInt(0),
			Currency:      "USDC",
			TimeoutBlocks: 1000,
		}
		if len(args) > 1 && !args[1].IsNull() && !args[1].IsUndefined() {
			p := args[1]
			if v := p.Get("amount"); !v.IsUndefined() {
				params.Amount, _ = new(big.Int).SetString(v.String(), 10)
			}
			if v := p.Get("buyer"); !v.IsUndefined() {
				params.Buyer = v.String()
			}
			if v := p.Get("seller"); !v.IsUndefined() {
				params.Seller = v.String()
			}
			if v := p.Get("currency"); !v.IsUndefined() {
				params.Currency = v.String()
			}
			if v := p.Get("chainId"); !v.IsUndefined() {
				params.ChainID = v.String()
			}
			if v := p.Get("timeoutBlocks"); !v.IsUndefined() {
				params.TimeoutBlocks = uint64(v.Float())
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		inst, err := es.manager.Fund(ctx, params)
		if err != nil {
			return nil, fmt.Errorf("fundEscrow: %w", err)
		}

		b.mu.Lock()
		es.lastInstance = inst
		b.mu.Unlock()

		return inst.TxHash, nil
	})
}

// releaseEscrow releases funds from an escrow.
// Plutus.releaseEscrow(escrowHandle) -> txHash
func (b *jsBridge) releaseEscrow(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("releaseEscrow: requires escrowHandle")
		}
		handle := int64(args[0].Float())

		b.mu.RLock()
		es, ok := b.escrowMgrs[handle]
		b.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("releaseEscrow: unknown handle %d", handle)
		}

		if es.lastInstance == nil {
			return nil, fmt.Errorf("releaseEscrow: no funded escrow on this handle")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		txHash, err := es.manager.Release(ctx, es.lastInstance.Address, escrow.ReleaseParams{})
		if err != nil {
			return nil, fmt.Errorf("releaseEscrow: %w", err)
		}

		return txHash, nil
	})
}

// disputeEscrow files a dispute on an escrow.
// Plutus.disputeEscrow(escrowHandle, evidence) -> txHash
func (b *jsBridge) disputeEscrow(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("disputeEscrow: requires escrowHandle")
		}
		handle := int64(args[0].Float())

		b.mu.RLock()
		es, ok := b.escrowMgrs[handle]
		b.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("disputeEscrow: unknown handle %d", handle)
		}

		if es.lastInstance == nil {
			return nil, fmt.Errorf("disputeEscrow: no funded escrow on this handle")
		}

		var evidence []byte
		if len(args) > 1 && !args[1].IsNull() && !args[1].IsUndefined() {
			evidence = []byte(args[1].String())
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		txHash, err := es.manager.Dispute(ctx, es.lastInstance.Address, escrow.DisputeParams{
			Evidence: evidence,
		})
		if err != nil {
			return nil, fmt.Errorf("disputeEscrow: %w", err)
		}

		return txHash, nil
	})
}

// escrowState queries the current escrow state.
// Plutus.escrowState(escrowHandle) -> state
func (b *jsBridge) escrowState(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("escrowState: requires escrowHandle")
		}
		handle := int64(args[0].Float())

		b.mu.RLock()
		es, ok := b.escrowMgrs[handle]
		b.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("escrowState: unknown handle %d", handle)
		}

		if es.lastInstance == nil {
			return nil, fmt.Errorf("escrowState: no funded escrow on this handle")
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		state, err := es.manager.State(ctx, es.lastInstance.Address)
		if err != nil {
			return nil, fmt.Errorf("escrowState: %w", err)
		}

		return marshalEscrowState(state), nil
	})
}

// verifyTx verifies a transaction via the witness mesh.
// Plutus.verifyTx(chainID, txHash, policyLevel) -> confirmed
func (b *jsBridge) verifyTx(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("verifyTx: requires chainID and txHash")
		}
		chainID := args[0].String()
		txHash := args[1].String()

		var policyLevel float64 = 50 // default standard
		if len(args) > 2 && !args[2].IsUndefined() {
			policyLevel = args[2].Float()
		}

		policy := witness.PolicyForValue(policyLevel)

		ctx, cancel := context.WithTimeout(context.Background(), policy.Timeout+5*time.Second)
		defer cancel()

		confirmed, err := b.verifier.IsConfirmed(ctx, chainID, txHash, policy)
		if err != nil {
			return nil, fmt.Errorf("verifyTx: %w", err)
		}

		return confirmed, nil
	})
}

// broadcastTx broadcasts a signed transaction via the witness mesh.
// Plutus.broadcastTx(chainID, signedTx) -> txHash
func (b *jsBridge) broadcastTx(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("broadcastTx: requires chainID and signedTx")
		}
		chainID := args[0].String()
		signedTxHex := args[1].String()

		signedTx, err := hex.DecodeString(signedTxHex)
		if err != nil {
			return nil, fmt.Errorf("broadcastTx: invalid hex: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		txHash, err := b.broadcast.BroadcastTx(ctx, chainID, signedTx)
		if err != nil {
			return nil, fmt.Errorf("broadcastTx: %w", err)
		}

		return txHash, nil
	})
}

// registerWitness registers the wallet as a witness for the given chain IDs.
// Plutus.registerWitness(walletHandle, chainIDs) -> void
func (b *jsBridge) registerWitness(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("registerWitness: requires walletHandle and chainIDs")
		}
		walletHandle := int64(args[0].Float())

		b.mu.RLock()
		ws, ok := b.wallets[walletHandle]
		b.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("registerWitness: unknown wallet handle %d", walletHandle)
		}

		chainIDsJS := args[1]
		chainIDs := make([]string, chainIDsJS.Length())
		for i := range chainIDs {
			chainIDs[i] = chainIDsJS.Index(i).String()
		}

		pubKey := ws.identityKey.Public().(ed25519.PublicKey)

		// Optional third argument: payoutAddresses as a JS object keyed by
		// chainID. Absent / wrong-typed objects leave the map nil; the fee
		// distributor will skip any chain with no configured address.
		var payoutAddresses map[string]string
		if len(args) >= 3 && args[2].Type() == js.TypeObject {
			payoutAddresses = make(map[string]string, len(chainIDs))
			for _, cid := range chainIDs {
				v := args[2].Get(cid)
				if v.Type() == js.TypeString {
					payoutAddresses[cid] = v.String()
				}
			}
		}

		reg := witness.WitnessRegistration{
			PubKey:          pubKey,
			ChainIDs:        chainIDs,
			Capabilities:    []string{"tx-confirm", "balance", "escrow-state", "broadcast"},
			Reputation:      0.5,
			RegisteredAt:    time.Now(),
			PayoutAddresses: payoutAddresses,
		}

		// Sign with the wallet identity key so Register()'s Verify() step
		// accepts the registration. ws.identityKey is an ed25519.PrivateKey
		// whose public half matches pubKey above.
		if err := reg.Sign(ws.identityKey); err != nil {
			return nil, fmt.Errorf("registerWitness: sign: %w", err)
		}

		if err := b.witnessReg.Register(reg); err != nil {
			return nil, fmt.Errorf("registerWitness: %w", err)
		}

		return nil, nil
	})
}

// reputation queries the reputation score for a pubkey.
// Plutus.reputation(pubkey) -> score
func (b *jsBridge) reputation(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("reputation: requires pubkey")
		}
		pubkeyHex := args[0].String()
		pubkey, err := hex.DecodeString(pubkeyHex)
		if err != nil {
			return nil, fmt.Errorf("reputation: invalid hex pubkey: %w", err)
		}

		score := b.repService.Score(pubkey)

		data, err := json.Marshal(score)
		if err != nil {
			return nil, fmt.Errorf("reputation: marshal score: %w", err)
		}

		return string(data), nil
	})
}

// recordReputation records a new reputation event via the WASM bridge.
// Plutus.recordReputation(record) -> void
func (b *jsBridge) recordReputation(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 || args[0].IsNull() || args[0].IsUndefined() {
			return nil, fmt.Errorf("recordReputation: requires record object")
		}

		recJS := args[0]

		subjectHex := recJS.Get("subjectPubKey").String()
		subjectPubKey, err := hex.DecodeString(subjectHex)
		if err != nil {
			return nil, fmt.Errorf("recordReputation: invalid subjectPubKey hex: %w", err)
		}

		recorderHex := recJS.Get("recorderPubKey").String()
		recorderPubKey, err := hex.DecodeString(recorderHex)
		if err != nil {
			return nil, fmt.Errorf("recordReputation: invalid recorderPubKey hex: %w", err)
		}

		rec := reputation.ReputationRecord{
			SubjectPubKey:  subjectPubKey,
			RecorderPubKey: recorderPubKey,
			Score:          int32(recJS.Get("score").Int()),
			Timestamp:      time.Now(),
		}

		if v := recJS.Get("type"); !v.IsUndefined() {
			rec.Type = reputation.RepType(v.Int())
		}
		if v := recJS.Get("appId"); !v.IsUndefined() {
			rec.AppID = v.String()
		}
		if v := recJS.Get("txHash"); !v.IsUndefined() {
			rec.TxHash = v.String()
		}
		if v := recJS.Get("comment"); !v.IsUndefined() {
			rec.Comment = v.String()
		}
		if v := recJS.Get("signature"); !v.IsUndefined() && !v.IsNull() {
			sigHex := v.String()
			sig, err := hex.DecodeString(sigHex)
			if err != nil {
				return nil, fmt.Errorf("recordReputation: invalid signature hex: %w", err)
			}
			rec.Signature = sig
		}

		if err := b.repService.Record(rec); err != nil {
			return nil, fmt.Errorf("recordReputation: %w", err)
		}

		return nil, nil
	})
}

// reputationHistory returns the reputation history for a pubkey.
// Plutus.reputationHistory(pubkeyHex, limit) -> array
func (b *jsBridge) reputationHistory(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("reputationHistory: requires pubkey")
		}
		pubkeyHex := args[0].String()
		pubkey, err := hex.DecodeString(pubkeyHex)
		if err != nil {
			return nil, fmt.Errorf("reputationHistory: invalid hex pubkey: %w", err)
		}

		limit := 50
		if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
			limit = args[1].Int()
		}

		records := b.repService.History(pubkey, limit)

		data, err := json.Marshal(records)
		if err != nil {
			return nil, fmt.Errorf("reputationHistory: marshal records: %w", err)
		}

		return string(data), nil
	})
}

// settleEscrow settles a disputed escrow with an arbitrator ruling.
// Plutus.settleEscrow(escrowHandle, ruling) -> txHash
func (b *jsBridge) settleEscrow(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("settleEscrow: requires escrowHandle and ruling")
		}
		handle := int64(args[0].Float())

		b.mu.RLock()
		es, ok := b.escrowMgrs[handle]
		b.mu.RUnlock()
		if !ok {
			return nil, fmt.Errorf("settleEscrow: unknown handle %d", handle)
		}

		if es.lastInstance == nil {
			return nil, fmt.Errorf("settleEscrow: no funded escrow on this handle")
		}

		rulingJS := args[1]
		ruling := escrow.Ruling{
			Outcome:       "settle",
			BuyerPercent:  uint32(rulingJS.Get("buyerPercent").Int()),
			SellerPercent: uint32(rulingJS.Get("sellerPercent").Int()),
		}
		if v := rulingJS.Get("outcome"); !v.IsUndefined() && !v.IsNull() {
			ruling.Outcome = v.String()
		}
		if v := rulingJS.Get("arbitratorSig"); !v.IsUndefined() && !v.IsNull() {
			sig, err := hex.DecodeString(v.String())
			if err != nil {
				return nil, fmt.Errorf("settleEscrow: invalid arbitratorSig hex: %w", err)
			}
			ruling.ArbitratorSig = sig
		}

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		txHash, err := es.manager.SettleWithRuling(ctx, es.lastInstance.Address, ruling)
		if err != nil {
			return nil, fmt.Errorf("settleEscrow: %w", err)
		}

		return txHash, nil
	})
}

// findArbitrators searches for available arbitrators.
// Plutus.findArbitrators(category, chainID) -> profiles
func (b *jsBridge) findArbitrators(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		var category, chainID string
		if len(args) > 0 && !args[0].IsUndefined() {
			category = args[0].String()
		}
		if len(args) > 1 && !args[1].IsUndefined() {
			chainID = args[1].String()
		}

		profiles := b.arbRegistry.Find(category, chainID)

		data, err := json.Marshal(profiles)
		if err != nil {
			return nil, fmt.Errorf("findArbitrators: marshal profiles: %w", err)
		}

		return string(data), nil
	})
}

// ============================================================
//  Marketplace-facing wallet helpers
// ============================================================

// supportedChains is the canonical list of chain short-codes that the bridge
// exposes to marketplace-style JS callers. These are the short "ETH"/"SOL"
// style names the UI uses; the bridge maps them to internal chainIDs via
// normalizeChainID.
var supportedChains = []string{"ETH", "SOL", "BTC", "ARB", "POLYGON"}

// normalizeChainID maps a UI-facing short chain code to the internal chain ID
// used throughout the plutus packages.
func normalizeChainID(chain string) string {
	switch chain {
	case "ETH":
		return "ethereum"
	case "SOL":
		return "solana"
	case "BTC":
		return "bitcoin"
	case "ARB":
		return "arbitrum"
	case "POLYGON":
		return "polygon"
	default:
		return chain
	}
}

// denormalizeChainID returns the short code for an internal chainID.
func denormalizeChainID(chainID string) string {
	switch chainID {
	case "ethereum", "eth":
		return "ETH"
	case "solana", "sol":
		return "SOL"
	case "bitcoin", "btc":
		return "BTC"
	case "arbitrum":
		return "ARB"
	case "polygon", "matic":
		return "POLYGON"
	default:
		return chainID
	}
}

// chainCurrency returns the native/display currency for a chain code.
func chainCurrency(chain string) string {
	switch chain {
	case "ETH", "ARB":
		return "ETH"
	case "POLYGON":
		return "MATIC"
	case "SOL":
		return "SOL"
	case "BTC":
		return "BTC"
	default:
		return chain
	}
}

// defaultWalletHandle returns the most recently created wallet handle, or an
// error if none is unlocked. Mirrors the "default unlocked wallet" convention
// requested by the marketplace-facing JS API.
func (b *jsBridge) defaultWalletHandle() (int64, *walletState, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if len(b.wallets) == 0 {
		return 0, nil, fmt.Errorf("no wallet available; call Plutus.createWallet first")
	}
	var bestHandle int64
	for h := range b.wallets {
		if h > bestHandle {
			bestHandle = h
		}
	}
	return bestHandle, b.wallets[bestHandle], nil
}

// accountView is the JS-friendly representation of an account used by the
// marketplace wallet page.
type accountView struct {
	Handle       int64  `json:"handle"`
	ChainID      string `json:"chainID"`
	Chain        string `json:"chain"`
	Currency     string `json:"currency"`
	Address      string `json:"address"`
	Account      uint32 `json:"account"`
	Name         string `json:"name"`
	IdentityOnly bool   `json:"identityOnly"`
}

// collectAccounts returns a snapshot of every account across every chain on
// the default wallet. When no accounts have been explicitly created yet an
// identity-only record is returned so the UI can prompt the user to create
// their first chain account.
func (b *jsBridge) collectAccounts() ([]accountView, int64, error) {
	handle, ws, err := b.defaultWalletHandle()
	if err != nil {
		return nil, 0, err
	}

	b.mu.RLock()
	defer b.mu.RUnlock()

	var out []accountView
	if len(ws.accounts) == 0 {
		// Identity-only wallet: surface a synthetic record so the UI can
		// render the "no chain accounts yet" empty state.
		return out, handle, nil
	}

	for chainID, accts := range ws.accounts {
		short := denormalizeChainID(chainID)
		for _, a := range accts {
			out = append(out, accountView{
				Handle:       handle,
				ChainID:      chainID,
				Chain:        short,
				Currency:     chainCurrency(short),
				Address:      a.Address,
				Account:      a.Index,
				Name:         a.Name,
				IdentityOnly: false,
			})
		}
	}
	return out, handle, nil
}

// getAccounts returns an array of {handle, chainID, chain, currency, address,
// account, name, identityOnly, balance, balanceUsd} for every account on the
// default unlocked wallet.
// Plutus.getAccounts() -> Promise<Array>
func (b *jsBridge) getAccounts(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		views, _, err := b.collectAccounts()
		if err != nil {
			return nil, err
		}

		// Enrich with a balance string by querying the witness mesh for each
		// account. Queries run in parallel with a short timeout; on failure
		// we fall back to a zero-string display so the UI remains usable.
		type enriched struct {
			accountView
			Balance    string `json:"balance"`
			BalanceUsd string `json:"balanceUsd"`
			Icon       string `json:"icon"`
		}
		out := make([]enriched, len(views))
		var wg sync.WaitGroup
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		for i, v := range views {
			out[i] = enriched{accountView: v, Balance: "0 " + v.Currency, BalanceUsd: "", Icon: ""}
			if v.Address == "" {
				continue
			}
			wg.Add(1)
			go func(idx int, ac accountView) {
				defer wg.Done()
				result, err := b.balanceVerif.QueryBalance(ctx, witness.BalanceQuery{
					ChainID:       ac.ChainID,
					Address:       ac.Address,
					MaxAgeSeconds: 60,
				})
				if err == nil && result != nil {
					out[idx].Balance = formatBalance(result.Balance, result.Decimals) + " " + ac.Currency
				}
			}(i, v)
		}
		wg.Wait()

		data, err := json.Marshal(out)
		if err != nil {
			return nil, fmt.Errorf("getAccounts: marshal: %w", err)
		}
		return string(data), nil
	})
}

// getAccountsBridgeCreateAccount creates a new BIP44 account on the given chain
// for the default unlocked wallet. Arg: chain short-code (e.g. "ETH").
// Plutus.createAccountDefault(chain) -> Promise<account view>
//
// NOTE: this is registered as "createAccount" on the JS side via main.go in
// addition to the existing handle-taking createAccount; the JS dispatcher
// differentiates by arg shape (one string arg = marketplace flow, three args
// = legacy flow).
func (b *jsBridge) createAccountDefault(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 || args[0].IsNull() || args[0].IsUndefined() {
			return nil, fmt.Errorf("createAccount: requires chain")
		}
		chainShort := args[0].String()
		chainID := normalizeChainID(chainShort)

		handle, ws, err := b.defaultWalletHandle()
		if err != nil {
			return nil, err
		}

		b.mu.Lock()
		if ws.accounts == nil {
			ws.accounts = make(map[string][]wallet.WalletAccount)
		}
		idx := uint32(0)
		if existing := ws.accounts[chainID]; len(existing) > 0 {
			for _, a := range existing {
				if a.Index >= idx {
					idx = a.Index + 1
				}
			}
		}

		coinType := chainIDToCoinType(chainID)
		chainKey, err := wallet.DeriveChainKey(ws.seed, coinType, idx)
		if err != nil {
			b.mu.Unlock()
			return nil, fmt.Errorf("createAccount: %w", err)
		}

		addr := wallet.ChainAddress(chainKey)
		name := fmt.Sprintf("%s Account %d", chainShort, idx)
		acct := wallet.WalletAccount{
			Index:     idx,
			Name:      name,
			ChainID:   chainID,
			Address:   addr,
			CreatedAt: time.Now(),
		}
		ws.accounts[chainID] = append(ws.accounts[chainID], acct)
		b.mu.Unlock()

		b.publishState()

		view := accountView{
			Handle:   handle,
			ChainID:  chainID,
			Chain:    chainShort,
			Currency: chainCurrency(chainShort),
			Address:  addr,
			Account:  idx,
			Name:     name,
		}
		data, err := json.Marshal(view)
		if err != nil {
			return nil, fmt.Errorf("createAccount: marshal: %w", err)
		}
		return string(data), nil
	})
}

// sendFunds sends `amount` (native units, e.g. "1.5" ETH or "100" USDC) from
// the default account on `chain` to `to`. It builds an unsigned transfer tx,
// asks the Signer to validate + sign (which enforces wallet-level policy),
// then broadcasts via the witness mesh. In the WASM build there are no
// chain adapters available, so the transfer payload is a minimal canonical
// representation used for witness-mesh broadcast.
// Plutus.sendFunds(to, amount, chain) -> Promise<{id, txHash, chainID}>
func (b *jsBridge) sendFunds(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 3 {
			return nil, fmt.Errorf("sendFunds: requires to, amount, chain")
		}
		to := args[0].String()
		amountStr := args[1].String()
		chainShort := args[2].String()
		chainID := normalizeChainID(chainShort)
		currency := chainCurrency(chainShort)

		if to == "" {
			return nil, fmt.Errorf("sendFunds: recipient is empty")
		}

		// Parse amount as a decimal string. Accept integer or decimal forms.
		// We scale by 10^18 for EVM-like chains and 10^8 for BTC as a best
		// effort; the witness mesh is the source of truth for final units.
		scale := 18
		switch chainShort {
		case "BTC":
			scale = 8
		case "SOL":
			scale = 9
		}
		amountUnits, err := parseDecimal(amountStr, scale)
		if err != nil {
			return nil, fmt.Errorf("sendFunds: invalid amount %q: %w", amountStr, err)
		}

		_, ws, err := b.defaultWalletHandle()
		if err != nil {
			return nil, err
		}

		if ws.signer == nil {
			return nil, fmt.Errorf("sendFunds: wallet is not configured for signing")
		}

		// Build a canonical unsigned-transfer payload. The payload bytes are
		// what the Signer signs; the witness mesh interprets them chain-side.
		payload, err := json.Marshal(map[string]interface{}{
			"kind":     "transfer",
			"chainID":  chainID,
			"currency": currency,
			"to":       to,
			"amount":   amountUnits.String(),
			"ts":       time.Now().UnixNano(),
		})
		if err != nil {
			return nil, fmt.Errorf("sendFunds: build payload: %w", err)
		}

		unsigned := &adapter.UnsignedTx{
			ChainID: chainID,
			To:      to,
			Amount:  amountUnits,
			Payload: payload,
		}

		// Signer enforces wallet-level policy (not locked, valid amount,
		// valid recipient). Refuses to sign otherwise.
		signed, err := ws.signer.SignTransfer(unsigned)
		if err != nil {
			return nil, fmt.Errorf("sendFunds: signer refused: %w", err)
		}

		// Broadcast via the witness mesh. The signed envelope combines the
		// payload and signature so the mesh can verify origin.
		envelope, err := json.Marshal(map[string]interface{}{
			"payload":   payload,
			"signature": hex.EncodeToString(signed),
			"pubKey":    hex.EncodeToString(ws.identityKey.Public().(ed25519.PublicKey)),
		})
		if err != nil {
			return nil, fmt.Errorf("sendFunds: build envelope: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		txHash, err := b.broadcast.BroadcastTx(ctx, chainID, envelope)
		if err != nil {
			return nil, fmt.Errorf("sendFunds: broadcast: %w", err)
		}

		// Record into in-memory tx log for getTransactions().
		b.recordTx(txRecord{
			TxHash:       txHash,
			ChainID:      chainID,
			Chain:        chainShort,
			Direction:    "sent",
			Amount:       amountStr + " " + currency,
			Counterparty: to,
			Timestamp:    time.Now(),
			Status:       "pending",
		})

		b.publishState()

		resp := map[string]interface{}{
			"id":      txHash,
			"txHash":  txHash,
			"chainID": chainID,
			"chain":   chainShort,
		}
		data, err := json.Marshal(resp)
		if err != nil {
			return nil, fmt.Errorf("sendFunds: marshal: %w", err)
		}
		return string(data), nil
	})
}

// txRecord represents a single wallet transaction for UI display.
type txRecord struct {
	TxHash       string    `json:"txHash"`
	ChainID      string    `json:"chainID"`
	Chain        string    `json:"chain"`
	Direction    string    `json:"direction"`   // "sent" | "received"
	Amount       string    `json:"amount"`      // display string incl. currency
	Counterparty string    `json:"counterparty"`
	BlockNumber  uint64    `json:"blockNumber"`
	Timestamp    time.Time `json:"timestamp"`
	Status       string    `json:"status"`      // "pending" | "confirmed"
}

// recordTx appends to the in-memory tx log (kept simple: no persistence).
func (b *jsBridge) recordTx(rec txRecord) {
	b.mu.Lock()
	b.txLog = append(b.txLog, rec)
	b.mu.Unlock()
}

// getTransactions returns recent wallet activity. chainID is optional; when
// present (as a short code like "ETH") results are filtered to that chain.
// Returns a JS-friendly array sorted newest-first.
// Plutus.getTransactions(chain?) -> Promise<Array>
func (b *jsBridge) getTransactions(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		var filterChainID string
		if len(args) > 0 && !args[0].IsNull() && !args[0].IsUndefined() {
			filterChainID = normalizeChainID(args[0].String())
		}

		b.mu.RLock()
		records := make([]txRecord, 0, len(b.txLog))
		for _, r := range b.txLog {
			if filterChainID != "" && r.ChainID != filterChainID {
				continue
			}
			records = append(records, r)
		}
		b.mu.RUnlock()

		// Sort newest-first.
		for i := 0; i < len(records); i++ {
			for j := i + 1; j < len(records); j++ {
				if records[j].Timestamp.After(records[i].Timestamp) {
					records[i], records[j] = records[j], records[i]
				}
			}
		}

		// Render into the shape the marketplace UI consumes:
		// {id, type, amount, to, time, status}
		type view struct {
			ID          string `json:"id"`
			TxHash      string `json:"txHash"`
			ChainID     string `json:"chainID"`
			Chain       string `json:"chain"`
			Type        string `json:"type"`
			Direction   string `json:"direction"`
			Amount      string `json:"amount"`
			To          string `json:"to"`
			Counterparty string `json:"counterparty"`
			Time        string `json:"time"`
			Timestamp   int64  `json:"timestamp"`
			BlockNumber uint64 `json:"blockNumber"`
			Status      string `json:"status"`
		}

		out := make([]view, 0, len(records))
		for _, r := range records {
			out = append(out, view{
				ID:           r.TxHash,
				TxHash:       r.TxHash,
				ChainID:      r.ChainID,
				Chain:        r.Chain,
				Type:         r.Direction,
				Direction:    r.Direction,
				Amount:       r.Amount,
				To:           r.Counterparty,
				Counterparty: r.Counterparty,
				Time:         r.Timestamp.Format(time.RFC3339),
				Timestamp:    r.Timestamp.Unix(),
				BlockNumber:  r.BlockNumber,
				Status:       r.Status,
			})
		}

		data, err := json.Marshal(out)
		if err != nil {
			return nil, fmt.Errorf("getTransactions: marshal: %w", err)
		}
		return string(data), nil
	})
}

// getBalance returns the balance for a single account on a chain. address is
// optional and defaults to account index 0 on that chain. The WASM build has
// no direct chain RPC, so balance reads go through the witness-mesh balance
// verifier: it publishes a BalanceQuery, collects K-of-N signed
// BalanceAttestations, and returns the quorum-agreed value.
//
// PRIVACY NOTE: every witness that responds sees the queried address. v1 has
// no query mixing; see witness-balance-query-guide.md §Privacy.
//
// Plutus.getBalance(chain, address?) -> Promise<{chain, address, balance,
// balanceRaw, decimals, blockNumber, balanceUsd}>
func (b *jsBridge) getBalance(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		if len(args) < 1 {
			return nil, fmt.Errorf("getBalance: requires chain")
		}
		chainShort := args[0].String()
		chainID := normalizeChainID(chainShort)
		currency := chainCurrency(chainShort)

		_, ws, err := b.defaultWalletHandle()
		if err != nil {
			return nil, err
		}

		var addr string
		if len(args) > 1 && !args[1].IsNull() && !args[1].IsUndefined() {
			addr = args[1].String()
		} else {
			b.mu.RLock()
			if accts := ws.accounts[chainID]; len(accts) > 0 {
				addr = accts[0].Address
			}
			b.mu.RUnlock()
		}

		if addr == "" {
			return nil, fmt.Errorf("getBalance: no account on %s", chainShort)
		}

		// Query the witness mesh. On failure (no witnesses, timeout, no
		// quorum) fall back to a zero-string display so the UI stays usable.
		balanceStr := "0 " + currency
		balanceRaw := "0"
		var decimals uint64
		var blockNumber uint64
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		result, qErr := b.balanceVerif.QueryBalance(ctx, witness.BalanceQuery{
			ChainID:       chainID,
			Address:       addr,
			MaxAgeSeconds: 60,
		})
		if qErr == nil && result != nil {
			balanceRaw = result.Balance.String()
			decimals = result.Decimals
			blockNumber = result.BlockNumber
			balanceStr = formatBalance(result.Balance, result.Decimals) + " " + currency
		}

		resp := map[string]interface{}{
			"chain":       chainShort,
			"chainID":     chainID,
			"address":     addr,
			"currency":    currency,
			"balance":     balanceStr,
			"balanceRaw":  balanceRaw,
			"decimals":    decimals,
			"blockNumber": blockNumber,
			"balanceUsd":  "",
		}
		data, err := json.Marshal(resp)
		if err != nil {
			return nil, fmt.Errorf("getBalance: marshal: %w", err)
		}
		return string(data), nil
	})
}

// formatBalance renders a big.Int with the given decimal count as a
// human-friendly string with up to 6 fractional digits (trailing zeros
// trimmed). Used by getBalance / getTotalBalance to produce the UI display.
func formatBalance(amount *big.Int, decimals uint64) string {
	if amount == nil || amount.Sign() == 0 {
		return "0"
	}
	s := amount.String()
	if decimals == 0 {
		return s
	}
	d := int(decimals)
	if len(s) <= d {
		s = strings.Repeat("0", d-len(s)+1) + s
	}
	whole := s[:len(s)-d]
	frac := s[len(s)-d:]
	// Show at most 6 fractional digits.
	if len(frac) > 6 {
		frac = frac[:6]
	}
	// Trim trailing zeros.
	for len(frac) > 0 && frac[len(frac)-1] == '0' {
		frac = frac[:len(frac)-1]
	}
	if frac == "" {
		return whole
	}
	return whole + "." + frac
}

// getTotalBalance returns a chain-keyed balance map plus a human display
// string for the marketplace UI. Each balance comes from the witness-mesh
// BalanceVerifier; on failure we fall back to "0 <currency>" per account.
// USD conversion is not implemented in v1.
// Plutus.getTotalBalance() -> Promise<{perChain, display, usd, usdEquivalent}>
func (b *jsBridge) getTotalBalance(this js.Value, args []js.Value) interface{} {
	return promiseWrapper(func() (interface{}, error) {
		views, _, err := b.collectAccounts()
		if err != nil {
			return nil, err
		}

		perChain := make(map[string]string)
		var mu sync.Mutex
		var wg sync.WaitGroup
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		for _, v := range views {
			mu.Lock()
			perChain[v.Chain] = "0 " + v.Currency
			mu.Unlock()
			if v.Address == "" {
				continue
			}
			wg.Add(1)
			go func(ac accountView) {
				defer wg.Done()
				result, err := b.balanceVerif.QueryBalance(ctx, witness.BalanceQuery{
					ChainID:       ac.ChainID,
					Address:       ac.Address,
					MaxAgeSeconds: 60,
				})
				if err == nil && result != nil {
					mu.Lock()
					perChain[ac.Chain] = formatBalance(result.Balance, result.Decimals) + " " + ac.Currency
					mu.Unlock()
				}
			}(v)
		}
		wg.Wait()

		display := "0.00"
		if len(perChain) == 0 {
			display = "No accounts"
		}

		resp := map[string]interface{}{
			"perChain":      perChain,
			"display":       display,
			"usd":           "",
			"usdEquivalent": "",
		}
		data, err := json.Marshal(resp)
		if err != nil {
			return nil, fmt.Errorf("getTotalBalance: marshal: %w", err)
		}
		return string(data), nil
	})
}

// publishState synchronously publishes a snapshot of wallet state onto
// window.Plutus.state for reactive UI consumption. Mirrors the Mercury.state
// pattern.
func (b *jsBridge) publishState() {
	views, _, err := b.collectAccounts()
	if err != nil {
		// No wallet: clear state.
		state := js.Global().Get("Object").New()
		state.Set("accounts", js.Global().Get("Array").New())
		state.Set("totalBalance", js.Global().Get("Object").New())
		state.Set("defaultChain", "")
		plutus := js.Global().Get("Plutus")
		if !plutus.IsUndefined() && !plutus.IsNull() {
			plutus.Set("state", state)
		}
		return
	}

	// Accounts array
	accountsArr := js.Global().Get("Array").New()
	defaultChain := ""
	for i, v := range views {
		item := js.Global().Get("Object").New()
		item.Set("handle", float64(v.Handle))
		item.Set("chainID", v.ChainID)
		item.Set("chain", v.Chain)
		item.Set("currency", v.Currency)
		item.Set("address", v.Address)
		item.Set("account", float64(v.Account))
		item.Set("name", v.Name)
		item.Set("identityOnly", v.IdentityOnly)
		accountsArr.SetIndex(i, item)
		if defaultChain == "" {
			defaultChain = v.Chain
		}
	}

	// Total balance map: seed with zero strings; the 30s refresh goroutine
	// (see balanceRefreshLoop) will overwrite with real values from the
	// witness mesh. Keeping publishState fully synchronous avoids blocking
	// the UI on a mesh roundtrip.
	totalBalance := js.Global().Get("Object").New()
	for _, v := range views {
		if cached := b.balanceVerif.QueryCached(v.ChainID, v.Address, ""); cached != nil {
			totalBalance.Set(v.Chain, formatBalance(cached.Balance, cached.Decimals)+" "+v.Currency)
		} else {
			totalBalance.Set(v.Chain, "0 "+v.Currency)
		}
	}
	totalBalance.Set("usdEquivalent", "")

	state := js.Global().Get("Object").New()
	state.Set("accounts", accountsArr)
	state.Set("totalBalance", totalBalance)
	state.Set("defaultChain", defaultChain)

	plutus := js.Global().Get("Plutus")
	if !plutus.IsUndefined() && !plutus.IsNull() {
		plutus.Set("state", state)
	}
}

// parseDecimal parses a decimal string like "1.5" into an integer with the
// given number of fractional digits (e.g. scale=18 -> wei).
func parseDecimal(s string, scale int) (*big.Int, error) {
	if s == "" {
		return nil, fmt.Errorf("empty")
	}
	// Split on '.'
	whole := s
	frac := ""
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			whole = s[:i]
			frac = s[i+1:]
			break
		}
	}
	if len(frac) > scale {
		frac = frac[:scale]
	}
	for len(frac) < scale {
		frac += "0"
	}
	combined := whole + frac
	// Strip leading zeros but keep at least one digit.
	i := 0
	for i < len(combined)-1 && combined[i] == '0' {
		i++
	}
	combined = combined[i:]
	n, ok := new(big.Int).SetString(combined, 10)
	if !ok {
		return nil, fmt.Errorf("not a decimal number")
	}
	return n, nil
}

// --- Helper types for WASM bridge ---

// wasmMeshVerifier implements escrow.MeshVerifier for the WASM bridge.
type wasmMeshVerifier struct {
	bridge *jsBridge
}

func (v *wasmMeshVerifier) IsConfirmed(ctx context.Context, chainID string, txHash string) (bool, error) {
	policy := witness.PolicyForValue(50)
	return v.bridge.verifier.IsConfirmed(ctx, chainID, txHash, policy)
}

func (v *wasmMeshVerifier) AttestEscrowState(ctx context.Context, chainID string, escrowAddr string) (*escrow.EscrowSnapshot, error) {
	snap, err := v.bridge.verifier.AttestEscrowState(ctx, chainID, escrowAddr)
	if err != nil {
		return nil, err
	}
	// Convert witness.EscrowSnapshot to escrow.EscrowSnapshot
	return &escrow.EscrowSnapshot{
		ChainID:      chainID,
		EscrowAddr:   escrowAddr,
		State:        escrow.OnChainEscrowState{
			Buyer:        snap.Buyer,
			Seller:       snap.Seller,
			Arbitrator:   snap.Arbitrator,
			Amount:       snap.Amount,
			Funded:       snap.Status == witness.EscrowSnapshotStatusFunded,
			Released:     snap.Status == witness.EscrowSnapshotStatusReleased,
			Disputed:     snap.Status == witness.EscrowSnapshotStatusDisputed,
			Settled:      snap.Status == witness.EscrowSnapshotStatusSettled,
			TimeoutBlock: snap.TimeoutAt,
		},
		AttestedAt:   time.Now(),
		WitnessCount: 1,
		Quorum:       true,
	}, nil
}

func (v *wasmMeshVerifier) BroadcastTx(ctx context.Context, chainID string, signedTx []byte) (string, error) {
	return v.bridge.broadcast.BroadcastTx(ctx, chainID, signedTx)
}

// wasmWallet implements escrow.Wallet for the WASM bridge.
type wasmWallet struct {
	bridge       *jsBridge
	walletHandle int64
}

func (w *wasmWallet) PublicKey() ed25519.PublicKey {
	w.bridge.mu.RLock()
	ws := w.bridge.wallets[w.walletHandle]
	w.bridge.mu.RUnlock()
	return ws.identityKey.Public().(ed25519.PublicKey)
}

func (w *wasmWallet) ChainAddress(chainID string) (string, error) {
	w.bridge.mu.RLock()
	ws := w.bridge.wallets[w.walletHandle]
	w.bridge.mu.RUnlock()

	coinType := chainIDToCoinType(chainID)
	chainKey, err := wallet.DeriveChainKey(ws.seed, coinType, 0)
	if err != nil {
		return "", err
	}
	return wallet.ChainAddress(chainKey), nil
}

func (w *wasmWallet) SignEscrowFunding(tx *escrow.UnsignedTx) ([]byte, error) {
	w.bridge.mu.RLock()
	ws := w.bridge.wallets[w.walletHandle]
	w.bridge.mu.RUnlock()
	return ed25519.Sign(ws.identityKey, tx.Data), nil
}

func (w *wasmWallet) SignSettlement(tx *escrow.UnsignedTx, expectedFees escrow.FeeBreakdown) ([]byte, error) {
	w.bridge.mu.RLock()
	ws := w.bridge.wallets[w.walletHandle]
	w.bridge.mu.RUnlock()

	// Delegate to the real Signer which enforces PRC fee validation.
	// If the signer is nil (PRC not configured in WASM context), refuse to
	// sign rather than bypassing fee enforcement.
	if ws.signer == nil {
		return nil, fmt.Errorf("plutus: wallet not configured for settlement signing")
	}

	adapterFees := adapter.FeeBreakdown{
		MaintainerFee:      expectedFees.MaintainerFee,
		ServiceProviderFee: expectedFees.ServiceProviderFee,
		ArbitratorFee:      expectedFees.ArbitratorFee,
		WitnessFee:         expectedFees.WitnessFee,
		SellerProceeds:     expectedFees.SellerProceeds,
		Total:              expectedFees.Total,
	}
	adapterTx := &adapter.UnsignedTx{
		ChainID: tx.ChainID,
		To:      tx.To,
		Amount:  tx.Value,
		Payload: tx.Data,
	}
	return ws.signer.SignSettlement(adapterTx, adapterFees)
}

func (w *wasmWallet) SignDispute(tx *escrow.UnsignedTx) ([]byte, error) {
	w.bridge.mu.RLock()
	ws := w.bridge.wallets[w.walletHandle]
	w.bridge.mu.RUnlock()
	return ed25519.Sign(ws.identityKey, tx.Data), nil
}

// wasmAdapterResolver is a no-op adapter resolver for the WASM bridge.
// In the browser, actual chain interaction happens via the witness mesh,
// not direct RPC. The adapter is only needed for TX construction.
type wasmAdapterResolver struct{}

func (r *wasmAdapterResolver) Resolve(chainID, currency string) (escrow.CurrencyAdapter, error) {
	return nil, fmt.Errorf("plutus/wasm: chain adapters not available in WASM; use witness mesh for chain operations")
}

// wasmFeeCalculator adapts settle.FeeCalculator to escrow.FeeCalculator
// for the WASM bridge context.
type wasmFeeCalculator struct {
	calc *settle.FeeCalculator
}

func (c *wasmFeeCalculator) Calculate(amount *big.Int, opts escrow.FeeOptions) (escrow.FeeBreakdown, error) {
	if c.calc == nil {
		c.calc = settle.NewFeeCalculator()
	}
	adapterOpts := adapter.FeeOptions{
		MaintainerBPS:      opts.MaintainerBPS,
		HasServiceProvider: opts.HasServiceProvider,
		ServiceProviderBPS: opts.ServiceProviderBPS,
		HasDispute:         opts.HasDispute,
		ArbitratorBPS:      opts.ArbitratorBPS,
		HasWitness:         opts.HasWitness,
		WitnessBPS:         opts.WitnessBPS,
	}
	result, err := c.calc.Calculate(amount, adapterOpts)
	if err != nil {
		return escrow.FeeBreakdown{}, err
	}
	return escrow.FeeBreakdown{
		MaintainerFee:      result.MaintainerFee,
		ServiceProviderFee: result.ServiceProviderFee,
		ArbitratorFee:      result.ArbitratorFee,
		WitnessFee:         result.WitnessFee,
		SellerProceeds:     result.SellerProceeds,
		Total:              result.Total,
	}, nil
}

// --- Utility functions ---

// chainIDToCoinType maps chain IDs to BIP44 coin types.
func chainIDToCoinType(chainID string) uint32 {
	switch chainID {
	case "ethereum", "eth":
		return 60
	case "polygon", "matic":
		return 966
	case "bitcoin", "btc":
		return 0
	case "solana", "sol":
		return 501
	case "avalanche", "avax":
		return 9005
	default:
		return 60 // default to Ethereum
	}
}

// toJSValue converts a Go value to a JS value.
func toJSValue(v interface{}) interface{} {
	if v == nil {
		return js.Null()
	}
	switch val := v.(type) {
	case string:
		return val
	case int64:
		return val
	case float64:
		return val
	case bool:
		return val
	default:
		// JSON-encode complex types
		data, err := json.Marshal(v)
		if err != nil {
			return js.Null()
		}
		return string(data)
	}
}

// marshalEscrowState converts an EscrowState to a JSON string for JS consumption.
func marshalEscrowState(state *escrow.EscrowState) string {
	data, err := json.Marshal(map[string]interface{}{
		"address":      state.Address,
		"chainId":      state.ChainID,
		"buyer":        state.Buyer,
		"seller":       state.Seller,
		"arbitrator":   state.Arbitrator,
		"amount":       state.Amount.String(),
		"status":       string(state.Status),
		"funded":       state.Funded,
		"released":     state.Released,
		"disputed":     state.Disputed,
		"settled":      state.Settled,
		"timedOut":     state.TimedOut,
		"timeoutBlock": state.TimeoutBlock,
		"currentBlock": state.CurrentBlock,
		"witnessCount": state.WitnessCount,
		"quorum":       state.Quorum,
	})
	if err != nil {
		return "{}"
	}
	return string(data)
}
