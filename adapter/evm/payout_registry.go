/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

import (
	"fmt"
	"strings"
	"sync"

	"github.com/bbmumford/plutus/adapter"
	"github.com/bbmumford/plutus/witness"
)

// PayoutBuilderRegistry maps (chainID, currency) -> witness.PayoutBuilder and
// satisfies witness.AdapterResolver. It lives alongside adapter.Registry
// rather than inside it because witness.PayoutBuilder is a narrower, separate
// concern from the full CurrencyAdapter interface — not every adapter ever
// needs to build witness-fee batches (e.g. read-only observer chains).
//
// Both EVM and BTC builders register into this same registry. If both agents
// need to coordinate on a shared instance, the caller constructs one and
// passes it to each package's Register* function.
type PayoutBuilderRegistry struct {
	mu       sync.RWMutex
	builders map[string]witness.PayoutBuilder
}

// NewPayoutBuilderRegistry returns an empty registry.
func NewPayoutBuilderRegistry() *PayoutBuilderRegistry {
	return &PayoutBuilderRegistry{
		builders: make(map[string]witness.PayoutBuilder),
	}
}

// Register associates a PayoutBuilder with a (chainID, currency) pair.
// Subsequent Register calls for the same key overwrite the prior entry so
// tests can swap implementations without a tear-down hook.
func (r *PayoutBuilderRegistry) Register(chainID, currency string, b witness.PayoutBuilder) error {
	if b == nil {
		return fmt.Errorf("evm/payout_registry: builder is nil")
	}
	if chainID == "" || currency == "" {
		return fmt.Errorf("evm/payout_registry: chainID and currency required")
	}
	key := payoutKey(chainID, currency)
	r.mu.Lock()
	r.builders[key] = b
	r.mu.Unlock()
	return nil
}

// ResolvePayoutBuilder implements witness.AdapterResolver.
func (r *PayoutBuilderRegistry) ResolvePayoutBuilder(chainID, currency string) (witness.PayoutBuilder, error) {
	key := payoutKey(chainID, currency)
	r.mu.RLock()
	b, ok := r.builders[key]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("evm/payout_registry: no payout builder for %s/%s", chainID, currency)
	}
	return b, nil
}

// List returns the keys (in "chainID/currency" form) of all registered
// builders. Used for smoke-test and admin introspection.
func (r *PayoutBuilderRegistry) List() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	keys := make([]string, 0, len(r.builders))
	for k := range r.builders {
		keys = append(keys, k)
	}
	return keys
}

func payoutKey(chainID, currency string) string {
	return strings.ToLower(chainID) + "/" + strings.ToUpper(currency)
}

// --- default wiring --------------------------------------------------

// DefaultEVMPayoutBuilderEntry describes one (chainID, currency) pair that
// should be registered with the default builder set. Exposed so operators
// can extend the defaults via their own factory wrapper.
type DefaultEVMPayoutBuilderEntry struct {
	ChainID      string
	EVMChainID   uint64
	Currency     string
	IsERC20      bool
	TokenAddress string
}

// DefaultEVMPayoutBuilders is the set of (chainID, currency) pairs that
// mirror chains.json. Currencies beyond these can be added by extending this
// slice (or by calling registry.Register directly).
var DefaultEVMPayoutBuilders = []DefaultEVMPayoutBuilderEntry{
	// Native-currency payouts.
	{ChainID: "polygon", EVMChainID: 137, Currency: "POL", IsERC20: false},
	{ChainID: "polygon", EVMChainID: 137, Currency: "MATIC", IsERC20: false}, // legacy name
	{ChainID: "ethereum", EVMChainID: 1, Currency: "ETH", IsERC20: false},
	{ChainID: "arbitrum", EVMChainID: 42161, Currency: "ETH", IsERC20: false},
	{ChainID: "bsc", EVMChainID: 56, Currency: "BNB", IsERC20: false},

	// ERC20 payouts (token addresses mirrored from chains.json).
	{ChainID: "polygon", EVMChainID: 137, Currency: "USDC", IsERC20: true, TokenAddress: "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"},
	{ChainID: "ethereum", EVMChainID: 1, Currency: "USDC", IsERC20: true, TokenAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"},
	{ChainID: "arbitrum", EVMChainID: 42161, Currency: "USDC", IsERC20: true, TokenAddress: "0xaf88d065e77c8cC2239327C5EDb3A432268e5831"},
	{ChainID: "bsc", EVMChainID: 56, Currency: "BUSD", IsERC20: true, TokenAddress: "0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56"},
}

// RegisterDefaultEVMPayoutBuilders populates `reg` with a builder for each
// entry in DefaultEVMPayoutBuilders. Returns the first error encountered.
//
// Prefer RegisterDefaultEVMPayoutBuildersInto when integrating with the
// shared *adapter.Registry used elsewhere in Plutus — it keeps BTC and EVM
// builders in one lookup so witness.AdapterResolver callers see both.
func RegisterDefaultEVMPayoutBuilders(reg *PayoutBuilderRegistry) error {
	if reg == nil {
		return fmt.Errorf("evm/payout_registry: registry is nil")
	}
	for _, e := range DefaultEVMPayoutBuilders {
		b, err := NewEVMPayoutBuilder(EVMPayoutBuilderConfig{
			ChainID:      e.ChainID,
			EVMChainID:   e.EVMChainID,
			Currency:     e.Currency,
			IsERC20:      e.IsERC20,
			TokenAddress: e.TokenAddress,
		})
		if err != nil {
			return fmt.Errorf("evm/payout_registry: build %s/%s: %w", e.ChainID, e.Currency, err)
		}
		if err := reg.Register(e.ChainID, e.Currency, b); err != nil {
			return fmt.Errorf("evm/payout_registry: register %s/%s: %w", e.ChainID, e.Currency, err)
		}
	}
	return nil
}

// RegisterDefaultEVMPayoutBuildersInto attaches the DefaultEVMPayoutBuilders
// entries to the shared *adapter.Registry via its RegisterPayoutBuilder API.
// Pair this with btc.RegisterBitcoinPayoutBuilder to populate a single
// registry with both BTC and EVM payout builders; PlutusSDK's
// WitnessPayoutResolver then resolves them uniformly for the fee
// distributor.
//
// PRC addresses are not populated on this path — callers that want the
// DESIGN §17 first-writer-wins entry point (PRC.distributeWindow) should
// use RegisterDefaultEVMPayoutBuildersIntoWithPRC instead.
func RegisterDefaultEVMPayoutBuildersInto(reg *adapter.Registry) error {
	return RegisterDefaultEVMPayoutBuildersIntoWithPRC(reg, nil)
}

// RegisterDefaultEVMPayoutBuildersIntoWithPRC is the PRC-aware variant of
// RegisterDefaultEVMPayoutBuildersInto. `prcAddresses` maps chainID → PRC
// contract hex address; entries with a non-empty value cause the built
// EVMPayoutBuilder to target PRC.distributeWindow on the window-aware path
// (see BuildWindowedBatchPayout), enabling DESIGN §17 first-writer-wins.
//
// Pass nil to disable the PRC path entirely (equivalent to the no-PRC
// helper). Entries missing from the map keep PRCAddress empty on their
// builder, which is the safe default (falls back to Multicall3).
func RegisterDefaultEVMPayoutBuildersIntoWithPRC(reg *adapter.Registry, prcAddresses map[string]string) error {
	if reg == nil {
		return fmt.Errorf("evm/payout_registry: adapter registry is nil")
	}
	for _, e := range DefaultEVMPayoutBuilders {
		prc := ""
		if prcAddresses != nil {
			prc = prcAddresses[e.ChainID]
		}
		b, err := NewEVMPayoutBuilder(EVMPayoutBuilderConfig{
			ChainID:      e.ChainID,
			EVMChainID:   e.EVMChainID,
			Currency:     e.Currency,
			IsERC20:      e.IsERC20,
			TokenAddress: e.TokenAddress,
			PRCAddress:   prc,
		})
		if err != nil {
			return fmt.Errorf("evm/payout_registry: build %s/%s: %w", e.ChainID, e.Currency, err)
		}
		if err := reg.RegisterPayoutBuilder(e.ChainID, e.Currency, b); err != nil {
			return fmt.Errorf("evm/payout_registry: register %s/%s: %w", e.ChainID, e.Currency, err)
		}
	}
	return nil
}
