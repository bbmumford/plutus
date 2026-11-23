/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// NeutrinoClient is the minimal subset of the embedded Neutrino SPV needed
// by ChainPoolBalanceProvider. Implementations live alongside the Neutrino
// wiring in mercury-node / mesh_embed. Kept small so tests can substitute a
// pure-Go fake.
type NeutrinoClient interface {
	// Balance returns the current confirmed balance for addr in satoshis.
	Balance(ctx context.Context, address string) (*big.Int, error)
}

// ErrPortalNetworkPending is returned by ChainPoolBalanceProvider for EVM
// chains until the Portal Network client is wired up. Per mercury DESIGN §4
// EVM witnessing is inactive at M4-M15; the fee distributor can still group
// EVM earnings and produce signed payout txs, but cannot automatically cap
// them against a pool balance without an on-chain balance source.
//
// Callers that observe this error should skip the balance cap for the group
// and proceed with builder-emitted payouts; the distributor's Run() path
// already tolerates a nil return from PoolBalance (best-effort cap).
var ErrPortalNetworkPending = errors.New(
	"witness/pool_balance_provider: EVM pool balance unavailable — Portal Network client not yet wired (mercury DESIGN §4)",
)

// ChainPoolBalanceProvider satisfies PoolBalanceProvider. It resolves balances
// for BTC-family chains through an embedded Neutrino SPV and returns
// ErrPortalNetworkPending for every EVM chain.
//
// A nil NeutrinoClient disables the BTC branch (a deliberate choice for
// client-only deployments); callers that need BTC pool-balance caps must
// construct the provider with a live client.
type ChainPoolBalanceProvider struct {
	neutrino NeutrinoClient
	// poolAddresses maps chainID → the on-chain address whose balance
	// represents the maintainer pool for that chain. Required because
	// PoolBalanceProvider.PoolBalance receives only chainID/currency, not the
	// address.
	poolAddresses map[string]string
}

// ChainPoolBalanceProviderConfig configures a new provider.
type ChainPoolBalanceProviderConfig struct {
	// Neutrino is the BIP157/158 SPV client used for BTC-family balance
	// queries. May be nil in deployments that don't witness BTC.
	Neutrino NeutrinoClient
	// PoolAddresses maps chainID → pool address. Typically the same map
	// passed into FeeDistributorConfig.PoolAddresses.
	PoolAddresses map[string]string
}

// NewChainPoolBalanceProvider returns a provider with cfg. It does not copy
// PoolAddresses — callers must not mutate the map after construction.
func NewChainPoolBalanceProvider(cfg ChainPoolBalanceProviderConfig) *ChainPoolBalanceProvider {
	pools := cfg.PoolAddresses
	if pools == nil {
		pools = make(map[string]string)
	}
	return &ChainPoolBalanceProvider{
		neutrino:      cfg.Neutrino,
		poolAddresses: pools,
	}
}

// PoolBalance satisfies PoolBalanceProvider.
//
// Routing rules:
//
//   - BTC-family chainIDs (bitcoin, bitcoin-testnet, bitcoin-regtest) →
//     delegate to neutrino.Balance(poolAddress). Returns an error when the
//     provider was constructed without a Neutrino client.
//   - Everything else → ErrPortalNetworkPending.
//
// The `currency` argument is accepted for interface conformance; BTC-family
// queries ignore non-BTC currencies (the pool address is per-chain, not
// per-token), and EVM queries short-circuit before inspecting it.
func (p *ChainPoolBalanceProvider) PoolBalance(ctx context.Context, chainID, currency string) (*big.Int, error) {
	if p == nil {
		return nil, errors.New("witness/pool_balance_provider: nil receiver")
	}

	if isBTCChain(chainID) {
		if p.neutrino == nil {
			return nil, fmt.Errorf("witness/pool_balance_provider: no Neutrino client for BTC chain %q", chainID)
		}
		addr, ok := p.poolAddresses[chainID]
		if !ok || addr == "" {
			return nil, fmt.Errorf("witness/pool_balance_provider: no pool address configured for chain %q", chainID)
		}
		bal, err := p.neutrino.Balance(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("witness/pool_balance_provider: neutrino balance for %s: %w", addr, err)
		}
		return bal, nil
	}

	// Every non-BTC chainID is treated as EVM today.
	return nil, ErrPortalNetworkPending
}

// isBTCChain reports whether chainID names a Bitcoin-family chain. Matches
// the canonical IDs emitted by the BTC payout builder
// (bitcoin / bitcoin-testnet / bitcoin-regtest) and is case-insensitive so
// operator-written configs don't trip over capitalization.
func isBTCChain(chainID string) bool {
	switch strings.ToLower(chainID) {
	case "bitcoin", "btc", "bitcoin-testnet", "bitcoin-regtest", "bitcoin-signet":
		return true
	}
	return false
}
