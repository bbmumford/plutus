/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/bbmumford/plutus/witness"
)

// knownTokenDecimals lists the hardcoded decimal counts for well-known ERC20
// tokens, keyed by lowercase contract address. Mapping via contract address
// (not symbol) because the same symbol may collide across chains. Tokens not
// in this table fall back to an on-chain decimals() call with per-token
// caching (see EVMBalanceProvider.resolveDecimals).
var knownTokenDecimals = map[string]uint64{
	// USDC — 6 decimals on every chain we deploy on.
	"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": 6, // Ethereum USDC
	"0x2791bca1f2de4661ed88a30c99a7a9449aa84174": 6, // Polygon USDC
	"0xaf88d065e77c8cc2239327c5edb3a432268e5831": 6, // Arbitrum USDC
	"0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d": 6, // BSC USDC
	// USDT — 6 decimals on Ethereum/Arbitrum, 18 on BSC (deliberately excluded
	// so the on-chain decimals() fallback picks up the right value).
	"0xdac17f958d2ee523a2206206994597c13d831ec7": 6, // Ethereum USDT
	// DAI — 18 decimals.
	"0x6b175474e89094c44da98b954eedeac495271d0f": 18, // Ethereum DAI
}

// EVMBalanceProvider implements witness.ChainBalanceProvider for EVM chains.
// A provider is bound to a single chain (via its EVMClient); witnesses that
// serve multiple EVM chains register one provider per chain.
type EVMBalanceProvider struct {
	client         *EVMClient
	nativeDecimals uint64

	mu            sync.Mutex
	decimalsCache map[string]uint64 // lowercased token contract -> decimals
}

// NewEVMBalanceProvider constructs a provider using the given EVMClient. The
// nativeDecimals argument controls how many decimals the native asset uses
// (18 for ETH/MATIC/BNB; pass 18 for all current EVM chains).
func NewEVMBalanceProvider(client *EVMClient, nativeDecimals uint64) (*EVMBalanceProvider, error) {
	if client == nil {
		return nil, errors.New("evm/balance: client is nil")
	}
	if nativeDecimals == 0 {
		nativeDecimals = 18
	}
	return &EVMBalanceProvider{
		client:         client,
		nativeDecimals: nativeDecimals,
		decimalsCache:  make(map[string]uint64),
	}, nil
}

// QueryBalance returns the current balance snapshot for (addr, token). token
// is empty for the native asset. For ERC20s, ABI-encodes balanceOf(address)
// and calls it via eth_call through the mesh-backed EVMClient.
func (p *EVMBalanceProvider) QueryBalance(ctx context.Context, addr, token string) (witness.BalanceSnapshot, error) {
	if addr == "" {
		return witness.BalanceSnapshot{}, errors.New("evm/balance: address is empty")
	}

	var balance *big.Int
	var decimals uint64
	var err error

	if token == "" {
		balance, err = p.client.GetBalance(ctx, addr)
		if err != nil {
			return witness.BalanceSnapshot{}, fmt.Errorf("evm/balance: native: %w", err)
		}
		decimals = p.nativeDecimals
	} else {
		erc20, err := NewERC20(p.client, token)
		if err != nil {
			return witness.BalanceSnapshot{}, fmt.Errorf("evm/balance: erc20 init: %w", err)
		}
		balance, err = erc20.BalanceOf(ctx, addr)
		if err != nil {
			return witness.BalanceSnapshot{}, fmt.Errorf("evm/balance: balanceOf: %w", err)
		}
		decimals, err = p.resolveDecimals(ctx, token)
		if err != nil {
			return witness.BalanceSnapshot{}, fmt.Errorf("evm/balance: decimals: %w", err)
		}
	}

	blockNumber, err := p.client.BlockNumber(ctx)
	if err != nil {
		return witness.BalanceSnapshot{}, fmt.Errorf("evm/balance: block number: %w", err)
	}

	return witness.BalanceSnapshot{
		Balance:     balance,
		Decimals:    decimals,
		BlockHash:   "", // getBlockByNumber would cost another RPC call; block_number alone is enough for quorum bucketing
		BlockNumber: blockNumber,
		Timestamp:   time.Now(),
	}, nil
}

// resolveDecimals returns the decimal count for an ERC20 contract, using the
// hardcoded knownTokenDecimals map first and falling back to an on-chain
// decimals() call (cached per contract). This minimizes RPC calls for the
// common case of querying USDC/USDT/DAI balances.
func (p *EVMBalanceProvider) resolveDecimals(ctx context.Context, token string) (uint64, error) {
	key := strings.ToLower(token)
	if d, ok := knownTokenDecimals[key]; ok {
		return d, nil
	}

	p.mu.Lock()
	if d, ok := p.decimalsCache[key]; ok {
		p.mu.Unlock()
		return d, nil
	}
	p.mu.Unlock()

	erc20, err := NewERC20(p.client, token)
	if err != nil {
		return 0, err
	}
	d8, err := erc20.Decimals(ctx)
	if err != nil {
		return 0, err
	}
	d := uint64(d8)

	p.mu.Lock()
	p.decimalsCache[key] = d
	p.mu.Unlock()
	return d, nil
}
