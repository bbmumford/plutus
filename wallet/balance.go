/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package wallet

import (
	"context"
	"errors"
	"fmt"
	"math/big"

	"github.com/bbmumford/plutus/witness"
)

// BalanceQuerier is the minimal surface of witness.BalanceVerifier that Wallet
// needs for balance reads. Declared here (rather than importing the concrete
// verifier) so the wallet package stays decoupled from the full verifier
// lifecycle — callers can inject a stub in tests.
type BalanceQuerier interface {
	QueryBalance(ctx context.Context, q witness.BalanceQuery) (*witness.BalanceResult, error)
}

// AttachBalanceVerifier wires a BalanceQuerier (typically
// *witness.BalanceVerifier) onto the wallet so that Wallet.Balance works.
// Safe to call multiple times; the most recent querier wins.
//
// This is called by the PlutusSDK after both Wallet and BalanceVerifier are
// constructed. Wallets used in isolation (no SDK) can skip this — Balance
// will return an explicit error instead of a panic.
func (w *Wallet) AttachBalanceVerifier(q BalanceQuerier) {
	w.mu.Lock()
	w.balanceQuerier = q
	w.mu.Unlock()
}

// Balance returns the current on-chain balance for the given account, as
// reported by the witness mesh. Returns the big-int balance in the chain's
// smallest unit (wei/sats) together with its decimal count so the caller can
// render a human-friendly string.
//
// PRIVACY NOTE: every witness that responds sees (chainID, address,
// token); the query mixes in no dummy addresses. Callers
// wishing to hide an address should use a derived per-order address.
func (w *Wallet) Balance(ctx context.Context, account WalletAccount) (*big.Int, uint64, error) {
	if account.ChainID == "" {
		return nil, 0, errors.New("plutus/wallet: account chainID required")
	}
	if account.Address == "" {
		return nil, 0, errors.New("plutus/wallet: account address required")
	}

	w.mu.RLock()
	querier := w.balanceQuerier
	w.mu.RUnlock()
	if querier == nil {
		return nil, 0, errors.New("plutus/wallet: no BalanceVerifier attached (call AttachBalanceVerifier)")
	}

	result, err := querier.QueryBalance(ctx, witness.BalanceQuery{
		ChainID:       account.ChainID,
		Address:       account.Address,
		Token:         "", // native; callers that need ERC20 should use BalanceForToken
		MaxAgeSeconds: 60,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("plutus/wallet: balance query: %w", err)
	}
	return result.Balance, result.Decimals, nil
}

// BalanceForToken is the ERC20 / contract-token variant of Balance. Passing
// an empty token is equivalent to Balance (native asset). Kept as a separate
// method so the common native-asset call stays a clean two-arg signature.
func (w *Wallet) BalanceForToken(ctx context.Context, account WalletAccount, token string) (*big.Int, uint64, error) {
	w.mu.RLock()
	querier := w.balanceQuerier
	w.mu.RUnlock()
	if querier == nil {
		return nil, 0, errors.New("plutus/wallet: no BalanceVerifier attached")
	}
	result, err := querier.QueryBalance(ctx, witness.BalanceQuery{
		ChainID:       account.ChainID,
		Address:       account.Address,
		Token:         token,
		MaxAgeSeconds: 60,
	})
	if err != nil {
		return nil, 0, fmt.Errorf("plutus/wallet: balance query: %w", err)
	}
	return result.Balance, result.Decimals, nil
}
