/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package escrow

import (
	"context"
	"fmt"
	"time"

	"github.com/bbmumford/plutus/observability"
	"go.opentelemetry.io/otel/attribute"
)

// Fund creates and funds an escrow on-chain.
//
// Orchestration steps:
//  1. Resolve the CurrencyAdapter for the requested chain+currency
//  2. Derive the buyer's chain address from the wallet
//  3. Construct the escrow creation TX via the adapter
//  4. Sign the TX via the wallet (fee enforcement applied)
//  5. Broadcast the signed TX via witnesses (MeshVerifier)
//  6. Wait for witness confirmation of the TX
//  7. Track the escrow instance locally
func (m *EscrowManager) Fund(ctx context.Context, params FundParams) (*EscrowInstance, error) {
	ctx, span := observability.Tracer("plutus.escrow").Start(ctx, "EscrowManager.Fund")
	defer span.End()
	span.SetAttributes(
		attribute.String(observability.AttrChainID, params.ChainID),
		attribute.String(observability.AttrCurrency, params.Currency),
	)
	start := time.Now()
	defer func() {
		observability.EscrowFundDuration().Record(ctx, float64(time.Since(start).Milliseconds()),
			observability.AttrSet(attribute.String(observability.AttrChainID, params.ChainID)))
	}()

	if params.Amount == nil || params.Amount.Sign() <= 0 {
		err := fmt.Errorf("escrow: fund amount must be positive")
		observability.RecordError(span, err)
		return nil, err
	}
	if params.Buyer == "" {
		err := fmt.Errorf("escrow: buyer address required")
		observability.RecordError(span, err)
		return nil, err
	}
	if params.Seller == "" {
		err := fmt.Errorf("escrow: seller address required")
		observability.RecordError(span, err)
		return nil, err
	}
	if params.Currency == "" {
		err := fmt.Errorf("escrow: currency required")
		observability.RecordError(span, err)
		return nil, err
	}
	if params.ChainID == "" {
		err := fmt.Errorf("escrow: chain ID required")
		observability.RecordError(span, err)
		return nil, err
	}
	if params.TimeoutBlocks == 0 {
		err := fmt.Errorf("escrow: timeout blocks must be > 0")
		observability.RecordError(span, err)
		return nil, err
	}

	// Step 1: Resolve adapter
	adapter, err := m.adapters.Resolve(params.ChainID, params.Currency)
	if err != nil {
		wrapped := fmt.Errorf("escrow: no adapter for %s/%s: %w", params.ChainID, params.Currency, err)
		observability.RecordError(span, wrapped)
		return nil, wrapped
	}

	// Step 2: Construct escrow TX via adapter
	constructParams := EscrowConstructParams{
		Amount:        params.Amount,
		Buyer:         params.Buyer,
		Seller:        params.Seller,
		Arbitrator:    params.Arbitrator,
		TimeoutBlocks: params.TimeoutBlocks,
		ReceiptHashes: params.ReceiptHashes,
		WitnessHashes: params.WitnessHashes,
		AppID:         params.AppID,
	}

	unsignedTx, err := adapter.ConstructEscrow(constructParams)
	if err != nil {
		wrapped := fmt.Errorf("escrow: construct escrow TX failed: %w", err)
		observability.RecordError(span, wrapped)
		return nil, wrapped
	}

	// Step 3: Sign the TX via wallet (applies fee enforcement)
	sig, err := m.wallet.SignEscrowFunding(unsignedTx)
	if err != nil {
		wrapped := fmt.Errorf("escrow: sign escrow TX failed: %w", err)
		observability.RecordError(span, wrapped)
		return nil, wrapped
	}

	// Step 4: Broadcast signed TX via witness mesh
	signedTx := appendSignature(unsignedTx, sig)
	txHash, err := m.verifier.BroadcastTx(ctx, params.ChainID, signedTx)
	if err != nil {
		wrapped := fmt.Errorf("escrow: broadcast TX failed: %w", err)
		observability.RecordError(span, wrapped)
		observability.GossipBroadcastFailures().Add(ctx, 1)
		return nil, wrapped
	}
	observability.GossipBroadcastCount().Add(ctx, 1)
	span.SetAttributes(attribute.String(observability.AttrTxHash, txHash))

	// Step 5: Wait for witness confirmation
	confirmed, err := m.verifier.IsConfirmed(ctx, params.ChainID, txHash)
	if err != nil {
		wrapped := fmt.Errorf("escrow: confirmation check failed: %w", err)
		observability.RecordError(span, wrapped)
		return nil, wrapped
	}
	if !confirmed {
		wrapped := fmt.Errorf("escrow: TX %s not confirmed by witness quorum", txHash)
		observability.RecordError(span, wrapped)
		return nil, wrapped
	}

	// Step 6: Derive the escrow contract address from the TX hash.
	// The actual address derivation is chain-specific; we use the TX hash
	// as the canonical identifier. The adapter's EscrowState method can
	// resolve the contract address from this hash.
	escrowAddr := deriveEscrowAddress(params.ChainID, txHash)

	inst := &EscrowInstance{
		Address:   escrowAddr,
		ChainID:   params.ChainID,
		TxHash:    txHash,
		Params:    params,
		CreatedAt: time.Now(),
	}

	// Step 7: Track locally
	m.mu.Lock()
	m.escrows[escrowAddr] = inst
	m.mu.Unlock()

	span.SetAttributes(attribute.String(observability.AttrEscrowAddr, escrowAddr))
	observability.EscrowFundedCount().Add(ctx, 1,
		observability.AttrSet(attribute.String(observability.AttrChainID, params.ChainID)))
	return inst, nil
}

// appendSignature combines the unsigned TX data with the signature for broadcast.
// The format is: [tx_data_len (4 bytes big-endian)][tx_data][signature]
func appendSignature(tx *UnsignedTx, sig []byte) []byte {
	dataLen := len(tx.Data)
	result := make([]byte, 4+dataLen+len(sig))
	result[0] = byte(dataLen >> 24)
	result[1] = byte(dataLen >> 16)
	result[2] = byte(dataLen >> 8)
	result[3] = byte(dataLen)
	copy(result[4:4+dataLen], tx.Data)
	copy(result[4+dataLen:], sig)
	return result
}

// deriveEscrowAddress produces a canonical escrow address from the chain ID
// and creation TX hash. Chain-specific adapters may resolve this differently,
// but for tracking purposes this provides a unique, deterministic identifier.
func deriveEscrowAddress(chainID, txHash string) string {
	return fmt.Sprintf("%s:escrow:%s", chainID, txHash)
}
