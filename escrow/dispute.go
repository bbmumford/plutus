/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package escrow

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/bbmumford/plutus/observability"
	"go.opentelemetry.io/otel/attribute"
)

// Dispute hashes the provided evidence, constructs a dispute TX via the chain
// adapter, signs it, broadcasts it, and returns the TX hash.
//
// Orchestration steps:
//  1. Look up the tracked escrow instance
//  2. Attest current state via MeshVerifier (witness quorum)
//  3. Verify the escrow is in a disputable state (funded, not already resolved)
//  4. Hash the evidence for on-chain anchoring
//  5. Resolve the CurrencyAdapter for the chain+currency
//  6. Construct the dispute TX via the adapter
//  7. Sign the TX via the wallet
//  8. Broadcast the signed TX
//  9. Confirm the TX via witness attestation
func (m *EscrowManager) Dispute(ctx context.Context, escrowAddr string, params DisputeParams) (string, error) {
	ctx, span := observability.Tracer("plutus.escrow").Start(ctx, "EscrowManager.Dispute")
	defer span.End()
	span.SetAttributes(attribute.String(observability.AttrEscrowAddr, escrowAddr))

	// Step 1: Retrieve tracked instance
	inst, err := m.getInstance(escrowAddr)
	if err != nil {
		observability.RecordError(span, err)
		return "", err
	}
	span.SetAttributes(attribute.String(observability.AttrChainID, inst.ChainID))

	// Step 2: Attest current state
	snapshot, err := m.verifier.AttestEscrowState(ctx, inst.ChainID, escrowAddr)
	if err != nil {
		return "", fmt.Errorf("escrow: witness attestation failed for %s: %w", escrowAddr, err)
	}

	// Step 3: Verify disputable state
	if err := validateDisputable(snapshot); err != nil {
		return "", err
	}

	// Step 4: Hash evidence for on-chain anchoring.
	// If the caller already provided a pre-computed hash, use it.
	// Otherwise compute the hash from raw evidence.
	evidenceHash := params.EvidenceHash
	if evidenceHash == nil && len(params.Evidence) > 0 {
		h, err := AnchorEvidence(params.Evidence)
		if err != nil {
			return "", fmt.Errorf("escrow: evidence hashing failed: %w", err)
		}
		evidenceHash = h
	}
	if evidenceHash == nil {
		return "", fmt.Errorf("escrow: dispute requires evidence or evidence hash")
	}

	// Step 5: Resolve adapter
	adapter, err := m.resolveAdapter(inst)
	if err != nil {
		return "", fmt.Errorf("escrow: no adapter for %s/%s: %w", inst.ChainID, inst.Params.Currency, err)
	}

	// Step 6: Construct dispute TX with the anchored evidence hash
	disputeParams := DisputeParams{
		Evidence:     params.Evidence,
		EvidenceHash: evidenceHash,
	}
	unsignedTx, err := adapter.DisputeEscrow(escrowAddr, disputeParams)
	if err != nil {
		return "", fmt.Errorf("escrow: construct dispute TX failed: %w", err)
	}

	// Step 7: Sign the TX
	sig, err := m.wallet.SignDispute(unsignedTx)
	if err != nil {
		return "", fmt.Errorf("escrow: sign dispute TX failed: %w", err)
	}

	// Step 8: Broadcast signed TX
	signedTx := appendSignature(unsignedTx, sig)
	txHash, err := m.verifier.BroadcastTx(ctx, inst.ChainID, signedTx)
	if err != nil {
		return "", fmt.Errorf("escrow: broadcast dispute TX failed: %w", err)
	}

	// Step 9: Confirm via witnesses
	confirmed, err := m.verifier.IsConfirmed(ctx, inst.ChainID, txHash)
	if err != nil {
		wrapped := fmt.Errorf("escrow: dispute confirmation check failed: %w", err)
		observability.RecordError(span, wrapped)
		return "", wrapped
	}
	if !confirmed {
		wrapped := fmt.Errorf("escrow: dispute TX %s not confirmed by witness quorum", txHash)
		observability.RecordError(span, wrapped)
		return "", wrapped
	}

	span.SetAttributes(attribute.String(observability.AttrTxHash, txHash))
	observability.EscrowDisputedCount().Add(ctx, 1,
		observability.AttrSet(attribute.String(observability.AttrChainID, inst.ChainID)))
	return txHash, nil
}

// SettleWithRuling applies an arbitrator's ruling to a disputed escrow.
//
// Orchestration steps:
//  1. Look up the tracked escrow instance
//  2. Attest current state via MeshVerifier
//  3. Verify the escrow is disputed and awaiting a ruling
//  4. Validate the ruling percentages
//  5. Resolve the CurrencyAdapter
//  6. Construct the settlement TX via the adapter
//  7. Sign the TX via the wallet
//  8. Broadcast and confirm
func (m *EscrowManager) SettleWithRuling(ctx context.Context, escrowAddr string, ruling Ruling) (string, error) {
	ctx, span := observability.Tracer("plutus.escrow").Start(ctx, "EscrowManager.SettleWithRuling")
	defer span.End()
	span.SetAttributes(
		attribute.String(observability.AttrEscrowAddr, escrowAddr),
		attribute.String(observability.AttrOutcome, ruling.Outcome),
	)

	// Step 1: Retrieve tracked instance
	inst, err := m.getInstance(escrowAddr)
	if err != nil {
		observability.RecordError(span, err)
		return "", err
	}
	span.SetAttributes(attribute.String(observability.AttrChainID, inst.ChainID))

	// Step 2: Attest current state
	snapshot, err := m.verifier.AttestEscrowState(ctx, inst.ChainID, escrowAddr)
	if err != nil {
		return "", fmt.Errorf("escrow: witness attestation failed for %s: %w", escrowAddr, err)
	}

	// Step 3: Verify settleable state
	if err := validateSettleable(snapshot); err != nil {
		return "", err
	}

	// Step 4: Validate ruling
	if err := validateRuling(ruling); err != nil {
		return "", err
	}

	// Step 5: Resolve adapter
	adapter, err := m.resolveAdapter(inst)
	if err != nil {
		return "", fmt.Errorf("escrow: no adapter for %s/%s: %w", inst.ChainID, inst.Params.Currency, err)
	}

	// Step 6: Construct settlement TX
	unsignedTx, err := adapter.SettleWithRuling(escrowAddr, ruling)
	if err != nil {
		return "", fmt.Errorf("escrow: construct settlement TX failed: %w", err)
	}

	// Step 7: Sign the TX with fee breakdown from the ruling split.
	// Build fee breakdown based on the escrow amount and ruling percentages.
	amount := snapshot.State.Amount
	if amount == nil {
		amount = new(big.Int)
	}
	sellerPct := new(big.Int).Mul(amount, big.NewInt(int64(ruling.SellerPercent)))
	sellerPct.Div(sellerPct, big.NewInt(100))
	buyerPct := new(big.Int).Sub(amount, sellerPct)
	_ = buyerPct // buyer refund handled by contract

	fees := FeeBreakdown{
		MaintainerFee:      new(big.Int),
		ServiceProviderFee: new(big.Int),
		ArbitratorFee:      new(big.Int),
		WitnessFee:         new(big.Int),
		SellerProceeds:     sellerPct,
		Total:              amount,
	}
	sig, err := m.wallet.SignSettlement(unsignedTx, fees)
	if err != nil {
		return "", fmt.Errorf("escrow: sign settlement TX failed: %w", err)
	}

	// Step 8: Broadcast signed TX
	signedTx := appendSignature(unsignedTx, sig)
	txHash, err := m.verifier.BroadcastTx(ctx, inst.ChainID, signedTx)
	if err != nil {
		return "", fmt.Errorf("escrow: broadcast settlement TX failed: %w", err)
	}

	// Step 9: Confirm via witnesses
	confirmed, err := m.verifier.IsConfirmed(ctx, inst.ChainID, txHash)
	if err != nil {
		wrapped := fmt.Errorf("escrow: settlement confirmation check failed: %w", err)
		observability.RecordError(span, wrapped)
		return "", wrapped
	}
	if !confirmed {
		wrapped := fmt.Errorf("escrow: settlement TX %s not confirmed by witness quorum", txHash)
		observability.RecordError(span, wrapped)
		return "", wrapped
	}

	span.SetAttributes(attribute.String(observability.AttrTxHash, txHash))
	observability.SettlementCount().Add(ctx, 1,
		observability.AttrSet(attribute.String(observability.AttrChainID, inst.ChainID)))
	return txHash, nil
}

// RefundAfterTimeout refunds the buyer when the escrow has timed out.
//
// Orchestration steps:
//  1. Look up the tracked escrow instance
//  2. Attest current state via MeshVerifier
//  3. Verify the escrow has timed out
//  4. Resolve the CurrencyAdapter
//  5. Construct the refund TX via the adapter
//  6. Sign, broadcast, and confirm
func (m *EscrowManager) RefundAfterTimeout(ctx context.Context, escrowAddr string) (string, error) {
	ctx, span := observability.Tracer("plutus.escrow").Start(ctx, "EscrowManager.RefundAfterTimeout")
	defer span.End()
	span.SetAttributes(attribute.String(observability.AttrEscrowAddr, escrowAddr))

	// Step 1: Retrieve tracked instance
	inst, err := m.getInstance(escrowAddr)
	if err != nil {
		observability.RecordError(span, err)
		return "", err
	}
	span.SetAttributes(attribute.String(observability.AttrChainID, inst.ChainID))

	// Step 2: Attest current state
	snapshot, err := m.verifier.AttestEscrowState(ctx, inst.ChainID, escrowAddr)
	if err != nil {
		return "", fmt.Errorf("escrow: witness attestation failed for %s: %w", escrowAddr, err)
	}

	// Step 3: Verify timed-out state
	if err := validateTimedOut(snapshot); err != nil {
		return "", err
	}

	// Step 4: Resolve adapter
	adapter, err := m.resolveAdapter(inst)
	if err != nil {
		return "", fmt.Errorf("escrow: no adapter for %s/%s: %w", inst.ChainID, inst.Params.Currency, err)
	}

	// Step 5: Construct refund TX
	unsignedTx, err := adapter.RefundAfterTimeout(escrowAddr)
	if err != nil {
		return "", fmt.Errorf("escrow: construct refund TX failed: %w", err)
	}

	// Step 6: Sign the TX (funding key; refunds go back to buyer)
	sig, err := m.wallet.SignEscrowFunding(unsignedTx)
	if err != nil {
		return "", fmt.Errorf("escrow: sign refund TX failed: %w", err)
	}

	// Step 7: Broadcast signed TX
	signedTx := appendSignature(unsignedTx, sig)
	txHash, err := m.verifier.BroadcastTx(ctx, inst.ChainID, signedTx)
	if err != nil {
		return "", fmt.Errorf("escrow: broadcast refund TX failed: %w", err)
	}

	// Step 8: Confirm via witnesses
	confirmed, err := m.verifier.IsConfirmed(ctx, inst.ChainID, txHash)
	if err != nil {
		wrapped := fmt.Errorf("escrow: refund confirmation check failed: %w", err)
		observability.RecordError(span, wrapped)
		return "", wrapped
	}
	if !confirmed {
		wrapped := fmt.Errorf("escrow: refund TX %s not confirmed by witness quorum", txHash)
		observability.RecordError(span, wrapped)
		return "", wrapped
	}

	span.SetAttributes(attribute.String(observability.AttrTxHash, txHash))
	observability.EscrowRefundedCount().Add(ctx, 1,
		observability.AttrSet(attribute.String(observability.AttrChainID, inst.ChainID)))
	return txHash, nil
}

// validateDisputable ensures the escrow is in a state that allows dispute.
func validateDisputable(snap *EscrowSnapshot) error {
	if !snap.Quorum {
		return fmt.Errorf("escrow: witness quorum not reached for dispute validation")
	}
	if !snap.State.Funded {
		return fmt.Errorf("escrow: cannot dispute unfunded escrow")
	}
	if snap.State.Released {
		return fmt.Errorf("escrow: cannot dispute already released escrow")
	}
	if snap.State.Disputed {
		return fmt.Errorf("escrow: escrow is already disputed")
	}
	if snap.State.Settled {
		return fmt.Errorf("escrow: cannot dispute already settled escrow")
	}
	if snap.State.TimedOut {
		return fmt.Errorf("escrow: cannot dispute timed-out escrow")
	}
	return nil
}

// validateSettleable ensures the escrow is disputed and awaiting a ruling.
func validateSettleable(snap *EscrowSnapshot) error {
	if !snap.Quorum {
		return fmt.Errorf("escrow: witness quorum not reached for settlement validation")
	}
	if !snap.State.Disputed {
		return fmt.Errorf("escrow: can only settle disputed escrows")
	}
	if snap.State.Settled {
		return fmt.Errorf("escrow: escrow is already settled")
	}
	if snap.State.Released {
		return fmt.Errorf("escrow: escrow has already been released")
	}
	return nil
}

// validateTimedOut ensures the escrow has timed out and is eligible for refund.
func validateTimedOut(snap *EscrowSnapshot) error {
	if !snap.Quorum {
		return fmt.Errorf("escrow: witness quorum not reached for timeout validation")
	}
	if !snap.State.Funded {
		return fmt.Errorf("escrow: cannot refund unfunded escrow")
	}
	if snap.State.Released {
		return fmt.Errorf("escrow: escrow already released, cannot refund")
	}
	if snap.State.Settled {
		return fmt.Errorf("escrow: escrow already settled, cannot refund")
	}
	if !snap.State.TimedOut && snap.State.CurrentBlock < snap.State.TimeoutBlock {
		return fmt.Errorf("escrow: escrow has not timed out (current block %d < timeout block %d)",
			snap.State.CurrentBlock, snap.State.TimeoutBlock)
	}
	return nil
}

// validateRuling checks that an arbitrator's ruling has valid percentages.
func validateRuling(ruling Ruling) error {
	if ruling.BuyerPercent+ruling.SellerPercent != 100 {
		return fmt.Errorf("escrow: ruling percentages must sum to 100, got buyer=%d seller=%d",
			ruling.BuyerPercent, ruling.SellerPercent)
	}
	if ruling.ArbitratorSig == nil {
		return fmt.Errorf("escrow: ruling must include arbitrator signature")
	}
	return nil
}

// hashEvidence computes the SHA-256 hash of raw evidence bytes.
func hashEvidence(evidence []byte) []byte {
	h := sha256.Sum256(evidence)
	return h[:]
}
