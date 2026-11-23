/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package escrow

import (
	"context"
	"fmt"

	"github.com/bbmumford/plutus/observability"
	"go.opentelemetry.io/otel/attribute"
)

// Release verifies escrow state via witnesses, constructs the release TX
// via the chain adapter, signs it, broadcasts it, and returns the TX hash.
//
// Orchestration steps:
//  1. Look up the tracked escrow instance
//  2. Attest current state via MeshVerifier (witness quorum)
//  3. Verify the escrow is in a releasable state (funded, not disputed/settled/timed-out)
//  4. Resolve the CurrencyAdapter for the chain+currency
//  5. Build the adapter-level release params from the escrow ReleaseParams
//  6. Construct the release TX via the adapter
//  7. Sign the TX via the wallet
//  8. Broadcast the signed TX
//  9. Confirm the TX via witness attestation
func (m *EscrowManager) Release(ctx context.Context, escrowAddr string, params ReleaseParams) (string, error) {
	ctx, span := observability.Tracer("plutus.escrow").Start(ctx, "EscrowManager.Release")
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

	// Step 3: Verify releasable state
	if err := validateReleasable(snapshot); err != nil {
		return "", err
	}

	// Step 4: Resolve adapter
	adapter, err := m.resolveAdapter(inst)
	if err != nil {
		return "", fmt.Errorf("escrow: no adapter for %s/%s: %w", inst.ChainID, inst.Params.Currency, err)
	}

	// Step 5: Build adapter-level release params.
	// Merge the receipt hashes from the release call with any witness hashes
	// originally attached to the escrow for full provenance.
	adapterParams := adapterReleaseParams(params)

	// Step 6: Construct release TX
	unsignedTx, err := adapter.ReleaseEscrow(escrowAddr, adapterParams)
	if err != nil {
		return "", fmt.Errorf("escrow: construct release TX failed: %w", err)
	}

	// Step 7: Sign the TX via wallet (settlement signing applies fee enforcement).
	// Calculate real fees via the fee calculator so the signer can verify
	// them against PRC on-chain rates. If no fee calculator is configured,
	// refuse to sign — fee enforcement cannot be bypassed.
	if m.feeCalc == nil {
		return "", fmt.Errorf("escrow: fee calculator not configured, cannot sign release")
	}
	feeOpts := FeeOptions{
		MaintainerBPS:      100, // default; overridden by PRC at signer layer
		HasServiceProvider: len(params.ReceiptHashes) > 0,
		ServiceProviderBPS: 50,
		HasWitness:         len(inst.Params.WitnessHashes) > 0,
		WitnessBPS:         25,
	}
	fees, err := m.feeCalc.Calculate(snapshot.State.Amount, feeOpts)
	if err != nil {
		return "", fmt.Errorf("escrow: fee calculation failed: %w", err)
	}
	sig, err := m.wallet.SignSettlement(unsignedTx, fees)
	if err != nil {
		return "", fmt.Errorf("escrow: sign release TX failed: %w", err)
	}

	// Step 8: Broadcast signed TX
	signedTx := appendSignature(unsignedTx, sig)
	txHash, err := m.verifier.BroadcastTx(ctx, inst.ChainID, signedTx)
	if err != nil {
		return "", fmt.Errorf("escrow: broadcast release TX failed: %w", err)
	}

	// Step 9: Confirm via witnesses
	confirmed, err := m.verifier.IsConfirmed(ctx, inst.ChainID, txHash)
	if err != nil {
		wrapped := fmt.Errorf("escrow: release confirmation check failed: %w", err)
		observability.RecordError(span, wrapped)
		return "", wrapped
	}
	if !confirmed {
		wrapped := fmt.Errorf("escrow: release TX %s not confirmed by witness quorum", txHash)
		observability.RecordError(span, wrapped)
		return "", wrapped
	}

	span.SetAttributes(attribute.String(observability.AttrTxHash, txHash))
	observability.EscrowReleasedCount().Add(ctx, 1,
		observability.AttrSet(attribute.String(observability.AttrChainID, inst.ChainID)))
	return txHash, nil
}

// validateReleasable ensures the escrow snapshot is in a state that allows release.
func validateReleasable(snap *EscrowSnapshot) error {
	if !snap.Quorum {
		return fmt.Errorf("escrow: witness quorum not reached for release validation")
	}
	if !snap.State.Funded {
		return fmt.Errorf("escrow: cannot release unfunded escrow")
	}
	if snap.State.Released {
		return fmt.Errorf("escrow: escrow already released")
	}
	if snap.State.Disputed {
		return fmt.Errorf("escrow: cannot release disputed escrow, must settle via ruling")
	}
	if snap.State.Settled {
		return fmt.Errorf("escrow: escrow already settled")
	}
	if snap.State.TimedOut {
		return fmt.Errorf("escrow: escrow has timed out, use RefundAfterTimeout instead")
	}
	return nil
}

// adapterReleaseParams converts escrow-level ReleaseParams to the adapter's format.
func adapterReleaseParams(params ReleaseParams) ReleaseParams {
	return params
}
