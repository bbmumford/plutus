/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"errors"
)

// FinalizingSigner is a FeeDistributionSigner wrapper that runs an
// EVMEnvelopeFinalizer over every batch before delegating to Inner.
//
// This is the glue point between builder and signer: the EVM payout builder
// emits an UnsignedBatch whose envelope has zero/empty Nonce + GasPrice, and
// the signer requires those fields populated. The finalizer injects live
// values read from the chain's RPC just before signing.
//
// For BTC and other batch kinds, Finalizer.Finalize is a no-op; the wrapper
// is a pure pass-through to Inner.
//
// A nil Finalizer is permitted (tests and no-EVM deployments) — in that case
// the wrapper is a transparent proxy.
type FinalizingSigner struct {
	Inner     FeeDistributionSigner
	Finalizer *EVMEnvelopeFinalizer
}

// Compile-time assertion.
var _ FeeDistributionSigner = (*FinalizingSigner)(nil)

// SignBatchPayout implements FeeDistributionSigner by (optionally) finalizing
// the envelope and then delegating to Inner.
func (s *FinalizingSigner) SignBatchPayout(ctx context.Context, batch UnsignedBatch) (SignedBatch, error) {
	if s == nil {
		return SignedBatch{}, errors.New("witness/finalizing_signer: nil receiver")
	}
	if s.Inner == nil {
		return SignedBatch{}, errors.New("witness/finalizing_signer: nil inner signer")
	}
	if s.Finalizer != nil {
		finalized, err := s.Finalizer.Finalize(ctx, batch)
		if err != nil {
			return SignedBatch{}, err
		}
		batch = finalized
	}
	return s.Inner.SignBatchPayout(ctx, batch)
}
