/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package btc

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bbmumford/plutus/adapter"
)

// DefaultDustThreshold is the minimum output value (satoshis) that will
// actually be written as an output on the release tx. Anything smaller is
// folded into the preceding recipient output rather than broadcast (Bitcoin
// relay rules reject outputs below ~546 sat for P2WPKH).
const DefaultDustThreshold int64 = 546

// ReleasePayouts describes every potential destination for a release tx.
// Addresses for witness/service/arbitrator are configurable per-escrow — the
// maintainer address is canonical.
type ReleasePayouts struct {
	// RecipientAddr is the primary payout address:
	//   - for normal release: the seller
	//   - for refund-before-timeout via 2-of-3: the buyer
	RecipientAddr string

	// MaintainerAddr is the canonical maintainer P2WPKH bech32 address.
	// This output MUST be present whenever MaintainerFee > dust, and the
	// signer will refuse to sign if it isn't.
	MaintainerAddr string

	// WitnessAddr is the payout destination for witness fees (zero or empty
	// if no witnesses were used).
	WitnessAddr string

	// ServiceAddr is the payout destination for service provider fees.
	ServiceAddr string

	// ArbitratorAddr is the payout destination for arbitrator fees (in
	// disputed releases).
	ArbitratorAddr string

	// ChangeAddr receives any leftover after all payouts and mining fee.
	// Typically set to the escrow's own P2WSH address so unspent funds
	// remain locked under the multisig.
	ChangeAddr string
}

// BuildReleaseTxParams bundles the inputs to BuildReleaseTx.
type BuildReleaseTxParams struct {
	// Escrow is the funded escrow being released.
	Escrow BTCEscrowState
	// Fees is the pre-calculated fee breakdown (from settle.Calculate).
	Fees adapter.FeeBreakdown
	// Payouts describes all output addresses.
	Payouts ReleasePayouts
	// FeeRateSatPerVByte is the mining fee rate to use.
	FeeRateSatPerVByte float64
	// LockTime sets the tx nLockTime (0 for immediate relay).
	LockTime uint32
	// Sequence to use for the input (default 0xFFFFFFFE to honour locktime).
	Sequence uint32
}

// BuildReleaseTx constructs the unsigned multisig release tx, enforcing the
// deterministic output order documented on BTCAdapter.ReleaseEscrow.
//
// Output order (deterministic, used by both builder and verifier):
//
//  1. Recipient (seller for normal release; buyer for in-multisig refund)
//  2. Maintainer fee  (if maintainerFee > dust)
//  3. Witness fee     (if witnessFee    > dust && WitnessAddr set)
//  4. Service fee     (if serviceFee    > dust && ServiceAddr set)
//  5. Arbitrator fee  (if arbitratorFee > dust && ArbitratorAddr set)
//  6. Change          (if remaining     > dust && ChangeAddr set)
//
// Fees that are present-but-dust or lack a destination are added back to the
// recipient's payout. Mining fee is deducted from the recipient (not from
// maintainer/fees, which MUST land intact for signer verification to pass).
func BuildReleaseTx(params BuildReleaseTxParams) (*MsgTx, error) {
	if params.Escrow.FundingAmount == nil || params.Escrow.FundingAmount.Sign() <= 0 {
		return nil, errors.New("btc/tx: escrow has no funding amount")
	}
	if params.Fees.Total == nil || params.Fees.Total.Sign() <= 0 {
		return nil, errors.New("btc/tx: fees.Total must be positive")
	}
	if params.Payouts.RecipientAddr == "" {
		return nil, errors.New("btc/tx: recipient address is empty")
	}
	if params.Payouts.MaintainerAddr == "" {
		return nil, errors.New("btc/tx: maintainer address is empty (canonical.MaintainerBTCAddress must be set)")
	}
	if params.Escrow.FundingTxID == "" {
		return nil, errors.New("btc/tx: escrow funding txid is empty")
	}
	if params.FeeRateSatPerVByte <= 0 {
		return nil, errors.New("btc/tx: fee rate must be positive")
	}

	total := params.Escrow.FundingAmount.Int64()
	if total <= 0 {
		return nil, errors.New("btc/tx: escrow funding amount must fit in int64 satoshis")
	}

	// Pre-script-check all addresses so we fail fast with clear errors.
	recipientScript, err := PkScriptForAddress(params.Payouts.RecipientAddr)
	if err != nil {
		return nil, fmt.Errorf("btc/tx: recipient address: %w", err)
	}
	maintainerScript, err := PkScriptForAddress(params.Payouts.MaintainerAddr)
	if err != nil {
		return nil, fmt.Errorf("btc/tx: maintainer address: %w", err)
	}

	sequence := params.Sequence
	if sequence == 0 {
		sequence = 0xFFFFFFFE
	}

	// Assemble outputs in deterministic order. Start with fee outputs; the
	// recipient output is computed last so we can absorb dust-sized fees.
	type plannedOut struct {
		addr   string
		script []byte
		value  int64
	}

	dust := DefaultDustThreshold
	absorbedIntoRecipient := int64(0)

	plan := make([]plannedOut, 0, 6)
	// Placeholder for recipient; populated at the end.
	plan = append(plan, plannedOut{
		addr:   params.Payouts.RecipientAddr,
		script: recipientScript,
		value:  0, // filled later
	})

	// Maintainer.
	mf := bigToSat(params.Fees.MaintainerFee)
	if mf > 0 {
		if mf < dust {
			return nil, fmt.Errorf("btc/tx: maintainer fee %d sat below dust %d — escrow amount too small for BTC", mf, dust)
		}
		plan = append(plan, plannedOut{
			addr:   params.Payouts.MaintainerAddr,
			script: maintainerScript,
			value:  mf,
		})
	}

	// Witness.
	wf := bigToSat(params.Fees.WitnessFee)
	if wf > 0 {
		if params.Payouts.WitnessAddr == "" || wf < dust {
			absorbedIntoRecipient += wf
		} else {
			s, err := PkScriptForAddress(params.Payouts.WitnessAddr)
			if err != nil {
				return nil, fmt.Errorf("btc/tx: witness address: %w", err)
			}
			plan = append(plan, plannedOut{params.Payouts.WitnessAddr, s, wf})
		}
	}

	// Service provider.
	sf := bigToSat(params.Fees.ServiceProviderFee)
	if sf > 0 {
		if params.Payouts.ServiceAddr == "" || sf < dust {
			absorbedIntoRecipient += sf
		} else {
			s, err := PkScriptForAddress(params.Payouts.ServiceAddr)
			if err != nil {
				return nil, fmt.Errorf("btc/tx: service address: %w", err)
			}
			plan = append(plan, plannedOut{params.Payouts.ServiceAddr, s, sf})
		}
	}

	// Arbitrator.
	af := bigToSat(params.Fees.ArbitratorFee)
	if af > 0 {
		if params.Payouts.ArbitratorAddr == "" || af < dust {
			absorbedIntoRecipient += af
		} else {
			s, err := PkScriptForAddress(params.Payouts.ArbitratorAddr)
			if err != nil {
				return nil, fmt.Errorf("btc/tx: arbitrator address: %w", err)
			}
			plan = append(plan, plannedOut{params.Payouts.ArbitratorAddr, s, af})
		}
	}

	// Sum everything paid to non-recipient outputs; recipient gets the rest
	// minus the mining fee. bigToSat clamps negatives; seller proceeds must
	// be non-negative by construction of settle.Calculate.
	nonRecipientPaid := int64(0)
	for _, p := range plan[1:] {
		nonRecipientPaid += p.value
	}

	sellerProceeds := bigToSat(params.Fees.SellerProceeds)
	recipientGross := sellerProceeds + absorbedIntoRecipient

	// Estimate mining fee.
	numOutputs := len(plan)
	// Tentatively include change if we'll have leftover above dust.
	// A rough first pass with no change; we'll recompute once we know.
	estVSize := EstimateTxVSize(1, numOutputs)
	miningFee := int64(float64(estVSize) * params.FeeRateSatPerVByte)
	if miningFee < 1 {
		miningFee = 1
	}

	// Consistency check: total must equal recipientGross + nonRecipientPaid.
	if recipientGross+nonRecipientPaid != total {
		return nil, fmt.Errorf(
			"btc/tx: fee breakdown mismatch: seller(%d) + absorbed(%d) + nonRecipient(%d) != total(%d)",
			sellerProceeds, absorbedIntoRecipient, nonRecipientPaid, total,
		)
	}

	// Mining fee comes out of the recipient (never out of maintainer/fees).
	recipientNet := recipientGross - miningFee
	if recipientNet < dust {
		return nil, fmt.Errorf(
			"btc/tx: recipient payout %d sat below dust after %d sat mining fee; escrow too small",
			recipientNet, miningFee,
		)
	}
	plan[0].value = recipientNet

	// Handle change. The change output carries the dust difference between
	// the estimated mining fee and the true mining fee; for a pure pass-
	// through release there typically is none because recipient absorbs it.
	// A release distributes the escrow exactly, so params.Payouts.ChangeAddr
	// gets no output here; a split-funding release with several inputs would
	// pay its change there.

	// Build the tx.
	tx := NewMsgTx(2)
	tx.LockTime = params.LockTime

	fundingHash, err := TxIDFromDisplayHex(params.Escrow.FundingTxID)
	if err != nil {
		return nil, fmt.Errorf("btc/tx: funding txid: %w", err)
	}
	tx.AddTxIn(&TxIn{
		PreviousOutPoint: OutPoint{Hash: fundingHash, Index: params.Escrow.FundingVout},
		Sequence:         sequence,
		InputValue:       total,
		WitnessScript:    params.Escrow.WitnessScript,
	})

	for _, p := range plan {
		tx.AddTxOut(&TxOut{Value: p.value, PkScript: p.script})
	}

	return tx, nil
}

// bigToSat converts a *big.Int fee value to int64 satoshis.
// Returns 0 for nil/negative/overflow (safe default — callers still need to
// treat a zero fee as "no output needed").
func bigToSat(v *big.Int) int64 {
	if v == nil || v.Sign() <= 0 {
		return 0
	}
	if !v.IsInt64() {
		return 0
	}
	return v.Int64()
}

// OutputPaysAddress returns true if the given output's pkScript matches the
// scriptPubKey produced by the given bech32 address. Used by the signer to
// verify the maintainer-fee output.
func OutputPaysAddress(out *TxOut, addr string) (bool, error) {
	if out == nil {
		return false, errors.New("btc/tx: nil output")
	}
	expected, err := PkScriptForAddress(addr)
	if err != nil {
		return false, err
	}
	return bytesEqual(out.PkScript, expected), nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// FindOutputForAddress returns the index and value (sat) of the first output
// that pays the given address, or -1/0 if no such output exists.
func FindOutputForAddress(tx *MsgTx, addr string) (int, int64, error) {
	if tx == nil {
		return -1, 0, errors.New("btc/tx: nil tx")
	}
	expected, err := PkScriptForAddress(addr)
	if err != nil {
		return -1, 0, err
	}
	for i, out := range tx.TxOut {
		if bytesEqual(out.PkScript, expected) {
			return i, out.Value, nil
		}
	}
	return -1, 0, nil
}
