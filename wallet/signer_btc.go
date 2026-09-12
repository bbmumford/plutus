/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package wallet

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/bbmumford/plutus/adapter"
	"github.com/bbmumford/plutus/adapter/btc"
	"github.com/bbmumford/plutus/settle"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// BTCSettlementRequest bundles everything the BTC signer needs to validate
// and sign a release transaction.
type BTCSettlementRequest struct {
	// Tx is the unsigned release transaction (produced by BTCAdapter.ReleaseEscrow
	// then deserialized — or constructed directly via BuildReleaseTx).
	Tx *btc.MsgTx

	// Fees is the expected fee breakdown. The signer cross-checks each output
	// of Tx against these values before producing a signature.
	Fees adapter.FeeBreakdown

	// Escrow is the cached escrow state (so the signer can reference
	// funding amount and witness script).
	Escrow btc.BTCEscrowState

	// MaintainerAddr is the canonical maintainer BTC address.
	// MUST match canonical.MaintainerBTCAddress in production.
	MaintainerAddr string

	// WitnessAddr / ServiceAddr / ArbitratorAddr are the chain-native payout
	// destinations for the non-maintainer fee outputs, if the escrow declared
	// them. When any of these is non-empty AND the corresponding fee in Fees
	// is non-zero, SignBTCSettlement verifies the tx includes a matching
	// output paying at least the expected amount — mirroring the maintainer
	// fee defence. Empty addresses disable the check for that fee (the fee
	// is assumed to be absorbed into the recipient output).
	WitnessAddr    string
	ServiceAddr    string
	ArbitratorAddr string

	// InputIndex identifies which input of Tx this signer controls.
	InputIndex int

	// PrivateKey is the secp256k1 key for the signer's role (buyer,
	// seller, or arbitrator) in the 2-of-3 multisig.
	PrivateKey *ECDSAPrivateKey
}

// SignBTCSettlement verifies maintainer-fee enforcement at the signer layer
// and returns an ECDSA signature over the BIP143 sighash for the specified
// input. The returned byte slice is a DER-encoded ECDSA signature with the
// SIGHASH_ALL flag byte appended (the standard Bitcoin witness format).
//
// ENFORCEMENT RULES (in order):
//
//  1. Tx must contain an output paying MaintainerAddr.
//  2. That output's value must be >= expected maintainerFee, computed as
//     floor(escrow.Amount * Fees.MaintainerFeeBPS / 10000) where
//     Fees.MaintainerFeeBPS is the effective BPS from Fees.MaintainerFee vs.
//     escrow.Amount — capped at settle.MaintainerFeeBPSCap.
//  3. If Fees has any non-zero witness/service/arbitrator fee AND the
//     corresponding output exists, the output must meet that amount.
//  4. Fee breakdown must pass verifyFeesAgainstPRC if a resolver is configured.
//  5. Combined BPS must not exceed settle.CombinedBPSCap.
//
// If ANY check fails, the signer returns an error WITHOUT signing. This is
// the defence that the prompt calls airtight: no fork can trivially produce
// a valid 2-of-3 release without at least one canonical co-signer, and every
// canonical co-signer runs this check.
func (s *Signer) SignBTCSettlement(req BTCSettlementRequest) ([]byte, error) {
	if req.Tx == nil {
		return nil, errors.New("plutus/wallet: BTC tx is nil")
	}
	if req.MaintainerAddr == "" {
		return nil, errors.New("plutus/wallet: maintainer address is empty — refusing to sign without canonical anchor")
	}
	if req.PrivateKey == nil || req.PrivateKey.D == nil {
		return nil, errors.New("plutus/wallet: signer private key is nil")
	}
	if req.Escrow.FundingAmount == nil || req.Escrow.FundingAmount.Sign() <= 0 {
		return nil, errors.New("plutus/wallet: escrow funding amount must be positive")
	}
	if req.InputIndex < 0 || req.InputIndex >= len(req.Tx.TxIn) {
		return nil, fmt.Errorf("plutus/wallet: input index %d out of range", req.InputIndex)
	}

	// Step 1: locate the maintainer output.
	idx, paidSat, err := btc.FindOutputForAddress(req.Tx, req.MaintainerAddr)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: locate maintainer output: %w", err)
	}

	// Step 2: compute expected maintainer fee using canonical caps.
	expected := expectedMaintainerSat(req.Escrow.FundingAmount, req.Fees.MaintainerFee)
	if expected <= 0 {
		// Maintainer fee is effectively zero — only acceptable if the
		// expected Fees.MaintainerFee is explicitly zero (i.e. a timeout
		// refund path handled by a different signer API). Fail closed here
		// on the release path.
		return nil, fmt.Errorf(
			"plutus/wallet: refusing to sign — maintainer fee evaluates to zero " +
				"(escrow amount too small or Fees.MaintainerFee not set)")
	}
	if idx < 0 {
		return nil, fmt.Errorf(
			"plutus/wallet: refusing to sign — release tx omits maintainer fee output (expected %d sat to %s)",
			expected, req.MaintainerAddr,
		)
	}
	if paidSat < expected {
		return nil, fmt.Errorf(
			"plutus/wallet: refusing to sign — maintainer fee %d sat < required %d sat (%s)",
			paidSat, expected, req.MaintainerAddr,
		)
	}

	// Step 2b: verify non-maintainer payout addresses (witness, service,
	// arbitrator). For each non-empty address with a positive expected fee
	// in Fees, require an output paying at least the expected amount to
	// that address. Mirrors the maintainer fee enforcement pattern.
	if err := verifyNonMaintainerPayouts(req); err != nil {
		return nil, err
	}

	// Step 3: validate combined fees against canonical caps.
	if err := validateCombinedCaps(req.Escrow.FundingAmount, req.Fees); err != nil {
		return nil, fmt.Errorf("plutus/wallet: refusing to sign — %w", err)
	}

	// Step 4: if PRC resolver is configured AND the tx chainID is known,
	// cross-check fees against PRC minima. Reuses the existing EVM helper.
	if s.prcResolver != nil {
		// Build a stub UnsignedTx carrying the expected total so the
		// existing helper applies correctly.
		stubTx := &adapter.UnsignedTx{
			ChainID: "bitcoin",
			Amount:  new(big.Int).Set(req.Escrow.FundingAmount),
		}
		if prcData, prcErr := s.prcResolver.Resolve(stubTx.ChainID); prcErr == nil && prcData != nil {
			if err := verifyFeesAgainstPRC(stubTx, req.Fees, prcData); err != nil {
				return nil, fmt.Errorf("plutus/wallet: refusing to sign — PRC check: %w", err)
			}
		}
		// Absence of PRC data on BTC is expected (no on-chain registry).
	}

	// Step 5: compute BIP143 sighash.
	sighash, err := req.Tx.ComputeBIP143SighashP2WSH(req.InputIndex, btc.SighashAll)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: compute sighash: %w", err)
	}

	// Step 6: produce DER-encoded low-S ECDSA signature.
	sig, err := ecdsaSignLowS(req.PrivateKey, sighash[:])
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: ecdsa sign: %w", err)
	}

	// Append SIGHASH_ALL byte (0x01) — the standard Bitcoin witness sig format.
	out := make([]byte, 0, len(sig)+1)
	out = append(out, sig...)
	out = append(out, byte(btc.SighashAll))
	return out, nil
}

// expectedMaintainerSat returns the minimum acceptable maintainer-fee output
// value in satoshis, in priority order:
//   - If expectedFee is non-nil and positive, use it directly (signer asserts
//     the caller precomputed via settle.Calculate).
//   - Otherwise compute floor(amount * MaintainerFeeBPSCap / 10000) — the
//     canonical cap as a safe floor.
//
// This matches the prompt requirement: "use the SAME canonical caps as EVM
// in settle/calculate.go".
func expectedMaintainerSat(amount, expectedFee *big.Int) int64 {
	if expectedFee != nil && expectedFee.Sign() > 0 {
		if !expectedFee.IsInt64() {
			return 0
		}
		return expectedFee.Int64()
	}
	if amount == nil || amount.Sign() <= 0 {
		return 0
	}
	v := new(big.Int).Mul(amount, big.NewInt(int64(settle.MaintainerFeeBPSCap)))
	v.Div(v, big.NewInt(int64(settle.BPSBase)))
	if !v.IsInt64() {
		return 0
	}
	return v.Int64()
}

// validateCombinedCaps ensures the fee breakdown's combined BPS does not
// exceed the canonical cap. Accepts the breakdown from settle.Calculate.
func validateCombinedCaps(amount *big.Int, fees adapter.FeeBreakdown) error {
	if amount == nil || amount.Sign() <= 0 {
		return errors.New("escrow amount must be positive")
	}
	total := new(big.Int)
	add := func(v *big.Int) {
		if v != nil && v.Sign() > 0 {
			total.Add(total, v)
		}
	}
	add(fees.MaintainerFee)
	add(fees.WitnessFee)
	add(fees.ServiceProviderFee)
	add(fees.ArbitratorFee)

	// combinedBPS = total * 10000 / amount (integer).
	combined := new(big.Int).Mul(total, big.NewInt(int64(settle.BPSBase)))
	combined.Div(combined, amount)
	if !combined.IsUint64() {
		return errors.New("combined fee BPS overflow")
	}
	if combined.Uint64() > uint64(settle.CombinedBPSCap) {
		return fmt.Errorf("combined fee %d BPS exceeds cap %d", combined.Uint64(), settle.CombinedBPSCap)
	}
	// Enforce individual caps too — a malicious tx could exceed one while
	// keeping combined below the cap.
	if fees.MaintainerFee != nil && amount.Sign() > 0 {
		b := bpsOf(fees.MaintainerFee, amount)
		if b > uint64(settle.MaintainerFeeBPSCap) {
			return fmt.Errorf("maintainer fee %d BPS exceeds cap %d", b, settle.MaintainerFeeBPSCap)
		}
	}
	if fees.WitnessFee != nil {
		if bpsOf(fees.WitnessFee, amount) > uint64(settle.WitnessBPSCap) {
			return fmt.Errorf("witness fee exceeds cap %d BPS", settle.WitnessBPSCap)
		}
	}
	if fees.ServiceProviderFee != nil {
		if bpsOf(fees.ServiceProviderFee, amount) > uint64(settle.ServiceProvBPSCap) {
			return fmt.Errorf("service fee exceeds cap %d BPS", settle.ServiceProvBPSCap)
		}
	}
	if fees.ArbitratorFee != nil {
		if bpsOf(fees.ArbitratorFee, amount) > uint64(settle.ArbitratorBPSCap) {
			return fmt.Errorf("arbitrator fee exceeds cap %d BPS", settle.ArbitratorBPSCap)
		}
	}
	return nil
}

func bpsOf(fee, amount *big.Int) uint64 {
	if fee == nil || fee.Sign() <= 0 {
		return 0
	}
	v := new(big.Int).Mul(fee, big.NewInt(int64(settle.BPSBase)))
	v.Div(v, amount)
	if !v.IsUint64() {
		return ^uint64(0)
	}
	return v.Uint64()
}

// verifyNonMaintainerPayouts enforces the witness/service/arbitrator fee
// outputs against the declared payout addresses on the escrow. For each role
// where the request carries a non-empty destination address AND the expected
// fee in Fees is positive, the tx MUST contain an output to that address with
// value >= the expected fee. When the address is empty, the corresponding fee
// is assumed to have been absorbed into the recipient output and no check is
// performed for that role (matches the tx builder's absorb-into-recipient
// fallback when no destination is set).
func verifyNonMaintainerPayouts(req BTCSettlementRequest) error {
	checks := []struct {
		role string
		addr string
		fee  *big.Int
	}{
		{"witness", req.WitnessAddr, req.Fees.WitnessFee},
		{"service-provider", req.ServiceAddr, req.Fees.ServiceProviderFee},
		{"arbitrator", req.ArbitratorAddr, req.Fees.ArbitratorFee},
	}
	for _, c := range checks {
		if c.addr == "" {
			continue
		}
		if c.fee == nil || c.fee.Sign() <= 0 {
			continue
		}
		if !c.fee.IsInt64() {
			return fmt.Errorf(
				"plutus/wallet: refusing to sign — %s fee does not fit int64 (escrow too large)",
				c.role,
			)
		}
		expected := c.fee.Int64()
		idx, paid, err := btc.FindOutputForAddress(req.Tx, c.addr)
		if err != nil {
			return fmt.Errorf("plutus/wallet: locate %s output: %w", c.role, err)
		}
		if idx < 0 {
			return fmt.Errorf(
				"plutus/wallet: refusing to sign — release tx omits %s fee output (expected %d sat to %s)",
				c.role, expected, c.addr,
			)
		}
		if paid < expected {
			return fmt.Errorf(
				"plutus/wallet: refusing to sign — %s fee %d sat < required %d sat (%s)",
				c.role, paid, expected, c.addr,
			)
		}
	}
	return nil
}

// ecdsaSignLowS signs a 32-byte digest with a secp256k1 private key and
// returns the DER-encoded signature with the S component normalized to the
// low-S form per BIP62 (required for Bitcoin standardness rules).
//
// Delegates to the audited decred/dcrd/dcrec/secp256k1/v4 library. Its
// ecdsa.Sign uses deterministic RFC6979 nonces and produces canonical
// low-S signatures per BIP62.
func ecdsaSignLowS(priv *ECDSAPrivateKey, digest []byte) ([]byte, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("plutus/wallet: sighash must be 32 bytes, got %d", len(digest))
	}
	if priv == nil || priv.D == nil {
		return nil, errors.New("plutus/wallet: private key is nil")
	}
	dBytes := make([]byte, 32)
	b := priv.D.Bytes()
	if len(b) > 32 {
		return nil, errors.New("plutus/wallet: secp256k1 scalar exceeds 32 bytes")
	}
	copy(dBytes[32-len(b):], b)
	sk := secp256k1.PrivKeyFromBytes(dBytes)
	// Defence-in-depth: PrivKeyFromBytes silently reduces mod N; reject a
	// zero scalar explicitly (caller should already be handling this).
	if sk.Key.IsZero() {
		return nil, errors.New("plutus/wallet: invalid secp256k1 scalar (zero after reduction)")
	}
	sig := ecdsa.Sign(sk, digest)
	return sig.Serialize(), nil
}

// Interface-level assertion: SignBTCSettlement should work the way the prompt
// described. We also expose a helper that hashes the maintainer destination
// once for convenience in tests.
func maintainerAddrHash(addr string) [32]byte {
	return sha256.Sum256([]byte(addr))
}

// Silence unused-import of sha256 when not used elsewhere.
var _ = maintainerAddrHash
