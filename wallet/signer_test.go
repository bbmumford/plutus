/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package wallet

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/bbmumford/plutus/adapter"
)

func TestSigner_SignEscrowFunding(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := NewSigner(priv, nil)
	tx := &adapter.UnsignedTx{Payload: []byte("escrow-fund-payload")}
	sig, err := s.SignEscrowFunding(tx)
	if err != nil {
		t.Fatalf("SignEscrowFunding: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, tx.Payload, sig) {
		t.Error("signature should verify")
	}
}

func TestSigner_SignEscrowFunding_EmptyPayload(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := NewSigner(priv, nil)
	if _, err := s.SignEscrowFunding(&adapter.UnsignedTx{}); err == nil {
		t.Error("expected error for empty payload")
	}
	if _, err := s.SignEscrowFunding(nil); err == nil {
		t.Error("expected error for nil tx")
	}
}

// stubVerifier provides fixed PRC data for signer tests.
type stubVerifier struct{ data []byte }

func (s *stubVerifier) AttestContractState(_ context.Context, _, _ string) ([]byte, error) {
	if s.data == nil {
		return nil, errors.New("no data")
	}
	return s.data, nil
}
func (s *stubVerifier) AttestEscrowState(_ context.Context, _, _ string) (*EscrowSnapshot, error) {
	return nil, errors.New("not used")
}

func TestSignSettlement_BelowPRCMinimum(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	// PRC with 100 BPS (1%) maintainer fee.
	prcData := &PRCData{
		MaintainerPayout:     "0x0000000000000000000000000000000000000001",
		MaintainerFeeBPS:     100,
		WitnessBPS:           0,
		MaintainerPubKeyHash: make([]byte, 32),
	}
	raw, _ := EncodePRCData(prcData)
	// NOTE: a full PRCResolver would call canonical.IsCanonicalPRC which
	// requires the chain to be in the PRC map. For this test we exercise
	// verifyFeesAgainstPRC directly rather than the cached resolver.
	s := NewSigner(priv, nil)
	_ = s
	_ = raw

	// Build a tx & fees where maintainer fee is too low (50 < 100 BPS of 10000).
	tx := &adapter.UnsignedTx{Payload: []byte("settle"), ChainID: "ethereum", Amount: big.NewInt(10_000)}
	expected := adapter.FeeBreakdown{
		Total:          big.NewInt(10_000),
		MaintainerFee:  big.NewInt(50),
		SellerProceeds: big.NewInt(9_950),
	}
	if err := verifyFeesAgainstPRC(tx, expected, prcData); err == nil {
		t.Error("expected fee-below-minimum error")
	} else if !strings.Contains(err.Error(), "below PRC minimum") {
		t.Errorf("unexpected error: %v", err)
	}

	// At exactly 100 BPS it should pass.
	expected.MaintainerFee = big.NewInt(100)
	expected.SellerProceeds = big.NewInt(9_900)
	if err := verifyFeesAgainstPRC(tx, expected, prcData); err != nil {
		t.Errorf("at-minimum should pass: %v", err)
	}
}

func TestVerifyFeeBreakdown_SumMismatch(t *testing.T) {
	t.Parallel()
	tx := &adapter.UnsignedTx{Amount: big.NewInt(1000)}
	fb := adapter.FeeBreakdown{
		Total:          big.NewInt(1000),
		MaintainerFee:  big.NewInt(10),
		SellerProceeds: big.NewInt(500), // sum = 510, not 1000
	}
	if err := verifyFeeBreakdown(tx, fb); err == nil {
		t.Error("expected sum-mismatch error")
	}
}

func TestVerifyFeeBreakdown_Valid(t *testing.T) {
	t.Parallel()
	tx := &adapter.UnsignedTx{Amount: big.NewInt(1000)}
	fb := adapter.FeeBreakdown{
		Total:          big.NewInt(1000),
		MaintainerFee:  big.NewInt(10),
		SellerProceeds: big.NewInt(990),
	}
	if err := verifyFeeBreakdown(tx, fb); err != nil {
		t.Errorf("valid breakdown: %v", err)
	}
}
