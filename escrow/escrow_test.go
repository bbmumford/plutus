/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package escrow

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"strings"
	"testing"
)

// makeSnapshot builds an EscrowSnapshot with default quorum=true.
func makeSnapshot(setState func(s *OnChainEscrowState)) *EscrowSnapshot {
	s := OnChainEscrowState{
		Buyer:  "0xB",
		Seller: "0xS",
		Amount: big.NewInt(1000),
	}
	if setState != nil {
		setState(&s)
	}
	return &EscrowSnapshot{
		State:  s,
		Quorum: true,
	}
}

func TestValidateReleasable(t *testing.T) {
	t.Parallel()

	if err := validateReleasable(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded = true
	})); err != nil {
		t.Errorf("valid funded escrow: %v", err)
	}

	// Unfunded.
	if err := validateReleasable(makeSnapshot(nil)); err == nil {
		t.Error("expected unfunded error")
	}
	// No quorum.
	snap := makeSnapshot(func(s *OnChainEscrowState) { s.Funded = true })
	snap.Quorum = false
	if err := validateReleasable(snap); err == nil {
		t.Error("expected quorum error")
	}
	// Already released.
	if err := validateReleasable(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded, s.Released = true, true
	})); err == nil {
		t.Error("expected already-released error")
	}
	// Disputed.
	if err := validateReleasable(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded, s.Disputed = true, true
	})); err == nil {
		t.Error("expected dispute error")
	}
	// Timed out.
	if err := validateReleasable(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded, s.TimedOut = true, true
	})); err == nil {
		t.Error("expected timed-out error")
	}
}

func TestValidateDisputable(t *testing.T) {
	t.Parallel()
	if err := validateDisputable(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded = true
	})); err != nil {
		t.Errorf("valid funded: %v", err)
	}
	if err := validateDisputable(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded, s.Disputed = true, true
	})); err == nil {
		t.Error("double-dispute should fail")
	}
	if err := validateDisputable(makeSnapshot(nil)); err == nil {
		t.Error("unfunded dispute should fail")
	}
}

func TestValidateSettleable(t *testing.T) {
	t.Parallel()
	if err := validateSettleable(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded, s.Disputed = true, true
	})); err != nil {
		t.Errorf("valid disputed: %v", err)
	}
	if err := validateSettleable(makeSnapshot(nil)); err == nil {
		t.Error("non-disputed should fail")
	}
	if err := validateSettleable(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded, s.Disputed, s.Settled = true, true, true
	})); err == nil {
		t.Error("already settled should fail")
	}
}

func TestValidateTimedOut(t *testing.T) {
	t.Parallel()
	// Explicit TimedOut flag.
	if err := validateTimedOut(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded, s.TimedOut = true, true
	})); err != nil {
		t.Errorf("TimedOut flag case: %v", err)
	}
	// Current block >= timeout block.
	if err := validateTimedOut(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded = true
		s.CurrentBlock = 100
		s.TimeoutBlock = 50
	})); err != nil {
		t.Errorf("block-based timeout: %v", err)
	}
	// Block ordering not timed out.
	if err := validateTimedOut(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded = true
		s.CurrentBlock = 10
		s.TimeoutBlock = 100
	})); err == nil {
		t.Error("should reject non-timed-out escrow")
	}
	// Already released.
	if err := validateTimedOut(makeSnapshot(func(s *OnChainEscrowState) {
		s.Funded, s.Released, s.TimedOut = true, true, true
	})); err == nil {
		t.Error("released escrow should not be refundable")
	}
}

func TestValidateRuling(t *testing.T) {
	t.Parallel()
	if err := validateRuling(Ruling{BuyerPercent: 40, SellerPercent: 60, ArbitratorSig: []byte{0x01}}); err != nil {
		t.Errorf("valid ruling: %v", err)
	}
	if err := validateRuling(Ruling{BuyerPercent: 40, SellerPercent: 50, ArbitratorSig: []byte{0x01}}); err == nil {
		t.Error("percent sum != 100 should fail")
	}
	if err := validateRuling(Ruling{BuyerPercent: 40, SellerPercent: 60}); err == nil {
		t.Error("missing arbitrator sig should fail")
	}
}

func TestAnchorEvidence(t *testing.T) {
	t.Parallel()
	h, err := AnchorEvidence([]byte("evidence-data"))
	if err != nil {
		t.Fatalf("AnchorEvidence: %v", err)
	}
	want := sha256.Sum256([]byte("evidence-data"))
	if !bytes.Equal(h, want[:]) {
		t.Error("anchor hash mismatch")
	}
	if _, err := AnchorEvidence(nil); err == nil {
		t.Error("expected error for empty evidence")
	}
}

func TestAppendSignature_Format(t *testing.T) {
	t.Parallel()
	tx := &UnsignedTx{Data: []byte("payload")}
	sig := []byte("signature")
	signed := appendSignature(tx, sig)

	if len(signed) != 4+len(tx.Data)+len(sig) {
		t.Errorf("bad total length: %d", len(signed))
	}
	// Check data-length prefix (big endian).
	if signed[0] != 0 || signed[1] != 0 || signed[2] != 0 || signed[3] != byte(len(tx.Data)) {
		t.Errorf("bad length prefix: %v", signed[:4])
	}
	// Check payload and signature ordering.
	if !bytes.Equal(signed[4:4+len(tx.Data)], tx.Data) {
		t.Error("data section mismatch")
	}
	if !bytes.Equal(signed[4+len(tx.Data):], sig) {
		t.Error("signature section mismatch")
	}
}

func TestDeriveEscrowAddress(t *testing.T) {
	t.Parallel()
	addr := deriveEscrowAddress("ethereum", "0xtxhash")
	if !strings.Contains(addr, "ethereum") {
		t.Errorf("addr should include chainID: %s", addr)
	}
	if !strings.Contains(addr, "0xtxhash") {
		t.Errorf("addr should include txhash: %s", addr)
	}
}

func TestSnapshotToState(t *testing.T) {
	t.Parallel()
	snap := &EscrowSnapshot{
		State: OnChainEscrowState{
			Funded: true,
		},
	}
	st := snapshotToState("0xE", "ethereum", snap)
	if st.Status != StatusFunded {
		t.Errorf("status: got %s, want funded", st.Status)
	}

	snap.State.Disputed = true
	st = snapshotToState("0xE", "ethereum", snap)
	if st.Status != StatusDisputed {
		t.Errorf("status: got %s, want disputed", st.Status)
	}
}
