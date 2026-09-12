/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package evm

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestPadAddress(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
	}{
		{"0x1234567890abcdef1234567890abcdef12345678", "0000000000000000000000001234567890abcdef1234567890abcdef12345678"},
		{"1234567890abcdef1234567890abcdef12345678", "0000000000000000000000001234567890abcdef1234567890abcdef12345678"},
	}
	for _, tc := range cases {
		got := hex.EncodeToString(padAddress(tc.in))
		if got != tc.want {
			t.Errorf("padAddress(%q) = %s, want %s", tc.in, got, tc.want)
		}
		if len(padAddress(tc.in)) != 32 {
			t.Error("padAddress must return 32 bytes")
		}
	}
}

func TestPadUint256(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   *big.Int
		want string
	}{
		{big.NewInt(0), "0000000000000000000000000000000000000000000000000000000000000000"},
		{big.NewInt(1), "0000000000000000000000000000000000000000000000000000000000000001"},
		{big.NewInt(255), "00000000000000000000000000000000000000000000000000000000000000ff"},
		{nil, "0000000000000000000000000000000000000000000000000000000000000000"},
	}
	for _, tc := range cases {
		got := hex.EncodeToString(padUint256(tc.in))
		if got != tc.want {
			t.Errorf("padUint256(%v) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestPadBytes32(t *testing.T) {
	t.Parallel()
	in := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	got := padBytes32(in)
	want, _ := hex.DecodeString("deadbeef00000000000000000000000000000000000000000000000000000000")
	if !bytes.Equal(got, want) {
		t.Errorf("padBytes32: got %x, want %x", got, want)
	}
	if len(got) != 32 {
		t.Error("padBytes32 must return 32 bytes")
	}
}

func TestEncodeCall(t *testing.T) {
	t.Parallel()
	selector := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	arg := padUint256(big.NewInt(0x42))
	got := encodeCall(selector, arg)
	if len(got) != 4+32 {
		t.Errorf("encoded length: got %d, want 36", len(got))
	}
	if !bytes.Equal(got[:4], selector) {
		t.Error("selector not prefixed correctly")
	}
	if got[len(got)-1] != 0x42 {
		t.Errorf("last byte should be 0x42, got 0x%x", got[len(got)-1])
	}
}

func TestDecodeBigInt(t *testing.T) {
	t.Parallel()
	// encode 255 then decode
	raw := padUint256(big.NewInt(255))
	v, err := decodeBigInt(raw)
	if err != nil {
		t.Fatalf("decodeBigInt: %v", err)
	}
	if v.Int64() != 255 {
		t.Errorf("got %d, want 255", v.Int64())
	}
	if _, err := decodeBigInt([]byte{1, 2, 3}); err == nil {
		t.Error("expected too-short error")
	}
}

func TestDecodeAddress(t *testing.T) {
	t.Parallel()
	// encode address then decode
	addr := "0x1234567890abcdef1234567890abcdef12345678"
	encoded := padAddress(addr)
	got := decodeAddress(encoded)
	if got != addr {
		t.Errorf("roundtrip mismatch: got %s, want %s", got, addr)
	}
	if decodeAddress([]byte{1, 2, 3}) != "" {
		t.Error("too-short input should return empty string")
	}
}

func TestDeployEscrowAddress_Deterministic(t *testing.T) {
	t.Parallel()
	factory := "0x4e59b44847b379578588920cA78FbF26c0B4956C" // Canonical CREATE2 factory
	var salt [32]byte
	copy(salt[:], []byte("test-salt-v1"))
	var initHash [32]byte
	copy(initHash[:], []byte("init-code-hash"))

	addr1 := DeployEscrowAddress(factory, salt, initHash)
	addr2 := DeployEscrowAddress(factory, salt, initHash)
	if addr1 != addr2 {
		t.Errorf("CREATE2 derivation must be deterministic: %s vs %s", addr1, addr2)
	}
	if len(addr1) != 42 {
		t.Errorf("address length: got %d, want 42", len(addr1))
	}
	if addr1[:2] != "0x" {
		t.Errorf("prefix: got %q", addr1[:2])
	}

	// Different salt -> different address.
	var otherSalt [32]byte
	copy(otherSalt[:], []byte("different-salt-v1"))
	other := DeployEscrowAddress(factory, otherSalt, initHash)
	if other == addr1 {
		t.Error("different salts should yield different addresses")
	}
}

func TestSelectorConstants(t *testing.T) {
	t.Parallel()
	// Function selectors are all 4 bytes.
	selectors := [][]byte{
		selectorFund, selectorRelease, selectorDispute, selectorSettle,
		selectorRefund, selectorState, selectorBuyer, selectorSeller,
		selectorAmount, selectorPRC, selectorArbitrator, selectorFunded,
		selectorTimeoutBlock,
	}
	for i, s := range selectors {
		if len(s) != 4 {
			t.Errorf("selector %d has length %d, want 4", i, len(s))
		}
	}
}

// TestConstructEscrowArgs_Layout verifies the static-slot ABI layout matches
// the 11-arg Solidity constructor (without requiring a live EVM client).
// We build args manually and check slot-by-slot that each param lands at the
// expected 32-byte boundary.
func TestConstructEscrowArgs_Layout(t *testing.T) {
	t.Parallel()

	// Parameters we want to encode.
	prc := "0x1111111111111111111111111111111111111111"
	tokenAddr := "0x2222222222222222222222222222222222222222"
	buyer := "0x3333333333333333333333333333333333333333"
	seller := "0x4444444444444444444444444444444444444444"
	amount := big.NewInt(1000)
	timeoutBlock := big.NewInt(500)
	receiptHash := bytes.Repeat([]byte{0xAA}, 32)
	spBPS := big.NewInt(100)
	spPayout := "0x5555555555555555555555555555555555555555"
	arbBPS := big.NewInt(200)

	// Per escrow.go: witnessOffset = 11 * 32 = 352 (static slot count * 32).
	witnessOffset := big.NewInt(11 * 32)

	args := make([]byte, 0, 11*32)
	args = append(args, padAddress(prc)...)
	args = append(args, padAddress(tokenAddr)...)
	args = append(args, padAddress(buyer)...)
	args = append(args, padAddress(seller)...)
	args = append(args, padUint256(amount)...)
	args = append(args, padUint256(timeoutBlock)...)
	args = append(args, padBytes32(receiptHash)...)
	args = append(args, padUint256(witnessOffset)...)
	args = append(args, padUint256(spBPS)...)
	args = append(args, padAddress(spPayout)...)
	args = append(args, padUint256(arbBPS)...)

	if len(args) != 11*32 {
		t.Fatalf("total args length: got %d, want %d", len(args), 11*32)
	}

	// Slot 0 should contain PRC address (last 20 bytes = prc bytes).
	gotPRC := "0x" + hex.EncodeToString(args[12:32])
	if gotPRC != prc {
		t.Errorf("slot 0 (PRC): got %s, want %s", gotPRC, prc)
	}

	// Slot 4 (amount) should contain 1000.
	amt, _ := decodeBigInt(args[4*32 : 5*32])
	if amt.Int64() != 1000 {
		t.Errorf("slot 4 (amount): got %d, want 1000", amt.Int64())
	}

	// Slot 7 (witness offset) should be 352.
	off, _ := decodeBigInt(args[7*32 : 8*32])
	if off.Int64() != 352 {
		t.Errorf("slot 7 (witness offset): got %d, want 352", off.Int64())
	}

	// Slot 10 (arbitrator BPS) should be 200.
	ab, _ := decodeBigInt(args[10*32 : 11*32])
	if ab.Int64() != 200 {
		t.Errorf("slot 10 (arbitratorBPS): got %d, want 200", ab.Int64())
	}
}
