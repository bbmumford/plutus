/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package wallet

import (
	"testing"
)

func TestNewWallet_SeedLength(t *testing.T) {
	t.Parallel()
	if _, err := NewWallet(make([]byte, 32), nil); err == nil {
		t.Error("expected seed-length error for 32-byte seed")
	}
	if _, err := NewWallet(make([]byte, 64), nil); err != nil {
		t.Errorf("64-byte seed should be accepted: %v", err)
	}
}

func TestWallet_IdentityOnlyInitially(t *testing.T) {
	t.Parallel()
	w, err := NewWallet(make([]byte, 64), nil)
	if err != nil {
		t.Fatalf("NewWallet: %v", err)
	}
	if !w.IsIdentityOnly() {
		t.Error("freshly created wallet should be identity-only")
	}
}

func TestWallet_PeerID_Stable(t *testing.T) {
	t.Parallel()
	w, err := NewWallet(testSeed(), nil)
	if err != nil {
		t.Fatal(err)
	}
	id1 := w.PeerID()
	id2 := w.PeerID()
	if id1 != id2 {
		t.Error("PeerID should be stable")
	}
	if len(id1) != 64 {
		t.Errorf("PeerID hex length: got %d, want 64", len(id1))
	}
}

func TestChainIDToCoinType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		chainID string
		want    uint32
		err     bool
	}{
		{"ethereum", 60, false},
		{"polygon", 60, false},
		{"arbitrum", 60, false},
		{"bsc", 60, false},
		{"bitcoin", 0, false},
		{"doge", 0, true},
		{"", 0, true},
	}
	for _, tc := range cases {
		got, err := chainIDToCoinType(tc.chainID)
		if (err != nil) != tc.err {
			t.Errorf("%s: err=%v want err=%v", tc.chainID, err, tc.err)
		}
		if !tc.err && got != tc.want {
			t.Errorf("%s: got %d, want %d", tc.chainID, got, tc.want)
		}
	}
}

func TestMnemonicRoundTrip(t *testing.T) {
	t.Parallel()
	m, err := GenerateMnemonic()
	if err != nil {
		t.Fatalf("GenerateMnemonic: %v", err)
	}
	if !ValidateMnemonic(m) {
		t.Error("fresh mnemonic should validate")
	}
	seed, err := MnemonicToSeed(m, "passphrase")
	if err != nil {
		t.Fatalf("MnemonicToSeed: %v", err)
	}
	if len(seed) != 64 {
		t.Errorf("seed len: %d, want 64", len(seed))
	}
}

func TestValidateMnemonic_InvalidInputs(t *testing.T) {
	t.Parallel()
	if ValidateMnemonic("") {
		t.Error("empty should not validate")
	}
	if ValidateMnemonic("only three words here") {
		t.Error("short mnemonic should not validate")
	}
}
