/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evmsign

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
)

func TestRLPBytes_EncodingMatchesSpec(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   []byte
		want string
	}{
		{nil, "80"},                            // empty string → 0x80
		{[]byte{0x00}, "00"},                   // single byte < 0x80
		{[]byte{0x7f}, "7f"},                   // single byte < 0x80
		{[]byte{0x80}, "8180"},                 // single byte >= 0x80 → 0x81+byte
		{[]byte{0x01, 0x02, 0x03}, "83010203"}, // len 3
	}
	for _, tc := range cases {
		got := hex.EncodeToString(RLPBytes(tc.in))
		if got != tc.want {
			t.Errorf("RLPBytes(%x) = %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestRLPUint_ZeroEncodesEmpty(t *testing.T) {
	t.Parallel()
	got := RLPUint(0)
	want := []byte{0x80}
	if !bytes.Equal(got, want) {
		t.Errorf("RLPUint(0) = %x, want %x", got, want)
	}
}

func TestRLPUint_StripsLeadingZeros(t *testing.T) {
	t.Parallel()
	got := RLPUint(0x0001)
	want := []byte{0x01}
	if !bytes.Equal(got, want) {
		t.Errorf("RLPUint(1) = %x, want %x", got, want)
	}
}

func TestRLPBigInt_NilAndZeroSameAsEmptyString(t *testing.T) {
	t.Parallel()
	if got := RLPBigInt(nil); !bytes.Equal(got, []byte{0x80}) {
		t.Errorf("RLPBigInt(nil) = %x, want 80", got)
	}
	if got := RLPBigInt(big.NewInt(0)); !bytes.Equal(got, []byte{0x80}) {
		t.Errorf("RLPBigInt(0) = %x, want 80", got)
	}
}

func TestRLPList_EmptyList(t *testing.T) {
	t.Parallel()
	got := RLPList()
	want := []byte{0xc0}
	if !bytes.Equal(got, want) {
		t.Errorf("RLPList() = %x, want c0", got)
	}
}

func TestSignLegacyTxEIP155_ProducesStableBytes(t *testing.T) {
	t.Parallel()
	// Known-good fixture. We don't assert on the exact bytes
	// (dcrec's RFC6979 is deterministic so this is reproducible,
	// but keeping the assertion at the structural level — two
	// signs of the same inputs produce the same output — is
	// sufficient for a smoke test; exhaustive consensus fixtures
	// live in plutus/witness/wallet_signer_test.go).
	priv, err := hex.DecodeString("4646464646464646464646464646464646464646464646464646464646464646")
	if err != nil {
		t.Fatalf("priv: %v", err)
	}
	tx := LegacyTx{
		Nonce:      9,
		GasPrice:   big.NewInt(20_000_000_000),
		GasLimit:   21000,
		To:         "0x3535353535353535353535353535353535353535",
		Value:      big.NewInt(1_000_000_000_000_000_000),
		Data:       nil,
		EVMChainID: 1,
	}
	a, err := SignLegacyTxEIP155(tx, priv)
	if err != nil {
		t.Fatalf("sign A: %v", err)
	}
	b, err := SignLegacyTxEIP155(tx, priv)
	if err != nil {
		t.Fatalf("sign B: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("deterministic sign produced differing outputs:\n a=%x\n b=%x", a, b)
	}
	// Sanity: top-level is an RLP list (prefix >= 0xc0).
	if len(a) == 0 || a[0] < 0xc0 {
		t.Errorf("signed tx should start with RLP list prefix, got %x", a[:1])
	}
}

func TestSignLegacyTxEIP155_RejectsZeroChainID(t *testing.T) {
	t.Parallel()
	priv := bytes.Repeat([]byte{1}, 32)
	_, err := SignLegacyTxEIP155(LegacyTx{GasPrice: big.NewInt(1)}, priv)
	if err == nil || !strings.Contains(err.Error(), "chain ID is zero") {
		t.Errorf("expected chain ID error, got %v", err)
	}
}

func TestSignLegacyTxEIP155_RejectsBadKeyLen(t *testing.T) {
	t.Parallel()
	_, err := SignLegacyTxEIP155(LegacyTx{
		GasPrice:   big.NewInt(1),
		EVMChainID: 1,
	}, []byte{1, 2, 3})
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("expected key-length error, got %v", err)
	}
}

func TestAddressFromPrivKey_ValidatesKey(t *testing.T) {
	t.Parallel()
	priv, _ := hex.DecodeString("4646464646464646464646464646464646464646464646464646464646464646")
	addr, err := AddressFromPrivKey(priv)
	if err != nil {
		t.Fatalf("AddressFromPrivKey: %v", err)
	}
	if !strings.HasPrefix(addr, "0x") || len(addr) != 42 {
		t.Errorf("bad address shape: %q", addr)
	}
	// Known expected checksum for this key (EIP-155 book vector):
	// https://ethereum.github.io/execution-specs/  (cross-reference).
	want := "0x9d8A62f656a8d1615C1294fd71e9CFb3E4855A4F"
	if strings.ToLower(addr) != strings.ToLower(want) {
		t.Errorf("address = %s, want (case-insensitive) %s", addr, want)
	}
}
