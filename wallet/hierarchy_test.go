/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package wallet

import (
	"bytes"
	"crypto/sha256"
	"math/big"
	"testing"
)

func testSeed() []byte {
	// Deterministic 64-byte seed for reproducible tests.
	s := sha256.Sum256([]byte("deterministic-seed-test-vector-v1"))
	t := sha256.Sum256([]byte("deterministic-seed-test-vector-v2"))
	out := make([]byte, 64)
	copy(out[:32], s[:])
	copy(out[32:], t[:])
	return out
}

func TestDeriveProtocolIdentity_Deterministic(t *testing.T) {
	t.Parallel()
	seed := testSeed()
	k1, err := DeriveProtocolIdentity(seed)
	if err != nil {
		t.Fatalf("DeriveProtocolIdentity: %v", err)
	}
	k2, err := DeriveProtocolIdentity(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(k1, k2) {
		t.Error("identity derivation must be deterministic")
	}
}

func TestDeriveProtocolIdentity_BadSeedLen(t *testing.T) {
	t.Parallel()
	if _, err := DeriveProtocolIdentity(make([]byte, 32)); err == nil {
		t.Error("expected seed-length error")
	}
}

func TestDeriveDifferentIdentities(t *testing.T) {
	t.Parallel()
	seed := testSeed()
	protocol, _ := DeriveProtocolIdentity(seed)
	store, _ := DeriveStoreIdentity(seed)
	replicator, _ := DeriveReplicatorKey(seed)
	arbitrator, _ := DeriveArbitratorKey(seed)

	// All should differ pairwise.
	if bytes.Equal(protocol, store) {
		t.Error("protocol and store keys collide")
	}
	if bytes.Equal(protocol, replicator) {
		t.Error("protocol and replicator keys collide")
	}
	if bytes.Equal(store, replicator) {
		t.Error("store and replicator keys collide")
	}
	if bytes.Equal(replicator, arbitrator) {
		t.Error("replicator and arbitrator keys collide")
	}
}

// DeriveChainKey and DeriveOrderEscrowKey previously triggered a Go 1.25
// strict-on-curve panic because BIP32 non-hardened steps called
// elliptic.CurveParams.ScalarBaseMult on the fake secp256k1 CurveParams.
// Point ops now go through the pure-Go scalarMultG (secp256k1_sign.go),
// so the hierarchy tests are fully exercised.

func TestDeriveOrderEscrowKey_Validation(t *testing.T) {
	t.Parallel()
	chaincode := sha256.Sum256([]byte("order-id-1"))
	if _, err := DeriveOrderEscrowKey(nil, chaincode[:]); err == nil {
		t.Error("expected nil master error")
	}
	// Chaincode-length validation should fail before any curve op.
	dummyMaster := &ECDSAPrivateKey{D: new(big.Int).SetInt64(1)}
	if _, err := DeriveOrderEscrowKey(dummyMaster, []byte{1, 2, 3}); err == nil {
		t.Error("expected chaincode length error")
	}
}

func TestDeriveChainKey_DeterministicAcrossRuns(t *testing.T) {
	t.Parallel()
	seed := testSeed()
	const coinTypeETH uint32 = 60
	k1, err := DeriveChainKey(seed, coinTypeETH, 0)
	if err != nil {
		t.Fatalf("DeriveChainKey (run 1): %v", err)
	}
	k2, err := DeriveChainKey(seed, coinTypeETH, 0)
	if err != nil {
		t.Fatalf("DeriveChainKey (run 2): %v", err)
	}
	if k1.D.Cmp(k2.D) != 0 {
		t.Error("DeriveChainKey: private scalar must be deterministic across runs")
	}
	if k1.X.Cmp(k2.X) != 0 || k1.Y.Cmp(k2.Y) != 0 {
		t.Error("DeriveChainKey: public point must be deterministic across runs")
	}

	// Different account indices must produce different keys.
	k3, err := DeriveChainKey(seed, coinTypeETH, 1)
	if err != nil {
		t.Fatalf("DeriveChainKey (account 1): %v", err)
	}
	if k1.D.Cmp(k3.D) == 0 {
		t.Error("DeriveChainKey: different account must yield different scalar")
	}
}

func TestChainAddress_Deterministic(t *testing.T) {
	t.Parallel()
	seed := testSeed()
	const coinTypeETH uint32 = 60
	key, err := DeriveChainKey(seed, coinTypeETH, 0)
	if err != nil {
		t.Fatalf("DeriveChainKey: %v", err)
	}
	addr1 := ChainAddress(key)
	addr2 := ChainAddress(key)
	if addr1 != addr2 {
		t.Errorf("ChainAddress must be deterministic: %q vs %q", addr1, addr2)
	}

	// Sanity: EIP-55 format is "0x" + 40 hex chars.
	if len(addr1) != 42 || addr1[:2] != "0x" {
		t.Errorf("address format wrong: %q", addr1)
	}
	// Must contain at least one mixed-case char (statistically near-certain)
	// unless the address happens to have no letters — in which case this
	// check is vacuous. We just ensure every char after 0x is hex.
	for i := 2; i < len(addr1); i++ {
		c := addr1[i]
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			t.Errorf("non-hex char in address: %q at index %d", c, i)
		}
	}
}

func TestDeriveOrderEscrowKey_PerOrderDistinct(t *testing.T) {
	t.Parallel()
	seed := testSeed()
	// Master key for the orders — derived from BIP44 BTC (coinType 0).
	const coinTypeBTC uint32 = 0
	master, err := DeriveChainKey(seed, coinTypeBTC, 0)
	if err != nil {
		t.Fatalf("master DeriveChainKey: %v", err)
	}

	cc1 := sha256.Sum256([]byte("order-id-1"))
	cc2 := sha256.Sum256([]byte("order-id-2"))

	k1, err := DeriveOrderEscrowKey(master, cc1[:])
	if err != nil {
		t.Fatalf("DeriveOrderEscrowKey order-1: %v", err)
	}
	k2, err := DeriveOrderEscrowKey(master, cc2[:])
	if err != nil {
		t.Fatalf("DeriveOrderEscrowKey order-2: %v", err)
	}
	if k1.D.Cmp(k2.D) == 0 {
		t.Error("different orders must produce different escrow scalars")
	}
	if k1.X.Cmp(k2.X) == 0 && k1.Y.Cmp(k2.Y) == 0 {
		t.Error("different orders must produce different escrow public points")
	}

	// Determinism per order.
	k1b, err := DeriveOrderEscrowKey(master, cc1[:])
	if err != nil {
		t.Fatalf("DeriveOrderEscrowKey order-1 (redo): %v", err)
	}
	if k1.D.Cmp(k1b.D) != 0 {
		t.Error("same order must produce the same escrow scalar")
	}

	// Sanity: the derived public key is 65 bytes (uncompressed, 0x04 prefix).
	pub := k1.PublicKeyBytes()
	if len(pub) != 65 || pub[0] != 0x04 {
		t.Errorf("PublicKeyBytes invalid: len=%d prefix=0x%x", len(pub), pub[0])
	}
}
