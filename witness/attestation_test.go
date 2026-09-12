/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"math/big"
	"testing"
	"time"
)

func makeAttestation(t *testing.T) (*ChainWitnessAttestation, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &ChainWitnessAttestation{
		ChainID:       "ethereum",
		TxHash:        "0xdeadbeef",
		BlockNumber:   100,
		Confirmed:     true,
		Balance:       big.NewInt(1000),
		WitnessPubKey: pub,
		Timestamp:     time.Unix(1_700_000_000, 0).UTC(),
		WitnessSeq:    1,
		RequestNonce:  []byte("nonce-abc"),
	}, priv
}

func TestSignVerifyAttestation_Roundtrip(t *testing.T) {
	t.Parallel()
	a, priv := makeAttestation(t)
	if err := SignAttestation(a, priv); err != nil {
		t.Fatalf("SignAttestation: %v", err)
	}
	if !VerifyAttestation(a) {
		t.Error("expected valid signature to verify")
	}
}

func TestVerifyAttestation_BadSignature(t *testing.T) {
	t.Parallel()
	a, priv := makeAttestation(t)
	if err := SignAttestation(a, priv); err != nil {
		t.Fatal(err)
	}
	a.Signature[0] ^= 0xFF
	if VerifyAttestation(a) {
		t.Error("tampered signature should not verify")
	}
}

func TestVerifyAttestation_TamperedContent(t *testing.T) {
	t.Parallel()
	a, priv := makeAttestation(t)
	if err := SignAttestation(a, priv); err != nil {
		t.Fatal(err)
	}
	a.Confirmed = !a.Confirmed
	if VerifyAttestation(a) {
		t.Error("tampered content should not verify")
	}
}

func TestVerifyAttestation_InvalidKeyOrSig(t *testing.T) {
	t.Parallel()
	a := &ChainWitnessAttestation{
		WitnessPubKey: []byte{1, 2, 3}, // too short
		Signature:     make([]byte, ed25519.SignatureSize),
	}
	if VerifyAttestation(a) {
		t.Error("short pubkey must not verify")
	}
	a.WitnessPubKey = make([]byte, ed25519.PublicKeySize)
	a.Signature = []byte{1, 2}
	if VerifyAttestation(a) {
		t.Error("short signature must not verify")
	}
}

func TestVerifyAttestationSequence(t *testing.T) {
	t.Parallel()
	a := &ChainWitnessAttestation{WitnessSeq: 5}
	if !VerifyAttestationSequence(a, 4) {
		t.Error("seq 5 > 4 should pass")
	}
	if VerifyAttestationSequence(a, 5) {
		t.Error("seq 5 == 5 should fail (replay)")
	}
	if VerifyAttestationSequence(a, 6) {
		t.Error("seq 5 < 6 should fail (replay)")
	}
}

func TestVerifyMerkleProofPresence(t *testing.T) {
	t.Parallel()
	a := &ChainWitnessAttestation{}
	if !VerifyMerkleProofPresence(a, false) {
		t.Error("no proof required -> should pass")
	}
	if VerifyMerkleProofPresence(a, true) {
		t.Error("proof required but absent -> should fail")
	}
	a.MerkleRoot = []byte("root")
	a.MerkleProof = [][]byte{[]byte("sibling")}
	if !VerifyMerkleProofPresence(a, true) {
		t.Error("proof required and present -> should pass")
	}
}

func TestAttestationHash_Deterministic(t *testing.T) {
	t.Parallel()
	a, _ := makeAttestation(t)
	h1 := AttestationHash(a)
	h2 := AttestationHash(a)
	if string(h1) != string(h2) {
		t.Error("attestation hash must be deterministic")
	}
}

func TestAttestationHash_DifferentOnChange(t *testing.T) {
	t.Parallel()
	a, _ := makeAttestation(t)
	h1 := AttestationHash(a)
	a.BlockNumber++
	h2 := AttestationHash(a)
	if string(h1) == string(h2) {
		t.Error("attestation hash should change on content change")
	}
}
