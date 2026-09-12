/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package receipt

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

func makeSignedReceipt(t *testing.T, content string) *ServiceReceipt {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	nonce, _ := GenerateNonce()
	ch := sha256.Sum256([]byte(content))
	r := &ServiceReceipt{
		ProviderPubKey: pub,
		BuyerNonce:     nonce,
		ServiceType:    "t",
		ContentHash:    ch[:],
		Timestamp:      time.Now(),
	}
	if err := SignReceipt(r, priv); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return r
}

func TestNewReceiptBundle_Empty(t *testing.T) {
	t.Parallel()
	if _, err := NewReceiptBundle(nil); err == nil {
		t.Error("expected error for empty receipt list")
	}
}

func TestReceiptBundle_SingleReceipt(t *testing.T) {
	t.Parallel()
	r := makeSignedReceipt(t, "a")
	b, err := NewReceiptBundle([]*ServiceReceipt{r})
	if err != nil {
		t.Fatalf("NewReceiptBundle: %v", err)
	}
	if len(b.Hashes) != 1 {
		t.Fatalf("hashes len: %d", len(b.Hashes))
	}
	if !bytes.Equal(b.MerkleRoot, b.Hashes[0]) {
		t.Error("single-leaf Merkle root should equal leaf hash")
	}
	if err := b.VerifyBundle(); err != nil {
		t.Errorf("VerifyBundle: %v", err)
	}
}

func TestReceiptBundle_MerkleProof(t *testing.T) {
	t.Parallel()
	receipts := []*ServiceReceipt{
		makeSignedReceipt(t, "a"),
		makeSignedReceipt(t, "b"),
		makeSignedReceipt(t, "c"),
		makeSignedReceipt(t, "d"),
	}
	b, err := NewReceiptBundle(receipts)
	if err != nil {
		t.Fatalf("NewReceiptBundle: %v", err)
	}
	if len(b.MerkleRoot) != sha256.Size {
		t.Errorf("root size: %d", len(b.MerkleRoot))
	}
	// Verify proof for each leaf.
	for i := range receipts {
		proof, err := b.MerkleProof(i)
		if err != nil {
			t.Fatalf("MerkleProof(%d): %v", i, err)
		}
		if !VerifyMerkleProof(b.Hashes[i], i, proof, b.MerkleRoot) {
			t.Errorf("Merkle proof verification failed for index %d", i)
		}
	}
}

func TestReceiptBundle_TamperDetection(t *testing.T) {
	t.Parallel()
	receipts := []*ServiceReceipt{
		makeSignedReceipt(t, "a"),
		makeSignedReceipt(t, "b"),
	}
	b, err := NewReceiptBundle(receipts)
	if err != nil {
		t.Fatal(err)
	}
	// Tamper with Merkle root.
	b.MerkleRoot[0] ^= 0xFF
	if err := b.VerifyBundle(); err == nil {
		t.Error("expected VerifyBundle to detect tampered root")
	}
}

func TestReceiptBundle_MerkleProofOutOfRange(t *testing.T) {
	t.Parallel()
	receipts := []*ServiceReceipt{makeSignedReceipt(t, "a")}
	b, _ := NewReceiptBundle(receipts)
	if _, err := b.MerkleProof(-1); err == nil {
		t.Error("expected out-of-range error")
	}
	if _, err := b.MerkleProof(10); err == nil {
		t.Error("expected out-of-range error")
	}
}
