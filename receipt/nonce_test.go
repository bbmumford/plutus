/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
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

func TestGenerateNonce_Length(t *testing.T) {
	t.Parallel()
	n, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	if len(n) != NonceSize {
		t.Errorf("nonce length: got %d, want %d", len(n), NonceSize)
	}
}

func TestGenerateNonce_Unique(t *testing.T) {
	t.Parallel()
	a, _ := GenerateNonce()
	b, _ := GenerateNonce()
	if bytes.Equal(a, b) {
		t.Error("two nonces should be distinct")
	}
}

func TestNonceHexRoundTrip(t *testing.T) {
	t.Parallel()
	n, _ := GenerateNonce()
	s := NonceToHex(n)
	decoded, err := NonceFromHex(s)
	if err != nil {
		t.Fatalf("NonceFromHex: %v", err)
	}
	if !bytes.Equal(n, decoded) {
		t.Error("round-trip mismatch")
	}
}

func TestNonceFromHex_Errors(t *testing.T) {
	t.Parallel()
	if _, err := NonceFromHex("not-hex!!!"); err == nil {
		t.Error("expected hex decode error")
	}
	if _, err := NonceFromHex("ababab"); err == nil {
		t.Error("expected length error for short nonce")
	}
}

// TestReceiptReplay verifies that two receipts with the same nonce produce
// the same hash (so a replay can be detected by hash comparison downstream).
func TestReceiptReplay(t *testing.T) {
	t.Parallel()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	nonce := bytes.Repeat([]byte{0x42}, NonceSize)
	content := sha256.Sum256([]byte("x"))
	ts := time.Unix(1_700_000_000, 0).UTC()

	r1 := &ServiceReceipt{
		ProviderPubKey: pub, BuyerNonce: nonce,
		ServiceType: "s", ContentHash: content[:], Timestamp: ts,
	}
	r2 := &ServiceReceipt{
		ProviderPubKey: pub, BuyerNonce: nonce,
		ServiceType: "s", ContentHash: content[:], Timestamp: ts,
	}
	_ = SignReceipt(r1, priv)
	_ = SignReceipt(r2, priv)
	h1, _ := ReceiptHash(r1)
	h2, _ := ReceiptHash(r2)
	if !bytes.Equal(h1, h2) {
		t.Error("identical receipt content should produce identical hash (replay detection)")
	}
}
