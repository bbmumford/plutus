/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package receipt

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"
)

func makeReceipt(t *testing.T) (*ServiceReceipt, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	content := sha256.Sum256([]byte("service-output"))
	nonce, err := GenerateNonce()
	if err != nil {
		t.Fatalf("GenerateNonce: %v", err)
	}
	r := &ServiceReceipt{
		ProviderPubKey: pub,
		BuyerNonce:     nonce,
		ServiceType:    "vdi-session",
		ContentHash:    content[:],
		Timestamp:      time.Now().UTC(),
	}
	return r, priv
}

func TestSignAndVerifyReceipt(t *testing.T) {
	t.Parallel()
	r, priv := makeReceipt(t)
	if err := SignReceipt(r, priv); err != nil {
		t.Fatalf("SignReceipt: %v", err)
	}
	if len(r.Signature) != ed25519.SignatureSize {
		t.Fatalf("signature size: got %d", len(r.Signature))
	}
	ok, err := VerifyReceipt(r)
	if err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
	if !ok {
		t.Error("expected verify true for fresh signature")
	}
}

func TestVerifyReceipt_Tampered(t *testing.T) {
	t.Parallel()
	r, priv := makeReceipt(t)
	if err := SignReceipt(r, priv); err != nil {
		t.Fatal(err)
	}
	r.ServiceType = "different-service"
	ok, err := VerifyReceipt(r)
	if err != nil {
		t.Fatalf("VerifyReceipt error: %v", err)
	}
	if ok {
		t.Error("tampered receipt should not verify")
	}
}

func TestSignReceipt_ValidationErrors(t *testing.T) {
	t.Parallel()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Missing everything.
	empty := &ServiceReceipt{}
	if err := SignReceipt(empty, priv); err == nil {
		t.Error("expected validation error for empty receipt")
	}
	// Short private key.
	r, _ := makeReceipt(t)
	if err := SignReceipt(r, ed25519.PrivateKey{1, 2, 3}); err == nil {
		t.Error("expected error for invalid private key")
	}
}

func TestReceiptHash_Stable(t *testing.T) {
	t.Parallel()
	r, priv := makeReceipt(t)
	if err := SignReceipt(r, priv); err != nil {
		t.Fatal(err)
	}
	h1, err := ReceiptHash(r)
	if err != nil {
		t.Fatalf("ReceiptHash: %v", err)
	}
	h2, err := ReceiptHash(r)
	if err != nil {
		t.Fatalf("ReceiptHash 2: %v", err)
	}
	if string(h1) != string(h2) {
		t.Error("ReceiptHash must be deterministic for same receipt")
	}

	// Unsigned -> error.
	r.Signature = nil
	if _, err := ReceiptHash(r); err == nil {
		t.Error("expected error for unsigned receipt")
	}
}

// A signature binds the buyer nonce and the content hash as they were signed:
// a byte moved from the content hash onto the end of the nonce leaves the
// digest's input unchanged, so that receipt must be refused, not verified.
func TestVerifyReceipt_RefusesAShiftedFieldBoundary(t *testing.T) {
	t.Parallel()
	r, priv := makeReceipt(t)
	if err := SignReceipt(r, priv); err != nil {
		t.Fatal(err)
	}
	shifted := *r
	shifted.BuyerNonce = append(append([]byte{}, r.BuyerNonce...), r.ContentHash[0])
	shifted.ContentHash = append([]byte{}, r.ContentHash[1:]...)
	ok, err := VerifyReceipt(&shifted)
	if err == nil || ok {
		t.Fatalf("a receipt whose nonce took the content hash's first byte was accepted (ok=%v, err=%v)", ok, err)
	}
}

// Signing and verifying refuse a nonce or a content hash of any size but its
// own, so no receipt is signed or accepted over a field boundary the digest
// does not record.
func TestReceipt_RefusesWrongFieldSizes(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*ServiceReceipt){
		"short nonce":        func(r *ServiceReceipt) { r.BuyerNonce = r.BuyerNonce[:NonceSize-1] },
		"long nonce":         func(r *ServiceReceipt) { r.BuyerNonce = append(r.BuyerNonce, 0) },
		"short content hash": func(r *ServiceReceipt) { r.ContentHash = r.ContentHash[:sha256.Size-1] },
		"long content hash":  func(r *ServiceReceipt) { r.ContentHash = append(r.ContentHash, 0) },
	}
	for name, mutate := range cases {
		r, priv := makeReceipt(t)
		mutate(r)
		if err := SignReceipt(r, priv); err == nil {
			t.Errorf("%s: SignReceipt signed it", name)
		}
		signed, priv2 := makeReceipt(t)
		if err := SignReceipt(signed, priv2); err != nil {
			t.Fatal(err)
		}
		mutate(signed)
		if ok, err := VerifyReceipt(signed); err == nil || ok {
			t.Errorf("%s: VerifyReceipt accepted it (ok=%v, err=%v)", name, ok, err)
		}
	}
}
