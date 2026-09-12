/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package maintainer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
	"time"
)

func TestRotate_And_Verify(t *testing.T) {
	t.Parallel()
	_, oldPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Rotate(RotateConfig{OldKey: oldPriv, Reason: "scheduled"})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if res.Cert == nil || res.NewPrivKey == nil {
		t.Fatal("rotation result missing fields")
	}
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	oldHash := sha256.Sum256(oldPub)
	if err := VerifyRotationCert(res.Cert, oldHash[:]); err != nil {
		t.Errorf("VerifyRotationCert: %v", err)
	}
}

func TestRotate_BadGracePeriod(t *testing.T) {
	t.Parallel()
	_, oldPriv, _ := ed25519.GenerateKey(nil)
	if _, err := Rotate(RotateConfig{OldKey: oldPriv, GracePeriod: 1 * time.Hour}); err == nil {
		t.Error("expected error for grace period <24h")
	}
}

func TestRotate_InvalidOldKey(t *testing.T) {
	t.Parallel()
	if _, err := Rotate(RotateConfig{OldKey: ed25519.PrivateKey{1}}); err == nil {
		t.Error("expected error for invalid old key")
	}
}

func TestVerifyRotationCert_BadSignature(t *testing.T) {
	t.Parallel()
	_, oldPriv, _ := ed25519.GenerateKey(nil)
	res, _ := Rotate(RotateConfig{OldKey: oldPriv})
	res.Cert.Signature[0] ^= 0xFF
	oldPub := oldPriv.Public().(ed25519.PublicKey)
	oldHash := sha256.Sum256(oldPub)
	if err := VerifyRotationCert(res.Cert, oldHash[:]); err == nil {
		t.Error("expected signature failure")
	}
}

func TestVerifyRotationCert_WrongHash(t *testing.T) {
	t.Parallel()
	_, oldPriv, _ := ed25519.GenerateKey(nil)
	res, _ := Rotate(RotateConfig{OldKey: oldPriv})
	bogus := make([]byte, 32)
	if err := VerifyRotationCert(res.Cert, bogus); err == nil {
		t.Error("expected hash mismatch error")
	}
}

func TestIsInGracePeriod(t *testing.T) {
	t.Parallel()
	_, oldPriv, _ := ed25519.GenerateKey(nil)
	res, _ := Rotate(RotateConfig{OldKey: oldPriv})
	if !IsInGracePeriod(res.Cert) {
		t.Error("freshly rotated cert should be in grace period")
	}
	res.Cert.ExpiresAt = time.Now().Add(-1 * time.Hour)
	if IsInGracePeriod(res.Cert) {
		t.Error("expired cert should not be in grace period")
	}
}

// TestIsInGracePeriod_ImmediatelyAfterRotation guards against the original
// off-by-zero where now.After(now) returned false on fast hardware, making a
// just-rotated cert report "not in grace period" until at least 1ns elapsed.
func TestIsInGracePeriod_ImmediatelyAfterRotation(t *testing.T) {
	t.Parallel()
	_, oldPriv, _ := ed25519.GenerateKey(nil)
	res, err := Rotate(RotateConfig{OldKey: oldPriv})
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	// No sleep, no backdate — the cert was just minted and MUST be in grace.
	if !IsInGracePeriod(res.Cert) {
		t.Fatal("cert must be in grace period immediately after Rotate()")
	}
	// Nil-safe.
	if IsInGracePeriod(nil) {
		t.Error("nil cert must not be in grace period")
	}
}

func TestAcceptedPubKeyHashes(t *testing.T) {
	t.Parallel()
	if hashes := AcceptedPubKeyHashes(nil); hashes != nil {
		t.Error("nil cert should return nil")
	}
	_, oldPriv, _ := ed25519.GenerateKey(nil)
	res, _ := Rotate(RotateConfig{OldKey: oldPriv})
	hashes := AcceptedPubKeyHashes(res.Cert)
	if len(hashes) != 2 {
		t.Errorf("expected 2 accepted hashes during grace, got %d", len(hashes))
	}
}

func TestSave_And_LoadRotationCert(t *testing.T) {
	t.Parallel()
	_, oldPriv, _ := ed25519.GenerateKey(nil)
	res, _ := Rotate(RotateConfig{OldKey: oldPriv, Reason: "test"})
	path := t.TempDir() + "/rot.json"
	if err := SaveRotationCert(path, res.Cert); err != nil {
		t.Fatalf("SaveRotationCert: %v", err)
	}
	loaded, err := LoadRotationCert(path)
	if err != nil {
		t.Fatalf("LoadRotationCert: %v", err)
	}
	if loaded.Reason != "test" {
		t.Errorf("reason mismatch: %q", loaded.Reason)
	}
}

func TestRotatePlatformKey(t *testing.T) {
	t.Parallel()
	or, _, _ := GenerateOfflineRoot("pw")
	oldCert, _, _ := GeneratePlatformKey(or)

	res, err := RotatePlatformKey(or, oldCert)
	if err != nil {
		t.Fatalf("RotatePlatformKey: %v", err)
	}
	if !VerifyPlatformCert(res.NewCert) {
		t.Error("new cert should verify")
	}
	if res.NewCert.PlatformPubKey.Equal(oldCert.PlatformPubKey) {
		t.Error("new pubkey should differ from old")
	}
}
