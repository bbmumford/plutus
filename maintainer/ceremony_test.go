/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package maintainer

import (
	"crypto/ed25519"
	"testing"
	"time"
)

func TestGenerateOfflineRoot_And_DecryptRoundtrip(t *testing.T) {
	t.Parallel()
	key, enc, err := GenerateOfflineRoot("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("GenerateOfflineRoot: %v", err)
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("pubkey size: %d", len(key.PublicKey))
	}
	if len(enc) < 32+24 {
		t.Error("encrypted blob too small")
	}
	decrypted, err := DecryptOfflineRoot(key.PublicKey, enc, "correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("DecryptOfflineRoot: %v", err)
	}
	if !decrypted.PublicKey.Equal(key.PublicKey) {
		t.Error("decrypted pubkey mismatch")
	}
	// Wrong passphrase fails.
	if _, err := DecryptOfflineRoot(key.PublicKey, enc, "wrong"); err == nil {
		t.Error("expected decrypt failure for wrong passphrase")
	}
}

func TestGenerateOfflineRoot_RequiresPassphrase(t *testing.T) {
	t.Parallel()
	if _, _, err := GenerateOfflineRoot(""); err == nil {
		t.Error("expected error for empty passphrase")
	}
}

func TestGeneratePlatformKey_And_Verify(t *testing.T) {
	t.Parallel()
	or, _, err := GenerateOfflineRoot("pw")
	if err != nil {
		t.Fatal(err)
	}
	cert, platformPriv, err := GeneratePlatformKey(or)
	if err != nil {
		t.Fatalf("GeneratePlatformKey: %v", err)
	}
	if !VerifyPlatformCert(cert) {
		t.Error("freshly generated platform cert should verify")
	}
	if len(platformPriv) != ed25519.PrivateKeySize {
		t.Errorf("platform priv size: %d", len(platformPriv))
	}
	if !cert.OfflineRootPubKey.Equal(or.PublicKey) {
		t.Error("cert OR pubkey mismatch")
	}

	// Tampered cert fails verification.
	cert.Signature[0] ^= 0xFF
	if VerifyPlatformCert(cert) {
		t.Error("tampered cert should not verify")
	}
}

func TestGeneratePlatformKey_NilRoot(t *testing.T) {
	t.Parallel()
	if _, _, err := GeneratePlatformKey(nil); err == nil {
		t.Error("expected error for nil root")
	}
	if _, _, err := GeneratePlatformKey(&OfflineRootKey{}); err == nil {
		t.Error("expected error for empty root")
	}
}

func TestSignPRCDeployment_And_Verify(t *testing.T) {
	t.Parallel()
	or, _, _ := GenerateOfflineRoot("pw")
	cert, platformPriv, _ := GeneratePlatformKey(or)

	dep, err := SignPRCDeployment("ethereum", "0xPRC", "0xtxhash", 12345, platformPriv)
	if err != nil {
		t.Fatalf("SignPRCDeployment: %v", err)
	}
	if !VerifyPRCDeployment(dep, cert) {
		t.Error("freshly signed deployment should verify")
	}
	dep.Signature[0] ^= 0xFF
	if VerifyPRCDeployment(dep, cert) {
		t.Error("tampered deployment should not verify")
	}
}

func TestSignPRCDeployment_Validation(t *testing.T) {
	t.Parallel()
	_, platformPriv, _ := ed25519.GenerateKey(nil) // nil ok, uses rand
	cases := []struct {
		chainID, addr, tx string
		priv              ed25519.PrivateKey
	}{
		{"", "a", "b", platformPriv},
		{"c", "", "b", platformPriv},
		{"c", "a", "", platformPriv},
		{"c", "a", "b", ed25519.PrivateKey{1, 2, 3}},
	}
	for _, tc := range cases {
		if _, err := SignPRCDeployment(tc.chainID, tc.addr, tc.tx, 1, tc.priv); err == nil {
			t.Errorf("expected validation error for %+v", tc)
		}
	}
}

func TestPlatformCertPayload_Deterministic(t *testing.T) {
	t.Parallel()
	cert := &PlatformKeyCertificate{
		PlatformPubKey:    make(ed25519.PublicKey, 32),
		OfflineRootPubKey: make(ed25519.PublicKey, 32),
		IssuedAt:          time.Unix(1700000000, 0).UTC(),
	}
	a := platformCertPayload(cert)
	b := platformCertPayload(cert)
	if string(a) != string(b) {
		t.Error("payload must be deterministic")
	}
}

func TestSave_And_LoadPlatformCert(t *testing.T) {
	t.Parallel()
	or, _, _ := GenerateOfflineRoot("pw")
	cert, _, _ := GeneratePlatformKey(or)

	tmpFile := t.TempDir() + "/cert.json"
	if err := SavePlatformCert(tmpFile, cert); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadPlatformCert(tmpFile)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !VerifyPlatformCert(loaded) {
		t.Error("loaded cert must verify")
	}
}
