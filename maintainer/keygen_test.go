/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package maintainer

import (
	"crypto/ed25519"
	"testing"
)

func TestGenerateKey_Fields(t *testing.T) {
	t.Parallel()
	key, priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("priv size: %d", len(priv))
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("pub size: %d", len(key.PublicKey))
	}
	if key.PublicKeyHex == "" {
		t.Error("PublicKeyHex empty")
	}
	if key.PubKeyHashHex == "" {
		t.Error("PubKeyHashHex empty")
	}
	if key.CreatedAt.IsZero() {
		t.Error("CreatedAt not set")
	}
}

func TestSaveAndLoadKey_Roundtrip(t *testing.T) {
	t.Parallel()
	key, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	path := t.TempDir() + "/key.json"
	if err := SaveKey(path, key, priv, "passw0rd"); err != nil {
		t.Fatalf("SaveKey: %v", err)
	}
	loaded, loadedPriv, err := LoadKey(path, "passw0rd")
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if !loaded.PublicKey.Equal(key.PublicKey) {
		t.Error("pubkey mismatch")
	}
	if string(loadedPriv) != string(priv) {
		t.Error("private key mismatch")
	}
}

func TestLoadKey_WrongPassphrase(t *testing.T) {
	t.Parallel()
	key, priv, _ := GenerateKey()
	path := t.TempDir() + "/k.json"
	_ = SaveKey(path, key, priv, "right")
	if _, _, err := LoadKey(path, "wrong"); err == nil {
		t.Error("expected decrypt failure with wrong passphrase")
	}
}

func TestSaveKey_Validation(t *testing.T) {
	t.Parallel()
	key, priv, _ := GenerateKey()
	if err := SaveKey("", key, priv, "pw"); err == nil {
		t.Error("expected path error")
	}
	if err := SaveKey("/tmp/x", nil, priv, "pw"); err == nil {
		t.Error("expected nil key error")
	}
	if err := SaveKey("/tmp/x", key, ed25519.PrivateKey{1}, "pw"); err == nil {
		t.Error("expected priv size error")
	}
	if err := SaveKey("/tmp/x", key, priv, ""); err == nil {
		t.Error("expected empty passphrase error")
	}
}

func TestKeyInfo_NonEmpty(t *testing.T) {
	t.Parallel()
	key, _, _ := GenerateKey()
	if info := KeyInfo(key); info == "" {
		t.Error("KeyInfo returned empty")
	}
}
