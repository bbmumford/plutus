/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/bbmumford/plutus/maintainer"
)

// RunVerify is the exported entry point used by tests.
func RunVerify(args []string) error { return runVerify(args) }

// runVerify reads a key or certificate file and validates its format +
// signatures. The file type is auto-detected by looking at which JSON
// keys are present in the decoded object.
func runVerify(args []string) error {
	fs := newFlagSet("verify", "Verify a ceremony key or certificate file")
	dir := fs.String("dir", defaultDirForHelp(), "ceremony working directory (override with --dir)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		return fmt.Errorf("file path is required")
	}

	workDir, err := ensureDir(*dir)
	if err != nil {
		return err
	}

	path := resolvePath(workDir, fs.Arg(0))
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}

	// Detect type by probing keys.
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}

	switch {
	case probeHas(probe, "encryptedPrivateKey") && probeHas(probe, "publicKey") && !probeHas(probe, "pubKeyHash"):
		return verifyRootOrPlatformKey(path, data)
	case probeHas(probe, "ciphertext"):
		return verifyEncryptedKey(path, data)
	case probeHas(probe, "platformPubKey") && probeHas(probe, "offlineRootPubKey"):
		return verifyPlatformCert(path)
	case probeHas(probe, "prcAddress") && probeHas(probe, "chainID"):
		return verifyDeploymentCert(path)
	case probeHas(probe, "oldPubKey") && probeHas(probe, "newPubKey"):
		return verifyRotationCert(path)
	default:
		return fmt.Errorf("cannot determine file type from JSON structure")
	}
}

// probeHas returns true if the map contains the given JSON key.
func probeHas(m map[string]json.RawMessage, key string) bool {
	_, ok := m[key]
	return ok
}

// verifyRootOrPlatformKey validates the on-disk root/platform key wrapper
// (publicKey + encryptedPrivateKey).
func verifyRootOrPlatformKey(path string, data []byte) error {
	var file struct {
		Version             int    `json:"version"`
		PublicKey           string `json:"publicKey"`
		EncryptedPrivateKey string `json:"encryptedPrivateKey"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse key file: %w", err)
	}
	pub, err := hex.DecodeString(file.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key size %d (want %d)", len(pub), ed25519.PublicKeySize)
	}
	enc, err := hex.DecodeString(file.EncryptedPrivateKey)
	if err != nil {
		return fmt.Errorf("decode encrypted private key: %w", err)
	}
	successf("Key file %s format OK (version=%d, pubkey=%s..., ciphertext=%d bytes)",
		path, file.Version, file.PublicKey[:16], len(enc))
	return nil
}

// verifyEncryptedKey validates the maintainer keygen format (salt +
// nonce + ciphertext). We cannot decrypt without a passphrase, but we
// can check that the envelope is well-formed.
func verifyEncryptedKey(path string, data []byte) error {
	var file struct {
		Version    int    `json:"version"`
		PublicKey  string `json:"publicKey"`
		PubKeyHash string `json:"pubKeyHash"`
		Salt       string `json:"salt"`
		Nonce      string `json:"nonce"`
		Ciphertext string `json:"ciphertext"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse key file: %w", err)
	}
	pub, err := hex.DecodeString(file.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid public key (err=%v, len=%d)", err, len(pub))
	}
	if file.Ciphertext == "" {
		return fmt.Errorf("ciphertext is empty")
	}
	successf("Encrypted key file %s format OK (version=%d, pubkey=%s...)",
		path, file.Version, file.PublicKey[:16])
	return nil
}

// verifyPlatformCert loads and verifies a Platform Key certificate.
func verifyPlatformCert(path string) error {
	cert, err := maintainer.LoadPlatformCert(path)
	if err != nil {
		return err
	}
	if !maintainer.VerifyPlatformCert(cert) {
		return fmt.Errorf("platform certificate signature is INVALID")
	}
	successf("Platform cert %s signature valid (PK=%s..., OR=%s..., issued=%s)",
		path,
		hex.EncodeToString(cert.PlatformPubKey)[:16],
		hex.EncodeToString(cert.OfflineRootPubKey)[:16],
		cert.IssuedAt.Format("2006-01-02"))
	return nil
}

// verifyDeploymentCert loads a PRC deployment certificate. Full verification
// requires the matching platform cert, so we only validate the envelope here.
func verifyDeploymentCert(path string) error {
	cert, err := maintainer.LoadPRCDeploymentCert(path)
	if err != nil {
		return err
	}
	if len(cert.Signature) == 0 {
		return fmt.Errorf("deployment certificate has no signature")
	}
	successf("Deployment cert %s format OK (chain=%s, addr=%s, tx=%s, block=%d)",
		path, cert.ChainID, cert.PRCAddress, cert.DeployTxHash, cert.BlockNumber)
	fmt.Println("Note: pass the matching platform.cert to verify the signature cryptographically.")
	return nil
}

// verifyRotationCert loads and verifies a rotation certificate.
func verifyRotationCert(path string) error {
	cert, err := maintainer.LoadRotationCert(path)
	if err != nil {
		return err
	}
	if err := maintainer.VerifyRotationCert(cert, nil); err != nil {
		return err
	}
	successf("Rotation cert %s signature valid (effective=%s, expires=%s)",
		path, cert.EffectiveAt.Format("2006-01-02"), cert.ExpiresAt.Format("2006-01-02"))
	return nil
}
