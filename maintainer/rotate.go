/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package maintainer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// RotationCert is a signed certificate that authorises a key rotation.
// The OLD key signs the certificate, attesting that the NEW key is its
// legitimate successor. During the grace period, both keys are accepted
// for adapter signature verification.
type RotationCert struct {
	// OldPubKey is the current (outgoing) maintainer public key.
	OldPubKey ed25519.PublicKey `json:"oldPubKey"`
	// OldPubKeyHash is SHA256(OldPubKey) — must match PRC maintainerPubKeyHash.
	OldPubKeyHash []byte `json:"oldPubKeyHash"`
	// NewPubKey is the new (incoming) maintainer public key.
	NewPubKey ed25519.PublicKey `json:"newPubKey"`
	// NewPubKeyHash is SHA256(NewPubKey).
	NewPubKeyHash []byte `json:"newPubKeyHash"`
	// GracePeriod is how long both keys should be accepted (e.g., 7 days).
	GracePeriod time.Duration `json:"gracePeriod"`
	// EffectiveAt is when the rotation becomes active.
	EffectiveAt time.Time `json:"effectiveAt"`
	// ExpiresAt is when the old key is no longer accepted (EffectiveAt + GracePeriod).
	ExpiresAt time.Time `json:"expiresAt"`
	// Reason is an optional human-readable reason for the rotation.
	Reason string `json:"reason,omitempty"`
	// Signature is the old key's Ed25519 signature over the rotation payload.
	Signature []byte `json:"signature"`
}

// RotateConfig configures a key rotation.
type RotateConfig struct {
	// OldKey is the current maintainer private key.
	OldKey ed25519.PrivateKey
	// NewKey is the new maintainer private key (nil = generate fresh).
	NewKey ed25519.PrivateKey
	// GracePeriod is how long both keys are valid (default: 7 days).
	GracePeriod time.Duration
	// Reason is an optional rotation reason.
	Reason string
}

// RotateResult contains the outcome of a key rotation.
type RotateResult struct {
	Cert       *RotationCert      `json:"cert"`
	NewKey     *MaintainerKey     `json:"newKey"`
	NewPrivKey ed25519.PrivateKey `json:"-"`
}

// Rotate creates a rotation certificate signed by the old key, authorising
// a transition to the new key. If no new key is provided, one is generated.
//
// IMPORTANT — post-rotation PRC redeployment:
// The canonical PRC CREATE2 salt is computed as
// keccak256("plutus-v1-prc" || MaintainerPubKeyHash) (see
// canonical.PlutusPRCSalt). Rotating the maintainer key changes
// MaintainerPubKeyHash, which changes the salt, which changes the
// deterministic PRC address on every chain. After a successful rotation
// the maintainer MUST:
//  1. Update _PACKAGES/plutus/canonical/keys/platform-key.pub (embedded
//     MaintainerPubKeyHash follows from this).
//  2. Re-run the deploy script against each supported chain with the new
//     MAINTAINER_PUBKEY_HASH env var to obtain the new predicted address.
//  3. Paste the new address into canonical.CanonicalPRCAddress and tag a
//     new release.
//  4. Re-run the PRC certification ceremony for each new deployment.
//
// Old PRCs are not destroyed; they simply become historical artifacts
// (they hold no funds — escrows live in per-order contracts, not in the
// PRC itself). New buyers will deploy escrows that deposit into the NEW
// PRC's fee pipeline.
func Rotate(config RotateConfig) (*RotateResult, error) {
	if len(config.OldKey) != ed25519.PrivateKeySize {
		return nil, errors.New("maintainer/rotate: invalid old key size")
	}

	if config.GracePeriod <= 0 {
		config.GracePeriod = 7 * 24 * time.Hour // 7 days default
	}

	if config.GracePeriod < 24*time.Hour {
		return nil, errors.New("maintainer/rotate: grace period must be at least 24 hours")
	}

	// Generate new key if not provided.
	var newPrivKey ed25519.PrivateKey
	if config.NewKey != nil {
		if len(config.NewKey) != ed25519.PrivateKeySize {
			return nil, errors.New("maintainer/rotate: invalid new key size")
		}
		newPrivKey = config.NewKey
	} else {
		var err error
		_, newPrivKey, err = GenerateKey()
		if err != nil {
			return nil, fmt.Errorf("maintainer/rotate: generate new key: %w", err)
		}
	}

	oldPub := config.OldKey.Public().(ed25519.PublicKey)
	newPub := newPrivKey.Public().(ed25519.PublicKey)

	oldHash := sha256.Sum256(oldPub)
	newHash := sha256.Sum256(newPub)

	now := time.Now().UTC()

	cert := &RotationCert{
		OldPubKey:     oldPub,
		OldPubKeyHash: oldHash[:],
		NewPubKey:     newPub,
		NewPubKeyHash: newHash[:],
		GracePeriod:   config.GracePeriod,
		EffectiveAt:   now,
		ExpiresAt:     now.Add(config.GracePeriod),
		Reason:        config.Reason,
	}

	// Sign the rotation payload with the old key.
	payload := rotationPayload(cert)
	cert.Signature = ed25519.Sign(config.OldKey, payload)

	// Build the new key metadata.
	newKey := &MaintainerKey{
		PublicKey:     newPub,
		PublicKeyHex:  hex.EncodeToString(newPub),
		PubKeyHash:    newHash,
		PubKeyHashHex: hex.EncodeToString(newHash[:]),
		CreatedAt:     now,
	}

	return &RotateResult{
		Cert:       cert,
		NewKey:     newKey,
		NewPrivKey: newPrivKey,
	}, nil
}

// VerifyRotationCert verifies that a rotation certificate is valid:
//  1. The old key's signature over the certificate payload is valid.
//  2. The old public key hash matches the expected PRC hash.
//  3. The certificate has not expired.
func VerifyRotationCert(cert *RotationCert, expectedOldPubKeyHash []byte) error {
	if cert == nil {
		return errors.New("maintainer/rotate: certificate is nil")
	}

	if len(cert.OldPubKey) != ed25519.PublicKeySize {
		return errors.New("maintainer/rotate: invalid old public key size")
	}

	if len(cert.NewPubKey) != ed25519.PublicKeySize {
		return errors.New("maintainer/rotate: invalid new public key size")
	}

	// Verify old key hash matches PRC.
	oldHash := sha256.Sum256(cert.OldPubKey)
	if len(expectedOldPubKeyHash) > 0 {
		hashMatch := true
		for i := range oldHash {
			if i >= len(expectedOldPubKeyHash) || oldHash[i] != expectedOldPubKeyHash[i] {
				hashMatch = false
				break
			}
		}
		if !hashMatch {
			return errors.New("maintainer/rotate: old key hash does not match PRC")
		}
	}

	// Verify signature.
	payload := rotationPayload(cert)
	if !ed25519.Verify(cert.OldPubKey, payload, cert.Signature) {
		return errors.New("maintainer/rotate: certificate signature is invalid")
	}

	// Check expiration.
	if time.Now().After(cert.ExpiresAt) {
		return fmt.Errorf("maintainer/rotate: certificate expired at %s", cert.ExpiresAt.Format(time.RFC3339))
	}

	return nil
}

// IsInGracePeriod returns true if the rotation is active and both keys should
// be accepted for verification. The grace period is inclusive of EffectiveAt
// (i.e. "started at T" means T itself counts) — using !now.Before(effective)
// avoids a same-nanosecond boundary bug where now.After(now) would be false
// immediately after Rotate() set EffectiveAt = time.Now().
func IsInGracePeriod(cert *RotationCert) bool {
	if cert == nil {
		return false
	}
	now := time.Now()
	return !now.Before(cert.EffectiveAt) && now.Before(cert.ExpiresAt)
}

// AcceptedPubKeyHashes returns the set of public key hashes that should be
// accepted for adapter verification, accounting for any active rotation.
// During the grace period, both old and new hashes are returned.
func AcceptedPubKeyHashes(cert *RotationCert) [][]byte {
	if cert == nil || !IsInGracePeriod(cert) {
		return nil
	}
	return [][]byte{cert.OldPubKeyHash, cert.NewPubKeyHash}
}

// rotationPayload computes the canonical bytes that are signed.
func rotationPayload(cert *RotationCert) []byte {
	payload := struct {
		OldPubKey   string `json:"oldPubKey"`
		NewPubKey   string `json:"newPubKey"`
		GracePeriod string `json:"gracePeriod"`
		EffectiveAt string `json:"effectiveAt"`
		Reason      string `json:"reason"`
	}{
		OldPubKey:   hex.EncodeToString(cert.OldPubKey),
		NewPubKey:   hex.EncodeToString(cert.NewPubKey),
		GracePeriod: cert.GracePeriod.String(),
		EffectiveAt: cert.EffectiveAt.Format(time.RFC3339Nano),
		Reason:      cert.Reason,
	}
	b, _ := json.Marshal(payload)
	return b
}

// SaveRotationCert writes a rotation certificate to a JSON file.
func SaveRotationCert(path string, cert *RotationCert) error {
	if path == "" {
		return errors.New("maintainer/rotate: file path is empty")
	}
	if cert == nil {
		return errors.New("maintainer/rotate: certificate is nil")
	}

	// Convert to a serializable format.
	data := struct {
		OldPubKey     string `json:"oldPubKey"`
		OldPubKeyHash string `json:"oldPubKeyHash"`
		NewPubKey     string `json:"newPubKey"`
		NewPubKeyHash string `json:"newPubKeyHash"`
		GracePeriod   string `json:"gracePeriod"`
		EffectiveAt   string `json:"effectiveAt"`
		ExpiresAt     string `json:"expiresAt"`
		Reason        string `json:"reason,omitempty"`
		Signature     string `json:"signature"`
	}{
		OldPubKey:     hex.EncodeToString(cert.OldPubKey),
		OldPubKeyHash: hex.EncodeToString(cert.OldPubKeyHash),
		NewPubKey:     hex.EncodeToString(cert.NewPubKey),
		NewPubKeyHash: hex.EncodeToString(cert.NewPubKeyHash),
		GracePeriod:   cert.GracePeriod.String(),
		EffectiveAt:   cert.EffectiveAt.Format(time.RFC3339),
		ExpiresAt:     cert.ExpiresAt.Format(time.RFC3339),
		Reason:        cert.Reason,
		Signature:     hex.EncodeToString(cert.Signature),
	}

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("maintainer/rotate: marshal cert: %w", err)
	}

	return os.WriteFile(path, b, 0644)
}

// LoadRotationCert reads a rotation certificate from a JSON file.
func LoadRotationCert(path string) (*RotationCert, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("maintainer/rotate: read cert file: %w", err)
	}

	var raw struct {
		OldPubKey     string `json:"oldPubKey"`
		OldPubKeyHash string `json:"oldPubKeyHash"`
		NewPubKey     string `json:"newPubKey"`
		NewPubKeyHash string `json:"newPubKeyHash"`
		GracePeriod   string `json:"gracePeriod"`
		EffectiveAt   string `json:"effectiveAt"`
		ExpiresAt     string `json:"expiresAt"`
		Reason        string `json:"reason"`
		Signature     string `json:"signature"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("maintainer/rotate: parse cert file: %w", err)
	}

	oldPub, _ := hex.DecodeString(raw.OldPubKey)
	oldHash, _ := hex.DecodeString(raw.OldPubKeyHash)
	newPub, _ := hex.DecodeString(raw.NewPubKey)
	newHash, _ := hex.DecodeString(raw.NewPubKeyHash)
	sig, _ := hex.DecodeString(raw.Signature)
	effectiveAt, _ := time.Parse(time.RFC3339, raw.EffectiveAt)
	expiresAt, _ := time.Parse(time.RFC3339, raw.ExpiresAt)

	gracePeriod := expiresAt.Sub(effectiveAt)

	return &RotationCert{
		OldPubKey:     oldPub,
		OldPubKeyHash: oldHash,
		NewPubKey:     newPub,
		NewPubKeyHash: newHash,
		GracePeriod:   gracePeriod,
		EffectiveAt:   effectiveAt,
		ExpiresAt:     expiresAt,
		Reason:        raw.Reason,
		Signature:     sig,
	}, nil
}

// PlatformKeyRotationResult contains the outcome of a platform key rotation.
type PlatformKeyRotationResult struct {
	// NewCert is the new platform key certificate signed by the Offline Root.
	NewCert *PlatformKeyCertificate
	// NewPrivateKey is the new platform private key.
	NewPrivateKey ed25519.PrivateKey
	// OldCert is the previous platform key certificate (for reference).
	OldCert *PlatformKeyCertificate
}

// RotatePlatformKey creates a new Platform Key and signs its certificate with
// the Offline Root Key. This is used when the Platform Key needs to be rotated,
// either as a scheduled rotation or because the PK was compromised.
//
// The Offline Root must be available (air-gapped ceremony). The old platform
// cert is provided for reference and audit trail purposes only; it is not
// required for the cryptographic operation since the OR is the authority.
//
// If the Offline Root is compromised, this is the catastrophic case --
// new PRCs must be deployed on all chains with a new OR.
func RotatePlatformKey(offlineRoot *OfflineRootKey, oldPlatformCert *PlatformKeyCertificate) (*PlatformKeyRotationResult, error) {
	if offlineRoot == nil {
		return nil, errors.New("maintainer/rotate: offline root key is nil")
	}
	if len(offlineRoot.PrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("maintainer/rotate: offline root private key is invalid")
	}
	if oldPlatformCert == nil {
		return nil, errors.New("maintainer/rotate: old platform certificate is required for audit trail")
	}

	// Verify the old platform cert is authentic (signed by this OR).
	if !VerifyPlatformCert(oldPlatformCert) {
		return nil, errors.New("maintainer/rotate: old platform certificate is not valid")
	}

	// Verify the OR in the old cert matches our OR.
	if !offlineRoot.PublicKey.Equal(ed25519.PublicKey(oldPlatformCert.OfflineRootPubKey)) {
		return nil, errors.New("maintainer/rotate: old platform cert was not signed by this offline root")
	}

	// Generate a new Platform Key.
	newPlatformPub, newPlatformPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("maintainer/rotate: generate new platform key: %w", err)
	}

	now := time.Now().UTC()

	newCert := &PlatformKeyCertificate{
		PlatformPubKey:    newPlatformPub,
		OfflineRootPubKey: offlineRoot.PublicKey,
		IssuedAt:          now,
	}

	// Sign the new certificate with the Offline Root key.
	payload := platformCertPayload(newCert)
	newCert.Signature = ed25519.Sign(offlineRoot.PrivateKey, payload)

	return &PlatformKeyRotationResult{
		NewCert:       newCert,
		NewPrivateKey: newPlatformPriv,
		OldCert:       oldPlatformCert,
	}, nil
}
