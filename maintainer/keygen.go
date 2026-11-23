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

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// MaintainerKey holds an Ed25519 key pair with associated metadata.
type MaintainerKey struct {
	// PublicKey is the Ed25519 public key.
	PublicKey ed25519.PublicKey `json:"-"`
	// PublicKeyHex is the hex-encoded public key.
	PublicKeyHex string `json:"publicKey"`
	// PubKeyHash is the SHA256 hash of the public key (stored in PRC).
	PubKeyHash [32]byte `json:"-"`
	// PubKeyHashHex is the hex-encoded public key hash.
	PubKeyHashHex string `json:"pubKeyHash"`
	// CreatedAt is when the key was generated.
	CreatedAt time.Time `json:"createdAt"`
}

// encryptedKeyFile is the on-disk format for an encrypted maintainer key.
// Version 2 uses Argon2id for key derivation and stores the salt.
// On-disk format for ciphertext: the raw bytes are [salt:32][nonce:24][ciphertext].
type encryptedKeyFile struct {
	Version      int    `json:"version"`
	PublicKey    string `json:"publicKey"`
	PubKeyHash   string `json:"pubKeyHash"`
	Salt         string `json:"salt,omitempty"` // hex-encoded Argon2id salt (v2+)
	Nonce        string `json:"nonce"`          // hex-encoded nonce
	Ciphertext   string `json:"ciphertext"`     // hex-encoded encrypted private key
	CreatedAt    string `json:"createdAt"`
}

// GenerateKey generates a new Ed25519 key pair for use as a maintainer identity.
// The public key hash is computed for embedding in the PRC.
func GenerateKey() (*MaintainerKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("maintainer/keygen: generate key: %w", err)
	}

	pubKeyHash := sha256.Sum256(pub)

	key := &MaintainerKey{
		PublicKey:     pub,
		PublicKeyHex:  hex.EncodeToString(pub),
		PubKeyHash:    pubKeyHash,
		PubKeyHashHex: hex.EncodeToString(pubKeyHash[:]),
		CreatedAt:     time.Now().UTC(),
	}

	return key, priv, nil
}

// SaveKey encrypts the private key with a passphrase and writes it to a file.
// Uses XChaCha20-Poly1305 with an Argon2id-derived key from the passphrase,
// matching the wallet/keystore.go KDF parameters.
func SaveKey(path string, key *MaintainerKey, privateKey ed25519.PrivateKey, passphrase string) error {
	if path == "" {
		return errors.New("maintainer/keygen: file path is empty")
	}
	if key == nil {
		return errors.New("maintainer/keygen: key is nil")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("maintainer/keygen: invalid private key size %d", len(privateKey))
	}
	if passphrase == "" {
		return errors.New("maintainer/keygen: passphrase is empty")
	}

	// Generate random salt for Argon2id.
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("maintainer/keygen: generate salt: %w", err)
	}

	// Derive encryption key from passphrase using Argon2id.
	// Parameters: time=3, memory=64MB, threads=4, keyLen=32.
	encKey := argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)

	// Encrypt private key with XChaCha20-Poly1305.
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return fmt.Errorf("maintainer/keygen: create cipher: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("maintainer/keygen: generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, []byte(privateKey), nil)

	// Serialize to JSON.
	file := encryptedKeyFile{
		Version:    2,
		PublicKey:  key.PublicKeyHex,
		PubKeyHash: key.PubKeyHashHex,
		Salt:       hex.EncodeToString(salt),
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ciphertext),
		CreatedAt:  key.CreatedAt.Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("maintainer/keygen: marshal key file: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("maintainer/keygen: write key file: %w", err)
	}

	return nil
}

// LoadKey reads and decrypts a maintainer key from a file.
// Supports both v1 (SHA256 KDF, legacy) and v2 (Argon2id KDF) key files.
func LoadKey(path string, passphrase string) (*MaintainerKey, ed25519.PrivateKey, error) {
	if path == "" {
		return nil, nil, errors.New("maintainer/keygen: file path is empty")
	}
	if passphrase == "" {
		return nil, nil, errors.New("maintainer/keygen: passphrase is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("maintainer/keygen: read key file: %w", err)
	}

	var file encryptedKeyFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, nil, fmt.Errorf("maintainer/keygen: parse key file: %w", err)
	}

	if file.Version != 1 && file.Version != 2 {
		return nil, nil, fmt.Errorf("maintainer/keygen: unsupported key file version %d", file.Version)
	}

	// Decode hex fields.
	nonce, err := hex.DecodeString(file.Nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("maintainer/keygen: decode nonce: %w", err)
	}

	ciphertext, err := hex.DecodeString(file.Ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("maintainer/keygen: decode ciphertext: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(file.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("maintainer/keygen: decode public key: %w", err)
	}

	// Derive decryption key based on version.
	var decKey []byte
	switch file.Version {
	case 1:
		// Legacy: SHA256 KDF.
		h := sha256.Sum256([]byte(passphrase))
		decKey = h[:]
	case 2:
		// Argon2id KDF.
		salt, err := hex.DecodeString(file.Salt)
		if err != nil {
			return nil, nil, fmt.Errorf("maintainer/keygen: decode salt: %w", err)
		}
		if len(salt) != 32 {
			return nil, nil, fmt.Errorf("maintainer/keygen: invalid salt length %d", len(salt))
		}
		decKey = argon2.IDKey([]byte(passphrase), salt, 3, 64*1024, 4, 32)
	}

	// Decrypt.
	aead, err := chacha20poly1305.NewX(decKey)
	if err != nil {
		return nil, nil, fmt.Errorf("maintainer/keygen: create cipher: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("maintainer/keygen: decrypt failed (wrong passphrase?): %w", err)
	}

	if len(plaintext) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("maintainer/keygen: decrypted key has invalid size %d", len(plaintext))
	}

	privateKey := ed25519.PrivateKey(plaintext)
	pubKey := ed25519.PublicKey(pubKeyBytes)
	pubKeyHash := sha256.Sum256(pubKey)

	createdAt, _ := time.Parse(time.RFC3339, file.CreatedAt)

	key := &MaintainerKey{
		PublicKey:     pubKey,
		PublicKeyHex:  file.PublicKey,
		PubKeyHash:    pubKeyHash,
		PubKeyHashHex: file.PubKeyHash,
		CreatedAt:     createdAt,
	}

	return key, privateKey, nil
}

// KeyInfo returns a human-readable summary of a maintainer key.
func KeyInfo(key *MaintainerKey) string {
	return fmt.Sprintf(
		"Maintainer Key:\n  Public Key: %s\n  PubKey Hash: %s\n  Created: %s",
		key.PublicKeyHex,
		key.PubKeyHashHex,
		key.CreatedAt.Format(time.RFC3339),
	)
}
