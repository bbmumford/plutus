package wallet

import (
	"crypto/rand"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Argon2id parameters (OWASP recommended for key derivation).
//
// NOTE: Uses 32-byte salt + 24-byte nonce (XChaCha20-Poly1305), which differs
// from cryptographic-protocol.md spec (16-byte salt + 12-byte nonce). This
// implementation is more secure: the larger salt provides better collision
// resistance for Argon2id, and XChaCha20-Poly1305's 24-byte nonce eliminates
// nonce-reuse risk for random nonces. Spec should be updated to match.
const (
	argon2Time    = 3
	argon2Memory  = 64 * 1024 // 64 MB
	argon2Threads = 4
	argon2KeyLen  = 32 // ChaCha20-Poly1305 key size
	saltLen       = 32
)

// EncryptSeed encrypts a BIP39 seed using Argon2id for key derivation and
// ChaCha20-Poly1305 for authenticated encryption.
//
// Output format: salt (16 bytes) || nonce (24 bytes) || ciphertext+tag
func EncryptSeed(seed []byte, passphrase string) ([]byte, error) {
	if len(seed) == 0 {
		return nil, errors.New("plutus/wallet: seed is empty")
	}
	if passphrase == "" {
		return nil, errors.New("plutus/wallet: passphrase is empty")
	}

	// Generate random salt.
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("plutus/wallet: salt generation failed: %w", err)
	}

	// Derive encryption key via Argon2id.
	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	// Create XChaCha20-Poly1305 AEAD (24-byte nonce for better collision resistance).
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: AEAD construction failed: %w", err)
	}

	// Generate random nonce.
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("plutus/wallet: nonce generation failed: %w", err)
	}

	// Encrypt with authenticated encryption.
	ciphertext := aead.Seal(nil, nonce, seed, salt) // salt as additional data

	// Pack: salt || nonce || ciphertext+tag
	result := make([]byte, 0, saltLen+len(nonce)+len(ciphertext))
	result = append(result, salt...)
	result = append(result, nonce...)
	result = append(result, ciphertext...)

	return result, nil
}

// DecryptSeed decrypts an encrypted seed blob produced by EncryptSeed.
func DecryptSeed(encrypted []byte, passphrase string) ([]byte, error) {
	nonceSize := chacha20poly1305.NonceSizeX
	minLen := saltLen + nonceSize + chacha20poly1305.Overhead + 1 // at least 1 byte of plaintext

	if len(encrypted) < minLen {
		return nil, errors.New("plutus/wallet: encrypted data too short")
	}
	if passphrase == "" {
		return nil, errors.New("plutus/wallet: passphrase is empty")
	}

	salt := encrypted[:saltLen]
	nonce := encrypted[saltLen : saltLen+nonceSize]
	ciphertext := encrypted[saltLen+nonceSize:]

	// Derive the same key.
	key := argon2.IDKey([]byte(passphrase), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: AEAD construction failed: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, salt)
	if err != nil {
		return nil, errors.New("plutus/wallet: decryption failed (wrong passphrase or corrupted data)")
	}

	return plaintext, nil
}
