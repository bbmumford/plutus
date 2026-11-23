/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package receipt

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

const (
	// NonceSize is the byte length of a buyer nonce.
	// 32 bytes provides 256 bits of entropy, sufficient for replay protection.
	NonceSize = 32
)

// GenerateNonce produces a cryptographically random nonce for use as a
// BuyerNonce in a ServiceReceipt. The nonce ensures that each receipt request
// is unique and prevents replay of old receipts against new escrows.
func GenerateNonce() ([]byte, error) {
	nonce := make([]byte, NonceSize)
	n, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("receipt: failed to generate nonce: %w", err)
	}
	if n != NonceSize {
		return nil, fmt.Errorf("receipt: short read generating nonce: got %d bytes, want %d", n, NonceSize)
	}
	return nonce, nil
}

// NonceToHex encodes a nonce to a hex string for transport or display.
func NonceToHex(nonce []byte) string {
	return hex.EncodeToString(nonce)
}

// NonceFromHex decodes a hex-encoded nonce. Returns an error if the decoded
// length does not match NonceSize.
func NonceFromHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("receipt: invalid nonce hex: %w", err)
	}
	if len(b) != NonceSize {
		return nil, fmt.Errorf("receipt: nonce must be %d bytes, got %d", NonceSize, len(b))
	}
	return b, nil
}
