/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package receipt

import (
	"crypto/ed25519"
	"fmt"
	"time"
)

// ReceiptManager creates and signs service receipts using the wallet's
// identity key. It provides a convenient API for service providers to
// generate receipts that can be bundled and anchored in escrow metadata.
type ReceiptManager struct {
	identityKey ed25519.PrivateKey
}

// NewReceiptManager creates a ReceiptManager bound to the given identity key.
func NewReceiptManager(identityKey ed25519.PrivateKey) *ReceiptManager {
	return &ReceiptManager{identityKey: identityKey}
}

// Create builds and signs a new ServiceReceipt. The caller must provide a
// buyer nonce (from GenerateNonce), the service type, and the content hash.
// The receipt is signed with the manager's identity key.
func (m *ReceiptManager) Create(buyerNonce []byte, serviceType string, contentHash []byte) (*ServiceReceipt, error) {
	if len(buyerNonce) == 0 {
		return nil, fmt.Errorf("receipt: buyer nonce is required")
	}
	if serviceType == "" {
		return nil, fmt.Errorf("receipt: service type is required")
	}
	if len(contentHash) == 0 {
		return nil, fmt.Errorf("receipt: content hash is required")
	}

	r := &ServiceReceipt{
		ProviderPubKey: m.identityKey.Public().(ed25519.PublicKey),
		BuyerNonce:     buyerNonce,
		ServiceType:    serviceType,
		ContentHash:    contentHash,
		Timestamp:      time.Now(),
	}

	if err := SignReceipt(r, m.identityKey); err != nil {
		return nil, fmt.Errorf("receipt: sign failed: %w", err)
	}

	return r, nil
}

// PublicKey returns the Ed25519 public key used for signing receipts.
func (m *ReceiptManager) PublicKey() ed25519.PublicKey {
	return m.identityKey.Public().(ed25519.PublicKey)
}
