/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package receipt

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"
)

// ServiceReceipt is a signed attestation from a service provider that work was
// delivered to a buyer. Receipts are hashed and included in escrow metadata so
// on-chain release can be tied to off-chain service delivery.
type ServiceReceipt struct {
	ProviderPubKey ed25519.PublicKey // service provider's public key
	BuyerNonce     []byte            // nonce provided by buyer to prove request
	ServiceType    string            // type of service rendered (e.g. "vdi-session", "print-job")
	ContentHash    []byte            // SHA-256 of service output/proof
	Timestamp      time.Time         // when the service was rendered
	Signature      []byte            // Ed25519 signature over all fields except Signature
}

// receiptDigest computes the canonical SHA-256 digest of all receipt fields
// except Signature. This is the message that gets signed and verified.
func receiptDigest(r *ServiceReceipt) []byte {
	h := sha256.New()

	// Provider public key
	h.Write(r.ProviderPubKey)

	// Buyer nonce
	h.Write(r.BuyerNonce)

	// Service type (length-prefixed to prevent ambiguity)
	var stLen [4]byte
	binary.BigEndian.PutUint32(stLen[:], uint32(len(r.ServiceType)))
	h.Write(stLen[:])
	h.Write([]byte(r.ServiceType))

	// Content hash
	h.Write(r.ContentHash)

	// Timestamp as Unix nanoseconds
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(r.Timestamp.UnixNano()))
	h.Write(tsBuf[:])

	return h.Sum(nil)
}

// SignReceipt signs the receipt with the provider's Ed25519 private key.
// The signature covers the SHA-256 digest of all content fields.
// The Signature field on the receipt is populated in-place.
func SignReceipt(r *ServiceReceipt, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("receipt: invalid private key size %d", len(privateKey))
	}
	if len(r.ProviderPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("receipt: invalid provider public key size %d", len(r.ProviderPubKey))
	}
	if len(r.BuyerNonce) == 0 {
		return fmt.Errorf("receipt: buyer nonce is required")
	}
	if r.ServiceType == "" {
		return fmt.Errorf("receipt: service type is required")
	}
	if len(r.ContentHash) == 0 {
		return fmt.Errorf("receipt: content hash is required")
	}
	if r.Timestamp.IsZero() {
		return fmt.Errorf("receipt: timestamp is required")
	}

	digest := receiptDigest(r)
	r.Signature = ed25519.Sign(privateKey, digest)
	return nil
}

// VerifyReceipt checks that the receipt's signature is valid for its content
// fields and was produced by the declared ProviderPubKey.
func VerifyReceipt(r *ServiceReceipt) (bool, error) {
	if len(r.ProviderPubKey) != ed25519.PublicKeySize {
		return false, fmt.Errorf("receipt: invalid provider public key size %d", len(r.ProviderPubKey))
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return false, fmt.Errorf("receipt: invalid signature size %d", len(r.Signature))
	}
	if len(r.BuyerNonce) == 0 {
		return false, fmt.Errorf("receipt: buyer nonce is required for verification")
	}
	if r.ServiceType == "" {
		return false, fmt.Errorf("receipt: service type is required for verification")
	}
	if len(r.ContentHash) == 0 {
		return false, fmt.Errorf("receipt: content hash is required for verification")
	}

	digest := receiptDigest(r)
	return ed25519.Verify(r.ProviderPubKey, digest, r.Signature), nil
}

// ReceiptHash computes the SHA-256 hash of a signed receipt. This hash is
// included in escrow metadata to bind on-chain escrow to off-chain service
// delivery without revealing the receipt contents on-chain.
func ReceiptHash(r *ServiceReceipt) ([]byte, error) {
	if len(r.Signature) == 0 {
		return nil, fmt.Errorf("receipt: cannot hash unsigned receipt")
	}

	h := sha256.New()
	// Hash the content digest + signature together to produce the receipt hash.
	// This ensures the hash commits to both the content and the provider's
	// attestation that the content is valid.
	h.Write(receiptDigest(r))
	h.Write(r.Signature)
	sum := h.Sum(nil)
	return sum, nil
}
