/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package receipt

import (
	"crypto/sha256"
	"fmt"
)

// ReceiptBundle aggregates multiple ServiceReceipts into a single Merkle root
// hash for efficient on-chain anchoring. Instead of including N receipt hashes
// in escrow metadata, a single Merkle root proves membership of all receipts.
type ReceiptBundle struct {
	Receipts   []*ServiceReceipt
	Hashes     [][]byte // individual receipt hashes (leaves)
	MerkleRoot []byte   // root of the Merkle tree over Hashes
}

// NewReceiptBundle creates a bundle from the given receipts, computing
// individual hashes and the Merkle root. All receipts must be signed.
func NewReceiptBundle(receipts []*ServiceReceipt) (*ReceiptBundle, error) {
	if len(receipts) == 0 {
		return nil, fmt.Errorf("receipt: bundle requires at least one receipt")
	}

	hashes := make([][]byte, len(receipts))
	for i, r := range receipts {
		h, err := ReceiptHash(r)
		if err != nil {
			return nil, fmt.Errorf("receipt: hash failed for receipt %d: %w", i, err)
		}
		hashes[i] = h
	}

	root := computeMerkleRoot(hashes)

	return &ReceiptBundle{
		Receipts:   receipts,
		Hashes:     hashes,
		MerkleRoot: root,
	}, nil
}

// VerifyBundle verifies every receipt in the bundle and recomputes the Merkle
// root to ensure it matches the stored root.
func (b *ReceiptBundle) VerifyBundle() error {
	if len(b.Receipts) == 0 {
		return fmt.Errorf("receipt: bundle is empty")
	}
	if len(b.Receipts) != len(b.Hashes) {
		return fmt.Errorf("receipt: receipt count %d does not match hash count %d",
			len(b.Receipts), len(b.Hashes))
	}

	for i, r := range b.Receipts {
		ok, err := VerifyReceipt(r)
		if err != nil {
			return fmt.Errorf("receipt: verification failed for receipt %d: %w", i, err)
		}
		if !ok {
			return fmt.Errorf("receipt: invalid signature on receipt %d", i)
		}

		h, err := ReceiptHash(r)
		if err != nil {
			return fmt.Errorf("receipt: hash failed for receipt %d: %w", i, err)
		}
		if !bytesEqual(h, b.Hashes[i]) {
			return fmt.Errorf("receipt: hash mismatch on receipt %d", i)
		}
	}

	root := computeMerkleRoot(b.Hashes)
	if !bytesEqual(root, b.MerkleRoot) {
		return fmt.Errorf("receipt: Merkle root mismatch")
	}

	return nil
}

// MerkleProof generates an inclusion proof for the receipt at the given index.
// The proof consists of sibling hashes needed to recompute the root from the leaf.
func (b *ReceiptBundle) MerkleProof(index int) ([][]byte, error) {
	if index < 0 || index >= len(b.Hashes) {
		return nil, fmt.Errorf("receipt: index %d out of range [0, %d)", index, len(b.Hashes))
	}
	return buildMerkleProof(b.Hashes, index), nil
}

// VerifyMerkleProof checks that a leaf hash at the given index can be combined
// with the proof siblings to reproduce the expected root.
func VerifyMerkleProof(leaf []byte, index int, proof [][]byte, root []byte) bool {
	current := leaf
	idx := index

	for _, sibling := range proof {
		if idx%2 == 0 {
			current = hashPair(current, sibling)
		} else {
			current = hashPair(sibling, current)
		}
		idx /= 2
	}

	return bytesEqual(current, root)
}

// computeMerkleRoot builds a Merkle tree from the given leaf hashes and
// returns the root hash. For odd-length levels, the last element is
// duplicated (standard Merkle tree padding).
func computeMerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	if len(leaves) == 1 {
		return leaves[0]
	}

	// Copy leaves so we don't mutate the input.
	level := make([][]byte, len(leaves))
	copy(level, leaves)

	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, hashPair(level[i], level[i+1]))
			} else {
				// Odd element: duplicate it.
				next = append(next, hashPair(level[i], level[i]))
			}
		}
		level = next
	}

	return level[0]
}

// buildMerkleProof collects the sibling hashes needed for an inclusion proof.
func buildMerkleProof(leaves [][]byte, index int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}

	level := make([][]byte, len(leaves))
	copy(level, leaves)

	var proof [][]byte
	idx := index

	for len(level) > 1 {
		// Determine sibling index.
		var siblingIdx int
		if idx%2 == 0 {
			siblingIdx = idx + 1
			if siblingIdx >= len(level) {
				siblingIdx = idx // duplicate case
			}
		} else {
			siblingIdx = idx - 1
		}
		proof = append(proof, level[siblingIdx])

		// Build next level.
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, hashPair(level[i], level[i+1]))
			} else {
				next = append(next, hashPair(level[i], level[i]))
			}
		}
		level = next
		idx /= 2
	}

	return proof
}

// hashPair computes SHA-256(left || right).
func hashPair(left, right []byte) []byte {
	h := sha256.New()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// bytesEqual is a constant-time-ish comparison for hash equality.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
