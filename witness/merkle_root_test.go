/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"golang.org/x/crypto/sha3"
)

// referenceKeccak is a standalone keccak256 helper used by the reference
// tests in this file so we never cross-talk with the production helpers in
// fee_distributor.go. A drift between the two will surface as a byte-level
// diff in TestBuildMerkleRoot_RoundtripMatchesOZ.
func referenceKeccak(chunks ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, c := range chunks {
		h.Write(c)
	}
	return h.Sum(nil)
}

// referenceSortedPair hashes two 32-byte words in canonical sorted order —
// the OpenZeppelin MerkleProof._hashPair convention: keccak256(min || max).
func referenceSortedPair(a, b []byte) []byte {
	if bytes.Compare(a, b) <= 0 {
		return referenceKeccak(a, b)
	}
	return referenceKeccak(b, a)
}

// TestBuildMerkleRoot_EmptyYieldsZero: no leaves → zero root. This is the
// sentinel the distributor uses to flag "no attestations this window".
func TestBuildMerkleRoot_EmptyYieldsZero(t *testing.T) {
	var zero [32]byte
	got := BuildMerkleRoot(nil)
	if got != zero {
		t.Fatalf("empty records root = %x, want zero", got)
	}
	// Records with empty AttestationID are ignored.
	got = BuildMerkleRoot([]EarningRecord{
		{OrderID: "o1", ChainID: "c", Currency: "X", Amount: big.NewInt(1), SettledAt: time.Now()},
	})
	if got != zero {
		t.Fatalf("records without AttestationID → root = %x, want zero", got)
	}
}

// TestBuildMerkleRoot_SingleLeafRoundtrip: one leaf ⇒ root == keccak256(leaf).
// The caller-facing round-trip: a single-leaf proof is the empty proof, which
// the on-chain MerkleProof.verify handles by returning the leaf unchanged.
func TestBuildMerkleRoot_SingleLeafRoundtrip(t *testing.T) {
	att := []byte("attestation-id-0")
	records := []EarningRecord{
		{OrderID: "o1", ChainID: "c", Currency: "X", Amount: big.NewInt(1), AttestationID: att},
	}
	got := BuildMerkleRoot(records)
	want := referenceKeccak(att)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("single-leaf root = %x, want %x", got, want)
	}
}

// TestBuildMerkleRoot_RoundtripMatchesOZ independently computes the expected
// 2-leaf and 3-leaf OpenZeppelin-standard roots by hand-building the tree via
// referenceSortedPair, then verifies BuildMerkleRoot agrees byte-for-byte.
//
// The 3-leaf case exercises the odd-tail promotion path: at level 0 we have
// [A, B, C] (sorted), the pair (A,B) folds to P0, and C is promoted unchanged
// to level 1 as [P0, C]; level 1 folds to keccak256(min(P0,C) || max(P0,C)).
// This is the exact shape the PRC's MerkleProof.processProof expects.
func TestBuildMerkleRoot_RoundtripMatchesOZ(t *testing.T) {
	atts := [][]byte{
		[]byte("aaaa"),
		[]byte("bbbb"),
		[]byte("cccc"),
	}
	records := make([]EarningRecord, len(atts))
	for i, a := range atts {
		records[i] = EarningRecord{
			OrderID:       "o",
			ChainID:       "c",
			Currency:      "X",
			Amount:        big.NewInt(1),
			AttestationID: a,
		}
	}

	// --- 2-leaf reference ---
	leaves2 := [][]byte{referenceKeccak(atts[0]), referenceKeccak(atts[1])}
	// BuildMerkleRoot sorts the leaves; mirror that here.
	if bytes.Compare(leaves2[0], leaves2[1]) > 0 {
		leaves2[0], leaves2[1] = leaves2[1], leaves2[0]
	}
	ref2 := referenceSortedPair(leaves2[0], leaves2[1])
	got2 := BuildMerkleRoot(records[:2])
	if !bytes.Equal(got2[:], ref2) {
		t.Fatalf("2-leaf root = %x, want %x", got2, ref2)
	}

	// --- 3-leaf reference ---
	leaves3 := [][]byte{
		referenceKeccak(atts[0]),
		referenceKeccak(atts[1]),
		referenceKeccak(atts[2]),
	}
	// Sort.
	if bytes.Compare(leaves3[0], leaves3[1]) > 0 {
		leaves3[0], leaves3[1] = leaves3[1], leaves3[0]
	}
	if bytes.Compare(leaves3[1], leaves3[2]) > 0 {
		leaves3[1], leaves3[2] = leaves3[2], leaves3[1]
	}
	if bytes.Compare(leaves3[0], leaves3[1]) > 0 {
		leaves3[0], leaves3[1] = leaves3[1], leaves3[0]
	}
	// Level 0 → Level 1: (l0, l1) pair, l2 promoted.
	p0 := referenceSortedPair(leaves3[0], leaves3[1])
	// Level 1 → root: sorted-pair(p0, l2).
	ref3 := referenceSortedPair(p0, leaves3[2])
	got3 := BuildMerkleRoot(records[:3])
	if !bytes.Equal(got3[:], ref3) {
		t.Fatalf("3-leaf root = %x, want %x", got3, ref3)
	}
}

// TestBuildMerkleRoot_ProofVerifies demonstrates the full proof round-trip:
// build a root from known records, independently construct a leaf's inclusion
// proof, and verify the proof by walking it through the sorted-pair hash (the
// same loop libraries/MerkleProof.sol implements on-chain). The test passes
// iff the reconstructed-from-proof value equals the root.
//
// For N=2, the proof for leaves[0] is [leaves[1]] (after sort-by-leaf) and
// verification reduces to a single sorted-pair hash of the leaf and sibling.
func TestBuildMerkleRoot_ProofVerifies(t *testing.T) {
	atts := [][]byte{[]byte("alpha"), []byte("beta")}
	records := []EarningRecord{
		{OrderID: "o", ChainID: "c", Currency: "X", Amount: big.NewInt(1), AttestationID: atts[0]},
		{OrderID: "o", ChainID: "c", Currency: "X", Amount: big.NewInt(1), AttestationID: atts[1]},
	}
	root := BuildMerkleRoot(records)

	// Build a proof for atts[0]: its leaf is k(atts[0]), sibling is k(atts[1]).
	leafTarget := referenceKeccak(atts[0])
	sibling := referenceKeccak(atts[1])
	proof := [][]byte{sibling}

	// MerkleProof.processProof: fold the leaf up through the proof using
	// sorted-pair hashing. For a 2-leaf tree, one level.
	computed := leafTarget
	for _, sib := range proof {
		computed = referenceSortedPair(computed, sib)
	}
	if !bytes.Equal(computed, root[:]) {
		t.Fatalf("proof verification failed:\n  computed = %x\n  root     = %x",
			computed, root[:])
	}

	// Sanity: an invalid proof must NOT verify.
	bad := referenceKeccak([]byte("not-a-sibling"))
	computed = leafTarget
	computed = referenceSortedPair(computed, bad)
	if bytes.Equal(computed, root[:]) {
		t.Fatalf("bad proof accidentally verified: %x", computed)
	}
}

// TestBuildMerkleRoot_DeterministicAcrossOrderings confirms that reordering
// records (simulating two witnesses iterating their attestation log in
// different Go-map orders) still yields the same root. This is the
// first-writer-wins invariant at the builder layer: both racers must compute
// the same AttestationLogRoot or the on-chain (chainID, windowID) gate
// doesn't even catch duplicates — it catches them because it sees two
// matching roots being written.
func TestBuildMerkleRoot_DeterministicAcrossOrderings(t *testing.T) {
	atts := [][]byte{
		[]byte("aa"), []byte("bb"), []byte("cc"), []byte("dd"), []byte("ee"),
	}
	build := func(order []int) [32]byte {
		records := make([]EarningRecord, 0, len(order))
		for _, i := range order {
			records = append(records, EarningRecord{
				OrderID:       "o",
				ChainID:       "c",
				Currency:      "X",
				Amount:        big.NewInt(1),
				AttestationID: atts[i],
			})
		}
		return BuildMerkleRoot(records)
	}
	r1 := build([]int{0, 1, 2, 3, 4})
	r2 := build([]int{4, 0, 3, 1, 2})
	r3 := build([]int{2, 4, 1, 0, 3})
	if r1 != r2 || r2 != r3 {
		t.Fatalf("non-deterministic root across orderings:\n  r1=%x\n  r2=%x\n  r3=%x",
			r1, r2, r3)
	}
}

// TestBuildMerkleRoot_DedupesDuplicateIDs confirms that two EarningRecords
// referencing the same AttestationID contribute a single leaf. Callers often
// fan multiple per-witness records out of the same attestation (witness A
// and witness B both earning from order X) and the tree must not double-count.
func TestBuildMerkleRoot_DedupesDuplicateIDs(t *testing.T) {
	att := []byte("shared-attestation")
	r := []EarningRecord{
		{OrderID: "o", ChainID: "c", Currency: "X", Amount: big.NewInt(1), AttestationID: att},
		{OrderID: "o", ChainID: "c", Currency: "X", Amount: big.NewInt(1), AttestationID: att},
		{OrderID: "o", ChainID: "c", Currency: "X", Amount: big.NewInt(1), AttestationID: att},
	}
	got := BuildMerkleRoot(r)
	want := referenceKeccak(att)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("deduped single-leaf root = %x, want %x (hex-decoded: %s)",
			got, want, hex.EncodeToString(want))
	}
}
