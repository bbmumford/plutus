/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package witness

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"time"

	"github.com/bbmumford/plutus/canonical"
)

// EscrowSnapshotStatus mirrors the proto EscrowSnapshotStatus enum.
type EscrowSnapshotStatus int

const (
	EscrowSnapshotStatusUnspecified EscrowSnapshotStatus = 0
	EscrowSnapshotStatusPending    EscrowSnapshotStatus = 1
	EscrowSnapshotStatusFunded     EscrowSnapshotStatus = 2
	EscrowSnapshotStatusReleased   EscrowSnapshotStatus = 3
	EscrowSnapshotStatusDisputed   EscrowSnapshotStatus = 4
	EscrowSnapshotStatusSettled    EscrowSnapshotStatus = 5
	EscrowSnapshotStatusRefunded   EscrowSnapshotStatus = 6
)

// EscrowSnapshot captures the on-chain state of a Plutus escrow contract at
// the moment a witness reads it. Witnesses include this in balance/escrow
// attestations so verifiers can confirm escrow conditions without chain access.
// Fields align with the proto EscrowSnapshot message.
type EscrowSnapshot struct {
	Address     string               // escrow_address
	Buyer       string               // buyer
	Seller      string               // seller
	Amount      *big.Int             // amount (big.Int for Go, string in proto)
	Status      EscrowSnapshotStatus // status enum
	Arbitrator  string               // arbitrator address
	CreatedAt   uint64               // creation timestamp (unix seconds)
	TimeoutAt   uint64               // timeout timestamp (unix seconds)
	BlockNumber uint64               // block number at attestation time
	BlockHash   []byte               // block hash at attestation time
}

// ChainWitnessAttestation is a signed statement from a witness about on-chain
// state. Witnesses produce these in response to attestation requests published
// on the plutus.attest.request topic. Verifiers collect multiple attestations
// and check quorum agreement.
type ChainWitnessAttestation struct {
	ChainID             string
	TxHash              string
	BlockNumber         uint64
	Confirmed           bool
	Balance             *big.Int        // non-nil for balance queries
	EscrowState         *EscrowSnapshot // non-nil for escrow queries
	ProtocolFingerprint string          // must match local fingerprint or attestation is rejected
	WitnessPubKey       ed25519.PublicKey
	Timestamp           time.Time
	Signature           []byte

	// Anti-replay fields: WitnessSeq is a monotonically increasing sequence
	// number per witness. RequestNonce is a random nonce from the attestation
	// request, binding this response to a specific request.
	WitnessSeq   uint64
	RequestNonce []byte

	// Merkle proof fields: for High and Maximum verification levels,
	// witnesses include a Merkle proof anchoring the attested state to
	// a known block's state root.
	MerkleProof [][]byte
	MerkleRoot  []byte
}

// AttestationHash returns the SHA-256 digest of the attestation's content
// fields (everything except Signature). This is the message that gets signed.
func AttestationHash(a *ChainWitnessAttestation) []byte {
	h := sha256.New()

	h.Write([]byte(a.ChainID))
	h.Write([]byte(a.TxHash))

	var blockBuf [8]byte
	binary.BigEndian.PutUint64(blockBuf[:], a.BlockNumber)
	h.Write(blockBuf[:])

	if a.Confirmed {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}

	if a.Balance != nil {
		h.Write(a.Balance.Bytes())
	} else {
		h.Write([]byte{0})
	}

	if a.EscrowState != nil {
		writeEscrowToHash(h, a.EscrowState)
	}

	h.Write([]byte(a.ProtocolFingerprint))
	h.Write([]byte(a.WitnessPubKey))

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(a.Timestamp.UnixNano()))
	h.Write(tsBuf[:])

	// Include anti-replay fields in the hash.
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], a.WitnessSeq)
	h.Write(seqBuf[:])

	if len(a.RequestNonce) > 0 {
		h.Write(a.RequestNonce)
	}

	// Include Merkle proof fields in the hash.
	if len(a.MerkleRoot) > 0 {
		h.Write(a.MerkleRoot)
	}
	for _, node := range a.MerkleProof {
		h.Write(node)
	}

	return h.Sum(nil)
}

// writeEscrowToHash writes all EscrowSnapshot fields into the hash in a
// deterministic order.
func writeEscrowToHash(h hash.Hash, es *EscrowSnapshot) {
	h.Write([]byte(es.Address))
	h.Write([]byte(es.Buyer))
	h.Write([]byte(es.Seller))
	if es.Amount != nil {
		h.Write(es.Amount.Bytes())
	} else {
		h.Write([]byte{0})
	}

	var statusBuf [4]byte
	binary.BigEndian.PutUint32(statusBuf[:], uint32(es.Status))
	h.Write(statusBuf[:])

	h.Write([]byte(es.Arbitrator))

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], es.CreatedAt)
	h.Write(tsBuf[:])
	binary.BigEndian.PutUint64(tsBuf[:], es.TimeoutAt)
	h.Write(tsBuf[:])
	binary.BigEndian.PutUint64(tsBuf[:], es.BlockNumber)
	h.Write(tsBuf[:])
	h.Write(es.BlockHash)
}

// SignAttestation signs the attestation content with the given Ed25519 private
// key. The signature covers the SHA-256 hash of all content fields.
// The ProtocolFingerprint is automatically set to the current deployment's
// fingerprint before signing.
func SignAttestation(a *ChainWitnessAttestation, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("witness: invalid private key size %d", len(privateKey))
	}
	a.ProtocolFingerprint = canonical.ProtocolFingerprint()
	digest := AttestationHash(a)
	a.Signature = ed25519.Sign(privateKey, digest)
	return nil
}

// VerifyAttestation checks that the attestation's signature is valid for its
// content and was produced by the declared WitnessPubKey. It also rejects
// attestations from a different protocol fingerprint (Layer 4 fork isolation).
func VerifyAttestation(a *ChainWitnessAttestation) bool {
	if len(a.WitnessPubKey) != ed25519.PublicKeySize {
		return false
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return false
	}
	// Reject attestations from a forked deployment with a different fingerprint.
	// Also reject empty fingerprints when the local fingerprint is populated,
	// preventing bypass of fork isolation by omitting the field.
	localFP := canonical.ProtocolFingerprint()
	if localFP != "" && a.ProtocolFingerprint != localFP {
		return false
	}
	digest := AttestationHash(a)
	return ed25519.Verify(a.WitnessPubKey, digest, a.Signature)
}

// VerifyAttestationSequence checks that an attestation's sequence number is
// monotonically increasing relative to the last seen sequence for the same
// witness. Returns false if the sequence is a replay (not strictly greater
// than lastSeq).
func VerifyAttestationSequence(a *ChainWitnessAttestation, lastSeq uint64) bool {
	return a.WitnessSeq > lastSeq
}

// VerifyMerkleProofPresence checks that an attestation includes a Merkle proof
// and root when required by the verification policy. Returns true if the proof
// fields are present, or if merkle proof is not required.
func VerifyMerkleProofPresence(a *ChainWitnessAttestation, requireMerkleProof bool) bool {
	if !requireMerkleProof {
		return true
	}
	return len(a.MerkleRoot) > 0 && len(a.MerkleProof) > 0
}
