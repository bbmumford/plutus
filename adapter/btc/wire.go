/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package btc

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

// This file provides a minimal, pure-Go Bitcoin wire-format representation
// sufficient for constructing and BIP143-signing P2WSH release transactions.
// We deliberately avoid pulling in the full btcsuite dependency tree — all
// that's needed for Plutus BTC release is:
//
//   - SegWit tx serialization (BIP141)
//   - BIP143 sighash computation for P2WSH inputs
//   - Bech32 (BIP173) encoding for P2WPKH / P2WSH outputs
//
// The structure mirrors btcd's wire.MsgTx / wire.TxIn / wire.TxOut so that
// the signer API (SignBTCSettlement) can evolve to accept btcsuite types
// later without reshaping callers.

// OutPoint identifies a specific UTXO (txid + output index).
type OutPoint struct {
	// Hash is the 32-byte txid in internal byte order (little-endian on wire).
	Hash [32]byte
	// Index is the output index within the referenced transaction.
	Index uint32
}

// TxIn is one input to a Bitcoin transaction.
type TxIn struct {
	PreviousOutPoint OutPoint
	// SignatureScript is empty for segwit inputs (witness carries the sigs).
	SignatureScript []byte
	// Witness is the witness stack for segwit inputs.
	Witness [][]byte
	// Sequence per BIP68. Use 0xFFFFFFFF for non-RBF, or 0xFFFFFFFE when
	// honouring nLockTime.
	Sequence uint32
	// InputValue is the value (in satoshis) of the UTXO being spent. Required
	// for BIP143 sighash computation; not serialized on the wire.
	InputValue int64
	// WitnessScript is the redeem script for P2WSH inputs. Required for
	// BIP143 sighash computation; not serialized (it lives in Witness instead).
	WitnessScript []byte
}

// TxOut is one output of a Bitcoin transaction.
type TxOut struct {
	// Value is the output amount in satoshis.
	Value int64
	// PkScript is the locking script for this output.
	PkScript []byte
}

// MsgTx is a minimal Bitcoin transaction structure sufficient for building
// and signing P2WSH release transactions. Field semantics mirror btcd's
// wire.MsgTx.
type MsgTx struct {
	Version  int32
	TxIn     []*TxIn
	TxOut    []*TxOut
	LockTime uint32
}

// NewMsgTx returns an empty tx with the given version (typically 2 for
// BIP68 relative-lock support).
func NewMsgTx(version int32) *MsgTx {
	return &MsgTx{
		Version: version,
		TxIn:    make([]*TxIn, 0, 1),
		TxOut:   make([]*TxOut, 0, 6),
	}
}

// AddTxIn appends an input.
func (tx *MsgTx) AddTxIn(in *TxIn) { tx.TxIn = append(tx.TxIn, in) }

// AddTxOut appends an output.
func (tx *MsgTx) AddTxOut(out *TxOut) { tx.TxOut = append(tx.TxOut, out) }

// HasWitness returns true if any input has witness data.
func (tx *MsgTx) HasWitness() bool {
	for _, in := range tx.TxIn {
		if len(in.Witness) > 0 {
			return true
		}
	}
	return false
}

// writeVarInt writes a Bitcoin variable-length integer.
func writeVarInt(buf *bytes.Buffer, n uint64) {
	switch {
	case n < 0xfd:
		buf.WriteByte(byte(n))
	case n <= 0xffff:
		buf.WriteByte(0xfd)
		_ = binary.Write(buf, binary.LittleEndian, uint16(n))
	case n <= 0xffffffff:
		buf.WriteByte(0xfe)
		_ = binary.Write(buf, binary.LittleEndian, uint32(n))
	default:
		buf.WriteByte(0xff)
		_ = binary.Write(buf, binary.LittleEndian, n)
	}
}

// writeVarBytes writes a variable-length byte string prefixed by its length.
func writeVarBytes(buf *bytes.Buffer, b []byte) {
	writeVarInt(buf, uint64(len(b)))
	buf.Write(b)
}

// Serialize writes the full BIP141 segwit-format transaction bytes.
// Includes the marker (0x00) and flag (0x01) bytes and witness stacks
// whenever any input has witness data.
func (tx *MsgTx) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	// Version.
	_ = binary.Write(&buf, binary.LittleEndian, tx.Version)

	// Segwit marker + flag (if any input has witness).
	hasWitness := tx.HasWitness()
	if hasWitness {
		buf.WriteByte(0x00) // marker
		buf.WriteByte(0x01) // flag
	}

	// Inputs.
	writeVarInt(&buf, uint64(len(tx.TxIn)))
	for _, in := range tx.TxIn {
		// Outpoint: hash (32) + index (4, LE).
		buf.Write(in.PreviousOutPoint.Hash[:])
		_ = binary.Write(&buf, binary.LittleEndian, in.PreviousOutPoint.Index)

		// SignatureScript (empty for segwit inputs).
		writeVarBytes(&buf, in.SignatureScript)

		// Sequence.
		_ = binary.Write(&buf, binary.LittleEndian, in.Sequence)
	}

	// Outputs.
	writeVarInt(&buf, uint64(len(tx.TxOut)))
	for _, out := range tx.TxOut {
		_ = binary.Write(&buf, binary.LittleEndian, out.Value)
		writeVarBytes(&buf, out.PkScript)
	}

	// Witness data (if any input has witness).
	if hasWitness {
		for _, in := range tx.TxIn {
			writeVarInt(&buf, uint64(len(in.Witness)))
			for _, item := range in.Witness {
				writeVarBytes(&buf, item)
			}
		}
	}

	// LockTime.
	_ = binary.Write(&buf, binary.LittleEndian, tx.LockTime)

	return buf.Bytes(), nil
}

// SerializeNoWitness writes the legacy (pre-segwit) format: no marker/flag,
// no witness stacks. Used as a component of BIP143 sighash computation and
// for txid calculation.
func (tx *MsgTx) SerializeNoWitness() []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, tx.Version)

	writeVarInt(&buf, uint64(len(tx.TxIn)))
	for _, in := range tx.TxIn {
		buf.Write(in.PreviousOutPoint.Hash[:])
		_ = binary.Write(&buf, binary.LittleEndian, in.PreviousOutPoint.Index)
		writeVarBytes(&buf, in.SignatureScript)
		_ = binary.Write(&buf, binary.LittleEndian, in.Sequence)
	}

	writeVarInt(&buf, uint64(len(tx.TxOut)))
	for _, out := range tx.TxOut {
		_ = binary.Write(&buf, binary.LittleEndian, out.Value)
		writeVarBytes(&buf, out.PkScript)
	}

	_ = binary.Write(&buf, binary.LittleEndian, tx.LockTime)
	return buf.Bytes()
}

// TxHash returns the txid (double-SHA256 of the pre-segwit serialization),
// in internal byte order (i.e., not reversed).
func (tx *MsgTx) TxHash() [32]byte {
	raw := tx.SerializeNoWitness()
	first := sha256.Sum256(raw)
	return sha256.Sum256(first[:])
}

// TxID returns the txid as a lowercase hex string in display order (big-endian,
// i.e., reversed from internal order, the format users see in block explorers).
func (tx *MsgTx) TxID() string {
	h := tx.TxHash()
	// Reverse for display order.
	for i, j := 0, len(h)-1; i < j; i, j = i+1, j-1 {
		h[i], h[j] = h[j], h[i]
	}
	return hex.EncodeToString(h[:])
}

// ReverseHash reverses a 32-byte hash in place (used to convert between
// internal and display byte orders).
func reverseHash(h [32]byte) [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = h[31-i]
	}
	return out
}

// TxIDFromDisplayHex parses a display-order txid string into internal byte
// order suitable for assigning to OutPoint.Hash.
func TxIDFromDisplayHex(s string) ([32]byte, error) {
	var zero [32]byte
	if len(s) != 64 {
		return zero, fmt.Errorf("btc/wire: expected 64-char txid, got %d", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return zero, fmt.Errorf("btc/wire: decode txid hex: %w", err)
	}
	var h [32]byte
	copy(h[:], b)
	return reverseHash(h), nil
}

// SighashType is the BIP143 sighash flag.
type SighashType uint32

const (
	// SighashAll signs all inputs and outputs.
	SighashAll SighashType = 0x01
)

// ComputeBIP143SighashP2WSH returns the 32-byte digest to be signed for a
// P2WSH input using SIGHASH_ALL. It follows the BIP143 specification:
//
//	hashPrevouts = dsha256(all outpoints)
//	hashSequence = dsha256(all sequences)
//	hashOutputs  = dsha256(all outputs)
//	preimage = version || hashPrevouts || hashSequence || outpoint ||
//	           scriptCode || amount || nSequence || hashOutputs ||
//	           locktime || hashType
//	sighash = dsha256(preimage)
//
// scriptCode for P2WSH is the witness script (the redeem script), length-prefixed.
func (tx *MsgTx) ComputeBIP143SighashP2WSH(inputIndex int, hashType SighashType) ([32]byte, error) {
	var zero [32]byte
	if inputIndex < 0 || inputIndex >= len(tx.TxIn) {
		return zero, fmt.Errorf("btc/wire: input index %d out of range (have %d inputs)", inputIndex, len(tx.TxIn))
	}
	in := tx.TxIn[inputIndex]
	if len(in.WitnessScript) == 0 {
		return zero, errors.New("btc/wire: input has no WitnessScript; cannot compute BIP143 sighash")
	}
	if in.InputValue <= 0 {
		return zero, errors.New("btc/wire: input InputValue must be positive for BIP143 sighash")
	}
	if hashType != SighashAll {
		return zero, fmt.Errorf("btc/wire: unsupported sighash type 0x%x (only SIGHASH_ALL supported)", hashType)
	}

	// hashPrevouts: dsha256(outpoint_0 || outpoint_1 || ...)
	var prev bytes.Buffer
	for _, ti := range tx.TxIn {
		prev.Write(ti.PreviousOutPoint.Hash[:])
		_ = binary.Write(&prev, binary.LittleEndian, ti.PreviousOutPoint.Index)
	}
	hashPrevouts := dsha256(prev.Bytes())

	// hashSequence: dsha256(sequence_0 || sequence_1 || ...)
	var seq bytes.Buffer
	for _, ti := range tx.TxIn {
		_ = binary.Write(&seq, binary.LittleEndian, ti.Sequence)
	}
	hashSequence := dsha256(seq.Bytes())

	// hashOutputs: dsha256(value_0 || pkScriptLen_0 || pkScript_0 || ...)
	var outs bytes.Buffer
	for _, to := range tx.TxOut {
		_ = binary.Write(&outs, binary.LittleEndian, to.Value)
		writeVarBytes(&outs, to.PkScript)
	}
	hashOutputs := dsha256(outs.Bytes())

	// Preimage.
	var pre bytes.Buffer
	_ = binary.Write(&pre, binary.LittleEndian, tx.Version)
	pre.Write(hashPrevouts[:])
	pre.Write(hashSequence[:])
	pre.Write(in.PreviousOutPoint.Hash[:])
	_ = binary.Write(&pre, binary.LittleEndian, in.PreviousOutPoint.Index)
	writeVarBytes(&pre, in.WitnessScript) // scriptCode
	_ = binary.Write(&pre, binary.LittleEndian, in.InputValue)
	_ = binary.Write(&pre, binary.LittleEndian, in.Sequence)
	pre.Write(hashOutputs[:])
	_ = binary.Write(&pre, binary.LittleEndian, tx.LockTime)
	_ = binary.Write(&pre, binary.LittleEndian, uint32(hashType))

	return dsha256(pre.Bytes()), nil
}

// dsha256 returns sha256(sha256(b)).
func dsha256(b []byte) [32]byte {
	first := sha256.Sum256(b)
	return sha256.Sum256(first[:])
}

// ComputeBIP143SighashP2WPKH returns the BIP143 SIGHASH_ALL digest for a
// P2WPKH input. The caller is expected to have stored the P2WPKH scriptCode
// (0x76 0xa9 0x14 {hash160} 0x88 0xac, 25 bytes) in in.WitnessScript — this
// mirrors how the P2WSH variant consumes the witness script and lets both
// sighash paths share the same preimage assembly code.
//
// Structurally the two methods produce identical digests when given the
// correct scriptCode, so this is a thin semantic wrapper. It exists to
// document intent at the call site and to let future changes (e.g.
// SIGHASH_SINGLE support for P2WPKH) diverge cleanly.
func (tx *MsgTx) ComputeBIP143SighashP2WPKH(inputIndex int, hashType SighashType) ([32]byte, error) {
	return tx.ComputeBIP143SighashP2WSH(inputIndex, hashType)
}
