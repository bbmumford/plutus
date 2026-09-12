/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package evmsign provides the canonical legacy EIP-155 transaction
// signing primitive shared by witness-level fee distribution and
// blob-escrow on-chain interactions.
//
// WHY A SEPARATE LEAF PACKAGE:
//   The witness package originally owned signLegacyTxEIP155 (private).
//   The adapter/evm package depends on witness for the PayoutBuilder
//   interface, so lifting the primitive into adapter/evm would create
//   a cycle. plutus/blob (the on-chain escrow client) also needs legacy
//   EIP-155 signing — duplicating the ~80 lines of consensus-critical
//   logic three places is a recipe for drift.
//
//   Putting the primitive in a dependency-free leaf package
//   (this one) lets witness, adapter/evm, and blob all import it
//   without forming any cycle:
//
//       plutus/evmsign   (leaf, zero plutus deps)
//         ├── plutus/witness    (uses evmsign)
//         ├── plutus/adapter/evm (uses witness, which uses evmsign)
//         └── plutus/blob       (uses evmsign directly)
//
// Security contract:
//   - priv is a 32-byte secp256k1 scalar; zero scalar rejected.
//   - Low-S normalization is enforced after dcrec's SignCompact has
//     already done it, so a library update cannot silently regress
//     Ethereum consensus.
//   - v = chainID*2 + 35 + recID — the EIP-155 replay-protection formula.
//   - The returned bytes are the RLP-encoded signed tx, directly suitable
//     for eth_sendRawTransaction.
package evmsign

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// LegacyTx is the public form SignLegacyTxEIP155 operates on. Fields map
// 1:1 to the nine RLP list elements of a legacy Ethereum transaction.
// Callers populate every field themselves (no implicit defaults — the
// signer is consensus-critical, defaults would mask bugs).
type LegacyTx struct {
	Nonce      uint64
	GasPrice   *big.Int
	GasLimit   uint64
	To         string // 0x-prefixed hex address; empty = contract creation
	Value      *big.Int
	Data       []byte
	EVMChainID uint64
}

// SignLegacyTxEIP155 RLP-encodes tx per EIP-155, keccak256-hashes the
// preimage, signs the digest with priv (secp256k1, RFC6979 deterministic
// k), and returns the raw wire-format bytes suitable for
// eth_sendRawTransaction.
func SignLegacyTxEIP155(tx LegacyTx, priv []byte) ([]byte, error) {
	if tx.EVMChainID == 0 {
		return nil, errors.New("evmsign: EIP-155 chain ID is zero")
	}
	if tx.GasPrice == nil || tx.GasPrice.Sign() <= 0 {
		return nil, errors.New("evmsign: gas price must be positive")
	}
	if tx.Value == nil {
		tx.Value = new(big.Int)
	}
	if len(priv) != 32 {
		return nil, fmt.Errorf("evmsign: private key must be 32 bytes, got %d", len(priv))
	}
	toBytes, err := decodeAddressHex(tx.To)
	if err != nil {
		return nil, fmt.Errorf("evmsign: decode to: %w", err)
	}

	// EIP-155 preimage: rlp([nonce, gasPrice, gasLimit, to, value, data,
	// chainID, 0, 0]).
	preimage := RLPList(
		RLPUint(tx.Nonce),
		RLPBigInt(tx.GasPrice),
		RLPUint(tx.GasLimit),
		RLPBytes(toBytes),
		RLPBigInt(tx.Value),
		RLPBytes(tx.Data),
		RLPUint(tx.EVMChainID),
		RLPUint(0),
		RLPUint(0),
	)
	digest := keccak256(preimage)

	sk := secp256k1.PrivKeyFromBytes(priv)
	if sk.Key.IsZero() {
		return nil, errors.New("evmsign: private key scalar is zero")
	}

	// dcrec SignCompact returns [27+recID, R(32), S(32)] with S already
	// low-S normalized (and recID flipped if S was negated).
	compact := ecdsa.SignCompact(sk, digest[:], false)
	if len(compact) != 65 {
		return nil, fmt.Errorf("evmsign: unexpected compact sig length %d", len(compact))
	}
	recID := int(compact[0]) - 27
	if recID < 0 || recID > 3 {
		return nil, fmt.Errorf("evmsign: recovery id %d out of range", recID)
	}
	r := new(big.Int).SetBytes(compact[1:33])
	sVal := new(big.Int).SetBytes(compact[33:65])

	// Defensive low-S enforcement.
	if sVal.Cmp(halfSecpOrder) > 0 {
		sVal = new(big.Int).Sub(secpOrder, sVal)
		recID ^= 1
	}

	// EIP-155: v = chainID*2 + 35 + recID.
	v := new(big.Int).SetUint64(tx.EVMChainID)
	v.Mul(v, big.NewInt(2))
	v.Add(v, big.NewInt(35))
	v.Add(v, big.NewInt(int64(recID)))

	signed := RLPList(
		RLPUint(tx.Nonce),
		RLPBigInt(tx.GasPrice),
		RLPUint(tx.GasLimit),
		RLPBytes(toBytes),
		RLPBigInt(tx.Value),
		RLPBytes(tx.Data),
		RLPBigInt(v),
		RLPBigInt(r),
		RLPBigInt(sVal),
	)
	return signed, nil
}

// AddressFromPrivKey derives the EIP-55 checksummed address for a raw
// 32-byte secp256k1 scalar. Exposed so callers that need to know "what
// address does my key sign for" (e.g. an EscrowClient's self-identity)
// can compute it without replicating the keccak+slice math.
func AddressFromPrivKey(priv []byte) (string, error) {
	if len(priv) != 32 {
		return "", fmt.Errorf("evmsign: private key must be 32 bytes, got %d", len(priv))
	}
	sk := secp256k1.PrivKeyFromBytes(priv)
	if sk.Key.IsZero() {
		return "", errors.New("evmsign: private key scalar is zero")
	}
	pub := sk.PubKey().SerializeUncompressed()
	if len(pub) != 65 || pub[0] != 0x04 {
		return "", fmt.Errorf("evmsign: unexpected pubkey format (len %d)", len(pub))
	}
	h := keccak256(pub[1:])
	addr := h[12:]

	lower := hex.EncodeToString(addr)
	hashOfLower := keccak256([]byte(lower))
	hashHex := hex.EncodeToString(hashOfLower[:])
	out := make([]byte, 42)
	out[0] = '0'
	out[1] = 'x'
	for i := 0; i < 40; i++ {
		c := lower[i]
		if c >= 'a' && c <= 'f' && hashHex[i] >= '8' {
			out[i+2] = c - 32
		} else {
			out[i+2] = c
		}
	}
	return string(out), nil
}

// decodeAddressHex accepts an optional 0x prefix and returns the 20 raw
// bytes, or the empty slice for an empty input (contract creation).
func decodeAddressHex(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) != 40 {
		return nil, fmt.Errorf("address must be 20 bytes (got %d hex chars)", len(s))
	}
	return hex.DecodeString(s)
}

// --- RLP primitives (exported so other plutus packages can use them
// without re-implementing, but unstable vs. a general-purpose RLP
// library — scope is intentionally "just enough for legacy Ethereum
// transactions").
//
// Zero is encoded as the empty byte string (NOT as 0x00). Integer
// encoders strip leading-zero bytes. Lists >= 56 bytes long use the
// 0xF7+len-of-len form.

// RLPBytes encodes a byte string per RLP rules.
func RLPBytes(b []byte) []byte {
	switch {
	case len(b) == 1 && b[0] < 0x80:
		return []byte{b[0]}
	case len(b) < 56:
		out := make([]byte, 0, 1+len(b))
		out = append(out, 0x80+byte(len(b)))
		out = append(out, b...)
		return out
	default:
		lenBytes := encodeLengthBE(uint64(len(b)))
		out := make([]byte, 0, 1+len(lenBytes)+len(b))
		out = append(out, 0xb7+byte(len(lenBytes)))
		out = append(out, lenBytes...)
		out = append(out, b...)
		return out
	}
}

// RLPList encodes a heterogeneous list of already-encoded RLP items.
func RLPList(items ...[]byte) []byte {
	total := 0
	for _, it := range items {
		total += len(it)
	}
	body := make([]byte, 0, total)
	for _, it := range items {
		body = append(body, it...)
	}
	switch {
	case total < 56:
		out := make([]byte, 0, 1+total)
		out = append(out, 0xc0+byte(total))
		out = append(out, body...)
		return out
	default:
		lenBytes := encodeLengthBE(uint64(total))
		out := make([]byte, 0, 1+len(lenBytes)+total)
		out = append(out, 0xf7+byte(len(lenBytes)))
		out = append(out, lenBytes...)
		out = append(out, body...)
		return out
	}
}

// RLPUint encodes a uint64 as an RLP byte string (leading zeros stripped;
// zero becomes the empty string).
func RLPUint(n uint64) []byte {
	if n == 0 {
		return RLPBytes(nil)
	}
	var buf [8]byte
	i := 8
	for v := n; v > 0; v >>= 8 {
		i--
		buf[i] = byte(v)
	}
	return RLPBytes(buf[i:])
}

// RLPBigInt encodes a non-negative *big.Int. Nil and zero both encode
// as the empty byte string. Negative values panic — legacy Ethereum has
// no signed-integer fields.
func RLPBigInt(n *big.Int) []byte {
	if n == nil || n.Sign() == 0 {
		return RLPBytes(nil)
	}
	if n.Sign() < 0 {
		panic("evmsign: negative big.Int cannot be RLP-encoded")
	}
	return RLPBytes(n.Bytes())
}

func encodeLengthBE(n uint64) []byte {
	var buf [8]byte
	i := 8
	for v := n; v > 0; v >>= 8 {
		i--
		buf[i] = byte(v)
	}
	if i == 8 {
		return []byte{0}
	}
	return buf[i:]
}

// --- secp256k1 curve constants used for low-S enforcement ------------------

var (
	secpOrder, _ = new(big.Int).SetString(
		"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16,
	)
	halfSecpOrder = new(big.Int).Rsh(secpOrder, 1)
)

// keccak256 is the Keccak-256 (pre-NIST-standardization SHA3) primitive
// Ethereum uses for transaction hashing. Kept package-private; callers
// that need keccak for general purposes should use sha3.NewLegacyKeccak256
// directly.
func keccak256(b []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
