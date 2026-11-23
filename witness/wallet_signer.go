/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"strings"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	ecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/sha3"

	"github.com/bbmumford/plutus/evmsign"
)

// WalletSigner is the unified FeeDistributionSigner used by the witness fee
// distributor. It owns the decrypted per-chain private keys that spend the
// maintainer pool balance. Compromise of a WalletSigner is bounded to at
// most one distribution window's worth of fees (see fee_distributor.go
// comment block on signer separation).
//
// The signer dispatches on UnsignedBatch.Kind:
//
//   - BatchKindBTCMultiOutput    → per-input secp256k1 signatures + witness
//     assembly over the BIP141 segwit serialization (P2WPKH).
//   - BatchKindEVMMulticall3     → decode the EVMBatchEnvelope, sign an
//     EIP-155 legacy transaction, return the raw wire-format bytes.
//   - BatchKindEVMIndividual     → decode each envelope in ItemPayloads,
//     sign an EIP-155 legacy tx per item with the same wallet key, and
//     return one raw signed tx per item. All-or-nothing: if any item fails
//     to sign the whole batch is rejected.
//
// Keys are keyed by the chain identifier used throughout the distributor
// (e.g. "bitcoin", "ethereum", "polygon"); see FeeDistributorConfig.
// PoolAddresses. Callers load the keys from disk via
// wallet.ReadEncryptedKeyfile before constructing the signer so the
// signer itself stays passphrase-ignorant.
//
// Wire-format primitives (BTC segwit parse/serialize, RLP, EIP-155) are
// implemented locally in this package rather than imported from adapter/btc
// or adapter/evm to avoid an import cycle: those adapters already depend on
// the witness package for the PayoutBuilder interface.
type WalletSigner struct {
	perChainKeys map[string][]byte
	logger       Logger
}

// WalletSignerConfig configures a WalletSigner. KeyFiles and Passphrases are
// looked up by chain ID (matching the distributor's groupKey.chainID). It is
// a configuration error to supply a key file without a passphrase entry, but
// an empty passphrase is permitted when the keyfile was written unencrypted
// (see wallet.WriteEncryptedKeyfile — the empty-passphrase path still goes
// through Argon2id + AEAD but accepts an empty secret).
type WalletSignerConfig struct {
	// KeyFiles maps chainID → on-disk encrypted keyfile path.
	KeyFiles map[string]string
	// Passphrases maps chainID → passphrase bytes. Typical callers source
	// these from wallet.PassphraseFromEnv; values are used once at New and
	// are not retained on the signer.
	Passphrases map[string][]byte
	// Logger is optional; when nil, no logs are emitted.
	Logger Logger
}

// NewWalletSigner validates cfg and decrypts every keyfile eagerly so callers
// learn about bad passphrases / missing files at startup instead of mid-round.
//
// Returns a non-nil error for:
//   - empty chainID keys,
//   - empty key-file paths,
//   - chainIDs present in KeyFiles but absent from Passphrases,
//   - wallet.ReadEncryptedKeyfile errors (file missing, corrupt, bad passphrase),
//   - decrypted key material not 32 bytes long (non-secp256k1 scalar),
//   - decrypted material that reduces to the zero scalar modulo the curve order.
func NewWalletSigner(cfg WalletSignerConfig) (*WalletSigner, error) {
	if len(cfg.KeyFiles) == 0 {
		return nil, errors.New("witness/wallet_signer: no key files configured")
	}
	keys := make(map[string][]byte, len(cfg.KeyFiles))
	for chainID, path := range cfg.KeyFiles {
		if chainID == "" {
			return nil, errors.New("witness/wallet_signer: empty chain ID in KeyFiles")
		}
		if path == "" {
			return nil, fmt.Errorf("witness/wallet_signer: empty key file path for chain %q", chainID)
		}
		pass, ok := cfg.Passphrases[chainID]
		if !ok {
			return nil, fmt.Errorf("witness/wallet_signer: no passphrase configured for chain %q", chainID)
		}
		raw, err := readEncryptedKeyfile(path, pass)
		if err != nil {
			return nil, fmt.Errorf("witness/wallet_signer: read keyfile for %q: %w", chainID, err)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf(
				"witness/wallet_signer: keyfile for %q is %d bytes, want 32 (secp256k1 scalar)",
				chainID, len(raw),
			)
		}
		sk := secp256k1.PrivKeyFromBytes(raw)
		if sk.Key.IsZero() {
			return nil, fmt.Errorf("witness/wallet_signer: keyfile for %q decodes to zero scalar", chainID)
		}
		keys[chainID] = append([]byte(nil), raw...)
	}
	logger := cfg.Logger
	if logger == nil {
		logger = nopLogger{}
	}
	return &WalletSigner{perChainKeys: keys, logger: logger}, nil
}

// Compile-time assertion.
var _ FeeDistributionSigner = (*WalletSigner)(nil)

// SignBatchPayout implements FeeDistributionSigner.
func (s *WalletSigner) SignBatchPayout(ctx context.Context, batch UnsignedBatch) (SignedBatch, error) {
	if s == nil {
		return SignedBatch{}, errors.New("witness/wallet_signer: nil receiver")
	}
	priv, ok := s.perChainKeys[batch.ChainID]
	if !ok {
		return SignedBatch{}, fmt.Errorf(
			"witness/wallet_signer: no key configured for chain %q", batch.ChainID,
		)
	}

	switch batch.Kind {
	case BatchKindBTCMultiOutput:
		return s.signBTC(batch, priv)
	case BatchKindEVMMulticall3:
		return s.signEVMAggregate(batch, priv)
	case BatchKindEVMIndividual:
		return s.signEVMIndividual(batch, priv)
	case BatchKindUnspecified:
		return SignedBatch{}, errors.New("witness/wallet_signer: batch kind is unspecified")
	default:
		return SignedBatch{}, fmt.Errorf("witness/wallet_signer: unsupported batch kind %d", batch.Kind)
	}
}

// =============================================================================
// BTC path
// =============================================================================

// signBTC produces per-input P2WPKH witness stacks from the precomputed
// sighashes and assembles the full BIP141 segwit-serialized tx.
func (s *WalletSigner) signBTC(batch UnsignedBatch, priv []byte) (SignedBatch, error) {
	if len(batch.Sighashes) == 0 {
		return SignedBatch{}, errors.New("witness/wallet_signer: BTC batch missing Sighashes")
	}
	if len(batch.InputScripts) != len(batch.Sighashes) {
		return SignedBatch{}, fmt.Errorf(
			"witness/wallet_signer: InputScripts (%d) / Sighashes (%d) length mismatch",
			len(batch.InputScripts), len(batch.Sighashes),
		)
	}
	if len(batch.InputValues) != len(batch.Sighashes) {
		return SignedBatch{}, fmt.Errorf(
			"witness/wallet_signer: InputValues (%d) / Sighashes (%d) length mismatch",
			len(batch.InputValues), len(batch.Sighashes),
		)
	}
	if len(batch.Payload) == 0 {
		return SignedBatch{}, errors.New("witness/wallet_signer: BTC batch missing Payload (serialized unsigned tx)")
	}
	for i, sh := range batch.Sighashes {
		if len(sh) != 32 {
			return SignedBatch{}, fmt.Errorf(
				"witness/wallet_signer: sighash[%d] is %d bytes, want 32",
				i, len(sh),
			)
		}
	}

	tx, err := parseUnsignedBTCTx(batch.Payload)
	if err != nil {
		return SignedBatch{}, fmt.Errorf("witness/wallet_signer: parse unsigned btc tx: %w", err)
	}
	if len(tx.txIn) != len(batch.Sighashes) {
		return SignedBatch{}, fmt.Errorf(
			"witness/wallet_signer: tx inputs (%d) != Sighashes (%d)",
			len(tx.txIn), len(batch.Sighashes),
		)
	}

	sk := secp256k1.PrivKeyFromBytes(priv)
	compressedPub := sk.PubKey().SerializeCompressed()

	for i, sighash := range batch.Sighashes {
		sig := ecdsa.Sign(sk, sighash)
		der := sig.Serialize()
		witSig := make([]byte, 0, len(der)+1)
		witSig = append(witSig, der...)
		witSig = append(witSig, btcSighashAll) // SIGHASH_ALL flag byte
		tx.txIn[i].witness = [][]byte{witSig, compressedPub}
	}

	raw, err := tx.serializeSegwit()
	if err != nil {
		return SignedBatch{}, fmt.Errorf("witness/wallet_signer: serialize signed btc tx: %w", err)
	}
	return SignedBatch{
		ChainID: batch.ChainID,
		Txs:     [][]byte{raw},
	}, nil
}

// btcSighashAll is the SIGHASH_ALL byte (0x01) appended to a DER signature
// on a P2WPKH witness stack.
const btcSighashAll byte = 0x01

// btcTxIn / btcTxOut / btcMsgTx mirror the wire-format structs in
// adapter/btc. We redeclare them locally to break the import cycle that
// would arise from witness → adapter/btc → witness.
type btcTxIn struct {
	prevHash  [32]byte
	prevIndex uint32
	sigScript []byte
	sequence  uint32
	witness   [][]byte
}

type btcTxOut struct {
	value    int64
	pkScript []byte
}

type btcMsgTx struct {
	version  int32
	txIn     []*btcTxIn
	txOut    []*btcTxOut
	lockTime uint32
}

// parseUnsignedBTCTx reparses the builder's serialized unsigned tx. The
// builder emits the legacy (pre-segwit) form when no input carries witness
// data, so we read that form here.
func parseUnsignedBTCTx(raw []byte) (*btcMsgTx, error) {
	if len(raw) < 10 {
		return nil, fmt.Errorf("raw tx too short (%d bytes)", len(raw))
	}
	tx := &btcMsgTx{}
	pos := 0

	if pos+4 > len(raw) {
		return nil, errors.New("version truncated")
	}
	tx.version = int32(binary.LittleEndian.Uint32(raw[pos : pos+4]))
	pos += 4

	// Optional segwit marker + flag. Unsigned txs have no witness data and
	// therefore omit these bytes; we still defend against a producer that
	// emits them prematurely.
	if pos+1 < len(raw) && raw[pos] == 0x00 && raw[pos+1] == 0x01 {
		pos += 2
	}

	inCount, n, err := readVarInt(raw[pos:])
	if err != nil {
		return nil, fmt.Errorf("input count: %w", err)
	}
	pos += n
	for i := uint64(0); i < inCount; i++ {
		if pos+36 > len(raw) {
			return nil, fmt.Errorf("input %d outpoint truncated", i)
		}
		var in btcTxIn
		copy(in.prevHash[:], raw[pos:pos+32])
		pos += 32
		in.prevIndex = binary.LittleEndian.Uint32(raw[pos : pos+4])
		pos += 4

		sigLen, n, err := readVarInt(raw[pos:])
		if err != nil {
			return nil, fmt.Errorf("input %d sig script length: %w", i, err)
		}
		pos += n
		if uint64(pos)+sigLen > uint64(len(raw)) {
			return nil, fmt.Errorf("input %d sig script truncated", i)
		}
		if sigLen > 0 {
			in.sigScript = append([]byte(nil), raw[pos:pos+int(sigLen)]...)
		}
		pos += int(sigLen)

		if pos+4 > len(raw) {
			return nil, fmt.Errorf("input %d sequence truncated", i)
		}
		in.sequence = binary.LittleEndian.Uint32(raw[pos : pos+4])
		pos += 4
		tx.txIn = append(tx.txIn, &in)
	}

	outCount, n, err := readVarInt(raw[pos:])
	if err != nil {
		return nil, fmt.Errorf("output count: %w", err)
	}
	pos += n
	for i := uint64(0); i < outCount; i++ {
		if pos+8 > len(raw) {
			return nil, fmt.Errorf("output %d value truncated", i)
		}
		val := int64(binary.LittleEndian.Uint64(raw[pos : pos+8]))
		pos += 8
		pkLen, n, err := readVarInt(raw[pos:])
		if err != nil {
			return nil, fmt.Errorf("output %d pkScript length: %w", i, err)
		}
		pos += n
		if uint64(pos)+pkLen > uint64(len(raw)) {
			return nil, fmt.Errorf("output %d pkScript truncated", i)
		}
		pk := append([]byte(nil), raw[pos:pos+int(pkLen)]...)
		pos += int(pkLen)
		tx.txOut = append(tx.txOut, &btcTxOut{value: val, pkScript: pk})
	}

	if pos+4 > len(raw) {
		return nil, errors.New("locktime truncated")
	}
	tx.lockTime = binary.LittleEndian.Uint32(raw[pos : pos+4])
	pos += 4

	if pos != len(raw) {
		return nil, fmt.Errorf("trailing bytes after locktime: %d", len(raw)-pos)
	}
	return tx, nil
}

// serializeSegwit emits the BIP141 segwit form of the tx, including the
// marker+flag bytes and per-input witness stacks when any input carries
// witness data.
func (tx *btcMsgTx) serializeSegwit() ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, tx.version); err != nil {
		return nil, err
	}

	hasWitness := false
	for _, in := range tx.txIn {
		if len(in.witness) > 0 {
			hasWitness = true
			break
		}
	}
	if hasWitness {
		buf.WriteByte(0x00)
		buf.WriteByte(0x01)
	}

	writeVarInt(&buf, uint64(len(tx.txIn)))
	for _, in := range tx.txIn {
		buf.Write(in.prevHash[:])
		_ = binary.Write(&buf, binary.LittleEndian, in.prevIndex)
		writeVarBytes(&buf, in.sigScript)
		_ = binary.Write(&buf, binary.LittleEndian, in.sequence)
	}

	writeVarInt(&buf, uint64(len(tx.txOut)))
	for _, out := range tx.txOut {
		_ = binary.Write(&buf, binary.LittleEndian, out.value)
		writeVarBytes(&buf, out.pkScript)
	}

	if hasWitness {
		for _, in := range tx.txIn {
			writeVarInt(&buf, uint64(len(in.witness)))
			for _, item := range in.witness {
				writeVarBytes(&buf, item)
			}
		}
	}

	_ = binary.Write(&buf, binary.LittleEndian, tx.lockTime)
	return buf.Bytes(), nil
}

// readVarInt parses a Bitcoin variable-length integer at the start of b.
func readVarInt(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("empty buffer")
	}
	switch b[0] {
	case 0xff:
		if len(b) < 9 {
			return 0, 0, errors.New("truncated uint64 varint")
		}
		return binary.LittleEndian.Uint64(b[1:9]), 9, nil
	case 0xfe:
		if len(b) < 5 {
			return 0, 0, errors.New("truncated uint32 varint")
		}
		return uint64(binary.LittleEndian.Uint32(b[1:5])), 5, nil
	case 0xfd:
		if len(b) < 3 {
			return 0, 0, errors.New("truncated uint16 varint")
		}
		return uint64(binary.LittleEndian.Uint16(b[1:3])), 3, nil
	default:
		return uint64(b[0]), 1, nil
	}
}

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

func writeVarBytes(buf *bytes.Buffer, b []byte) {
	writeVarInt(buf, uint64(len(b)))
	buf.Write(b)
}

// =============================================================================
// EVM path
// =============================================================================

// evmEnvelope is the decoded form of an EVM UnsignedBatch.Payload. We
// reparse the JSON-ish format emitted by adapter/evm.EVMBatchEnvelope.Marshal
// without importing adapter/evm (which would form an import cycle).
type evmEnvelope struct {
	to         string
	value      *big.Int
	data       []byte
	gasLimit   uint64
	evmChainID uint64
	from       string
	nonce      uint64
	nonceSet   bool
	gasPrice   *big.Int
}

// signEVMAggregate decodes the envelope from batch.Payload, builds a legacy
// EIP-155 transaction, signs it with priv, and returns the raw serialized
// bytes as the single element of SignedBatch.Txs. Used for
// BatchKindEVMMulticall3.
func (s *WalletSigner) signEVMAggregate(batch UnsignedBatch, priv []byte) (SignedBatch, error) {
	if len(batch.Payload) == 0 {
		return SignedBatch{}, errors.New("witness/wallet_signer: EVM batch missing envelope payload")
	}
	raw, err := s.signOneEVMEnvelope(batch.Payload, priv)
	if err != nil {
		return SignedBatch{}, err
	}
	return SignedBatch{ChainID: batch.ChainID, Txs: [][]byte{raw}}, nil
}

// signEVMIndividual walks batch.ItemPayloads and produces one fully-signed
// EIP-155 legacy transaction per item, all signed with the same wallet key
// (the pool-wallet private key for batch.ChainID). If any item fails to
// parse, validate, or sign, the whole batch is rejected — no partial-success
// output, which keeps the broadcaster from sending a mid-range gap that would
// strand later txs behind an unsigned nonce.
func (s *WalletSigner) signEVMIndividual(batch UnsignedBatch, priv []byte) (SignedBatch, error) {
	if len(batch.ItemPayloads) == 0 {
		return SignedBatch{}, errors.New("witness/wallet_signer: BatchKindEVMIndividual has no ItemPayloads")
	}
	txs := make([][]byte, 0, len(batch.ItemPayloads))
	for i, raw := range batch.ItemPayloads {
		signedRaw, err := s.signOneEVMEnvelope(raw, priv)
		if err != nil {
			return SignedBatch{}, fmt.Errorf("witness/wallet_signer: item %d: %w", i, err)
		}
		txs = append(txs, signedRaw)
	}
	return SignedBatch{ChainID: batch.ChainID, Txs: txs}, nil
}

// signOneEVMEnvelope is the common per-envelope path used by both aggregate
// and individual EVM signing. It parses, validates, and EIP-155 signs a
// single envelope against priv. Returns the RLP-encoded signed tx bytes.
func (s *WalletSigner) signOneEVMEnvelope(payload, priv []byte) ([]byte, error) {
	env, err := parseEVMEnvelope(payload)
	if err != nil {
		return nil, fmt.Errorf("decode EVM envelope: %w", err)
	}
	if env.evmChainID == 0 {
		return nil, errors.New("EVM envelope has zero chain ID (EIP-155 requires explicit chain ID)")
	}
	if env.gasLimit == 0 {
		return nil, errors.New("EVM envelope has zero gas limit")
	}
	if !env.nonceSet {
		return nil, errors.New("EVM envelope missing nonce (caller must populate before signing)")
	}
	if env.gasPrice == nil || env.gasPrice.Sign() <= 0 {
		return nil, errors.New("EVM envelope missing gas price (caller must populate before signing)")
	}
	raw, err := evmsign.SignLegacyTxEIP155(evmsign.LegacyTx{
		Nonce:      env.nonce,
		GasPrice:   env.gasPrice,
		GasLimit:   env.gasLimit,
		To:         env.to,
		Value:      env.value,
		Data:       env.data,
		EVMChainID: env.evmChainID,
	}, priv)
	if err != nil {
		return nil, fmt.Errorf("EIP-155 sign: %w", err)
	}
	return raw, nil
}

// parseEVMEnvelope mirrors adapter/evm.UnmarshalEVMBatchEnvelope but lives
// here to break the witness → adapter/evm import cycle. The envelope format
// is a small hand-written JSON document (see adapter/evm/payout_builder.go
// EVMBatchEnvelope.Marshal).
func parseEVMEnvelope(raw []byte) (evmEnvelope, error) {
	var env evmEnvelope
	s := string(raw)

	getField := func(key string) (string, bool) {
		idx := strings.Index(s, `"`+key+`":`)
		if idx < 0 {
			return "", false
		}
		rest := s[idx+len(key)+3:]
		for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
			rest = rest[1:]
		}
		if len(rest) == 0 {
			return "", false
		}
		if rest[0] == '"' {
			end := strings.IndexByte(rest[1:], '"')
			if end < 0 {
				return "", false
			}
			return rest[1 : 1+end], true
		}
		end := strings.IndexAny(rest, ",}")
		if end < 0 {
			return "", false
		}
		return strings.TrimSpace(rest[:end]), true
	}

	if v, ok := getField("to"); ok {
		env.to = v
	}
	if v, ok := getField("value"); ok {
		hexStr := strings.TrimPrefix(v, "0x")
		n := new(big.Int)
		if hexStr != "" {
			if _, ok := n.SetString(hexStr, 16); !ok {
				return env, fmt.Errorf("invalid value hex %q", v)
			}
		}
		env.value = n
	}
	if v, ok := getField("data"); ok {
		hexStr := strings.TrimPrefix(v, "0x")
		data, err := hex.DecodeString(hexStr)
		if err != nil {
			return env, fmt.Errorf("invalid data hex: %w", err)
		}
		env.data = data
	}
	if v, ok := getField("gasLimit"); ok {
		var n uint64
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
			return env, fmt.Errorf("invalid gasLimit %q: %w", v, err)
		}
		env.gasLimit = n
	}
	if v, ok := getField("evmChainID"); ok {
		var n uint64
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
			return env, fmt.Errorf("invalid evmChainID %q: %w", v, err)
		}
		env.evmChainID = n
	}
	if v, ok := getField("from"); ok {
		env.from = v
	}
	if v, ok := getField("nonce"); ok {
		var n uint64
		if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
			return env, fmt.Errorf("invalid nonce %q: %w", v, err)
		}
		env.nonce = n
		env.nonceSet = true
	}
	if v, ok := getField("nonceSet"); ok {
		if v == "true" {
			env.nonceSet = true
		}
	}
	if v, ok := getField("gasPrice"); ok {
		hexStr := strings.TrimPrefix(v, "0x")
		n := new(big.Int)
		if hexStr != "" {
			if _, ok := n.SetString(hexStr, 16); !ok {
				return env, fmt.Errorf("invalid gasPrice hex %q", v)
			}
		}
		env.gasPrice = n
	}
	return env, nil
}

// --- EIP-155 signing delegation -------------------------------------------
//
// The consensus-critical legacy-tx signing primitive now lives in the
// leaf package plutus/evmsign. Historically it was defined here, which
// forced the blob-escrow client to duplicate ~80 lines. This file keeps
// thin wrappers under the old private names so the existing in-package
// test suite (wallet_signer_test.go) continues to exercise identical
// byte sequences, and so any future caller in witness that needs to
// RLP-encode a header field has the helper at hand.

// rlpBytes / rlpList / rlpUint / rlpBigInt / keccak256 are thin
// re-exports of evmsign helpers. Do NOT add logic here — every caller
// that wants legacy EIP-155 signing or RLP encoding should go through
// evmsign directly; these wrappers exist only for historical test
// compatibility.

func rlpBytes(b []byte) []byte      { return evmsign.RLPBytes(b) }
func rlpList(items ...[]byte) []byte { return evmsign.RLPList(items...) }
func rlpUint(n uint64) []byte       { return evmsign.RLPUint(n) }
func rlpBigInt(n *big.Int) []byte   { return evmsign.RLPBigInt(n) }

func keccak256(b []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// --- encrypted keyfile decrypt --------------------------------------------
//
// readEncryptedKeyfile is a local clone of wallet.ReadEncryptedKeyfile.
// Keeping it here — rather than importing plutus/wallet — avoids the import
// cycle that would form through wallet → adapter/btc → witness. The file
// format is the spec-verbatim [salt:16][nonce:24][ciphertext+tag] per
// cryptographic-protocol.md §8 and is bit-compatible with the wallet
// helper (same Argon2id parameters, same AEAD, same associated data).
const (
	keyfileSaltSize        = 16
	keyfileNonceSize       = 24
	keyfileTagSize         = 16
	keyfileArgon2Time      = 3
	keyfileArgon2Memory    = 64 * 1024
	keyfileArgon2Threads   = 4
	keyfileArgon2KeyLen    = 32
	keyfileAssociatedData  = "mercury-wallet-v1"
)

// ErrKeyfileBadPassphrase is returned when the on-disk ciphertext fails
// AEAD verification — cryptographically indistinguishable from a tampered
// blob and, per usual AEAD practice, collapsed into a single sentinel.
var ErrKeyfileBadPassphrase = errors.New("witness/wallet_signer: bad passphrase (AEAD verify failed)")

func readEncryptedKeyfile(path string, passphrase []byte) ([]byte, error) {
	if path == "" {
		return nil, errors.New("keyfile path is empty")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("keyfile not found: %s", path)
		}
		return nil, fmt.Errorf("read keyfile: %w", err)
	}
	if len(data) < keyfileSaltSize+keyfileNonceSize+keyfileTagSize {
		return nil, fmt.Errorf("keyfile corrupt or truncated: %s (have %d bytes, need >=%d)",
			path, len(data), keyfileSaltSize+keyfileNonceSize+keyfileTagSize)
	}
	salt := data[:keyfileSaltSize]
	nonce := data[keyfileSaltSize : keyfileSaltSize+keyfileNonceSize]
	ciphertext := data[keyfileSaltSize+keyfileNonceSize:]

	key := argon2.IDKey(
		passphrase, salt,
		keyfileArgon2Time, keyfileArgon2Memory, keyfileArgon2Threads, keyfileArgon2KeyLen,
	)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("AEAD construction failed: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, []byte(keyfileAssociatedData))
	if err != nil {
		return nil, ErrKeyfileBadPassphrase
	}
	return plaintext, nil
}

// evmAddressFromPrivKey derives the EIP-55 checksummed address for a raw
// 32-byte secp256k1 scalar. Exposed (lowercase) for package-internal test
// assertions.
func evmAddressFromPrivKey(priv []byte) (string, error) {
	if len(priv) != 32 {
		return "", fmt.Errorf("private key must be 32 bytes, got %d", len(priv))
	}
	sk := secp256k1.PrivKeyFromBytes(priv)
	if sk.Key.IsZero() {
		return "", errors.New("private key scalar is zero")
	}
	pub := sk.PubKey().SerializeUncompressed()
	if len(pub) != 65 || pub[0] != 0x04 {
		return "", fmt.Errorf("unexpected pubkey format (len %d)", len(pub))
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
