/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package btc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/bbmumford/plutus/witness"
)

// WitnessWindowOpReturnMagic is the 4-byte magic prefix ("WWDW" — Witness
// Window Distribute Window) the BTC payout builder writes into an OP_RETURN
// output whenever first-writer-wins window metadata is available. Off-
// chain auditors scan a distribution tx's outputs for this prefix to
// recover (windowID, attestationLogRoot) without decoding proprietary
// structures.
//
// Full payload: 4 (magic) + 8 (windowID BE) + 32 (root) = 44 bytes. Fits
// comfortably under the 80-byte standard OP_RETURN relay limit.
var WitnessWindowOpReturnMagic = []byte{0x57, 0x57, 0x44, 0x57}

// DefaultPayoutFeeRateSatPerVByte is the fallback mempool.space-style default
// used when no explicit fee rate is configured. 20 sat/vbyte is a
// conservative "next-few-blocks" rate that works outside fee spikes.
const DefaultPayoutFeeRateSatPerVByte = 20.0

// PoolUTXO describes one UTXO owned by the maintainer pool that the payout
// builder can spend. Callers (typically the fee-distribution node, which has
// a Neutrino or full-node client) populate these before invoking the builder
// so the builder itself does no network IO.
type PoolUTXO struct {
	// TxID is the 32-byte txid in display order (big-endian hex) — matches
	// the format returned by block explorers and RPC `listunspent`.
	TxID string
	// Vout is the output index within TxID that we're spending.
	Vout uint32
	// AmountSat is the value of the UTXO in satoshis.
	AmountSat int64
	// PubKeyHash160 is the 20-byte HASH160 of the compressed public key that
	// owns this UTXO. All pool UTXOs are expected to be P2WPKH outputs, so
	// the scriptPubKey is `0x0014{pubKeyHash160}` and the BIP143 scriptCode
	// is `0x1976a914{pubKeyHash160}88ac`. We carry the hash160 rather than
	// the pubkey itself because the builder only needs it for the sighash
	// preimage; the signer supplies the signature and pubkey.
	PubKeyHash160 [20]byte
}

// PoolUTXOSource is the read-side dependency the builder uses to discover
// which UTXOs it can consolidate into a batch payout. Implementations in
// production wrap a Neutrino client or full node; test doubles just return a
// fixed slice.
type PoolUTXOSource interface {
	// PoolUTXOs returns every UTXO currently owned by the pool `from`
	// address. Implementations may filter unconfirmed or below-minimum
	// values; the builder does no further filtering.
	PoolUTXOs(from string) ([]PoolUTXO, error)
}

// StaticPoolUTXOSource is a convenience implementation for callers that
// already know the UTXO set (tests, regtest fixtures, scripted deployments).
type StaticPoolUTXOSource struct {
	ByAddr map[string][]PoolUTXO
}

// PoolUTXOs implements PoolUTXOSource.
func (s *StaticPoolUTXOSource) PoolUTXOs(from string) ([]PoolUTXO, error) {
	if s == nil || s.ByAddr == nil {
		return nil, fmt.Errorf("btc/payout: no static UTXO map configured")
	}
	utxos, ok := s.ByAddr[from]
	if !ok {
		return nil, fmt.Errorf("btc/payout: no UTXOs for pool address %s", from)
	}
	return append([]PoolUTXO(nil), utxos...), nil
}

// BTCPayoutBuilderConfig configures a new BTCPayoutBuilder.
type BTCPayoutBuilderConfig struct {
	// Network is "mainnet", "testnet", or "regtest". The builder rejects
	// recipient + pool addresses whose HRP does not match the configured
	// network, so a mainnet builder cannot be tricked into paying out to
	// testnet addresses and vice versa.
	Network string
	// UTXOSource supplies pool UTXOs at BuildBatchPayout time. Required —
	// the builder does no network IO of its own.
	UTXOSource PoolUTXOSource
	// FeeRateSatPerVByte overrides DefaultPayoutFeeRateSatPerVByte. Must be
	// positive when non-zero.
	FeeRateSatPerVByte float64
	// DustThreshold overrides DefaultDustThreshold (546 sat). Set only in
	// tests that exercise custom relay rules.
	DustThreshold int64
}

// BTCPayoutBuilder assembles a single Bitcoin transaction that consolidates
// the pool's P2WPKH UTXOs into N P2WPKH outputs (one per payout) plus a
// change output back to the pool address. The tx is returned BIP143-ready:
// the per-input sighashes are precomputed so the signer only needs to
// produce ECDSA signatures.
//
// The builder never broadcasts; it never queries chain state; it never holds
// a private key. Those responsibilities live in the fee-distribution signer.
// Keeping this layer pure makes it trivial to unit test and safe to run
// inside WASM, inside a TEE, or in a process with no network access.
type BTCPayoutBuilder struct {
	network            string
	hrp                string
	chainID            string
	utxoSource         PoolUTXOSource
	feeRateSatPerVByte float64
	dustThreshold      int64
}

// Compile-time assertion: BTCPayoutBuilder implements witness.PayoutBuilder.
var _ witness.PayoutBuilder = (*BTCPayoutBuilder)(nil)

// Compile-time assertion: BTCPayoutBuilder exposes the window-aware extension
// so the distributor can thread the window metadata into the serialized tx
// via an OP_RETURN output.
var _ witness.WindowAwarePayoutBuilder = (*BTCPayoutBuilder)(nil)

// NewBTCPayoutBuilder constructs a builder from cfg. Returns an error when
// the network is unknown or UTXOSource is nil.
func NewBTCPayoutBuilder(cfg BTCPayoutBuilderConfig) (*BTCPayoutBuilder, error) {
	hrp := "bc"
	chainID := "bitcoin"
	switch cfg.Network {
	case "", "mainnet":
		hrp = "bc"
		chainID = "bitcoin"
	case "testnet":
		hrp = "tb"
		chainID = "bitcoin-testnet"
	case "regtest":
		hrp = "bcrt"
		chainID = "bitcoin-regtest"
	default:
		return nil, fmt.Errorf("btc/payout: unknown network %q", cfg.Network)
	}
	if cfg.UTXOSource == nil {
		return nil, errors.New("btc/payout: UTXOSource is required")
	}
	feeRate := cfg.FeeRateSatPerVByte
	if feeRate <= 0 {
		feeRate = DefaultPayoutFeeRateSatPerVByte
	}
	dust := cfg.DustThreshold
	if dust <= 0 {
		dust = DefaultDustThreshold
	}
	return &BTCPayoutBuilder{
		network:            cfg.Network,
		hrp:                hrp,
		chainID:            chainID,
		utxoSource:         cfg.UTXOSource,
		feeRateSatPerVByte: feeRate,
		dustThreshold:      dust,
	}, nil
}

// ChainID returns the canonical chain ID the builder is targeting.
func (b *BTCPayoutBuilder) ChainID() string { return b.chainID }

// HRP returns the bech32 human-readable prefix the builder accepts.
func (b *BTCPayoutBuilder) HRP() string { return b.hrp }

// BuildBatchPayout implements witness.PayoutBuilder. The `useMulticall3`
// flag is ignored for Bitcoin — there is no equivalent primitive; we always
// emit a single multi-output transaction.
//
// Algorithm:
//
//  1. Validate that every payout amount is above the dust threshold and
//     every payout/change address decodes as a P2WPKH bech32 address whose
//     HRP matches the configured network.
//  2. Fetch pool UTXOs from UTXOSource(from).
//  3. Sort payouts deterministically by witness address so the resulting
//     tx is byte-identical across repeated builds of the same input set.
//  4. Estimate mining fee from vsize * feeRateSatPerVByte.
//  5. Construct a wire.MsgTx with one input per pool UTXO, one P2WPKH
//     output per payout, and one change output paying the balance back to
//     the pool address (skipped if change would be dust).
//  6. Compute the BIP143 P2WPKH sighash for each input and return them in
//     UnsignedBatch.Sighashes in input order.
func (b *BTCPayoutBuilder) BuildBatchPayout(from string, payouts []witness.Payout, _ bool) (witness.UnsignedBatch, error) {
	return b.buildBatchPayout(from, payouts, 0, [32]byte{})
}

// BuildWindowedBatchPayout is the DESIGN §17 first-writer-wins BTC entry point.
// Bitcoin has no smart contract to host the idempotency mapping, so the
// on-chain guarantee is "spending the same UTXOs cannot land twice" (already
// enforced by Bitcoin Core). This method additionally appends an OP_RETURN
// output carrying:
//
//	magic ("WWDW", 4 bytes) || windowID BE (8 bytes) || attestationLogRoot (32 bytes)
//
// Total 44 bytes, well under the 80-byte standard-relay limit. Off-chain
// auditors scan outputs for the magic prefix to recover (windowID, root)
// so the dispute path (if later extended with a BTC-side slashing oracle)
// can bind a proof to this specific window.
//
// When windowID or root is zero, BuildWindowedBatchPayout is a direct
// alias for BuildBatchPayout — no OP_RETURN is emitted.
func (b *BTCPayoutBuilder) BuildWindowedBatchPayout(
	from string,
	payouts []witness.Payout,
	_ bool,
	windowID uint64,
	attestationLogRoot [32]byte,
) (witness.UnsignedBatch, error) {
	return b.buildBatchPayout(from, payouts, windowID, attestationLogRoot)
}

// buildBatchPayout is the shared core called by both BuildBatchPayout and
// BuildWindowedBatchPayout. When windowID+root are non-zero it appends an
// OP_RETURN output embedding both values so downstream auditors can match
// this tx to its distribution window. The OP_RETURN adds ~43
// vbytes (1 op_return + 1 push-len + 44 data); the fee estimator accounts
// for it via an extra output in estimatePayoutVSize.
func (b *BTCPayoutBuilder) buildBatchPayout(from string, payouts []witness.Payout, windowID uint64, attestationLogRoot [32]byte) (witness.UnsignedBatch, error) {
	var empty witness.UnsignedBatch
	var zero [32]byte
	embedWindow := windowID != 0 && attestationLogRoot != zero
	if from == "" {
		return empty, errors.New("btc/payout: pool (from) address is empty")
	}
	if len(payouts) == 0 {
		return empty, errors.New("btc/payout: no payouts to build")
	}

	// Pool address must decode as a P2WPKH on our network.
	poolSW, err := DecodeSegWitAddress(from)
	if err != nil {
		return empty, fmt.Errorf("btc/payout: pool address %q: %w", from, err)
	}
	if poolSW.HRP != b.hrp {
		return empty, fmt.Errorf(
			"btc/payout: pool address HRP %q does not match network %q (expected %q)",
			poolSW.HRP, b.network, b.hrp,
		)
	}
	if poolSW.Version != 0 || len(poolSW.Program) != 20 {
		return empty, fmt.Errorf("btc/payout: pool address %q is not P2WPKH (v0, 20-byte program)", from)
	}
	poolScript, err := PkScriptForAddress(from)
	if err != nil {
		return empty, fmt.Errorf("btc/payout: pool scriptPubKey: %w", err)
	}

	// Normalise + validate payouts. Sort deterministically for reproducibility.
	sorted := make([]witness.Payout, len(payouts))
	copy(sorted, payouts)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].WitnessAddr < sorted[j].WitnessAddr
	})

	type plannedOut struct {
		addr   string
		script []byte
		value  int64
	}

	planned := make([]plannedOut, 0, len(sorted))
	totalOutSat := int64(0)
	for i, p := range sorted {
		if p.Amount == nil || p.Amount.Sign() <= 0 {
			return empty, fmt.Errorf("btc/payout: payout %d has non-positive amount", i)
		}
		if !p.Amount.IsInt64() {
			return empty, fmt.Errorf("btc/payout: payout %d amount overflows int64 satoshis", i)
		}
		sat := p.Amount.Int64()
		if sat < b.dustThreshold {
			return empty, fmt.Errorf(
				"btc/payout: payout %d amount %d sat below dust %d sat for recipient %s",
				i, sat, b.dustThreshold, p.WitnessAddr,
			)
		}
		sw, err := DecodeSegWitAddress(p.WitnessAddr)
		if err != nil {
			return empty, fmt.Errorf("btc/payout: payout %d address %q: %w", i, p.WitnessAddr, err)
		}
		if sw.HRP != b.hrp {
			return empty, fmt.Errorf(
				"btc/payout: payout %d address %q HRP %q does not match network %q (expected %q)",
				i, p.WitnessAddr, sw.HRP, b.network, b.hrp,
			)
		}
		if sw.Version != 0 || len(sw.Program) != 20 {
			return empty, fmt.Errorf(
				"btc/payout: payout %d address %q is not P2WPKH (v0, 20-byte program)",
				i, p.WitnessAddr,
			)
		}
		script, err := PkScriptForAddress(p.WitnessAddr)
		if err != nil {
			return empty, fmt.Errorf("btc/payout: payout %d scriptPubKey: %w", i, err)
		}
		planned = append(planned, plannedOut{addr: p.WitnessAddr, script: script, value: sat})
		totalOutSat += sat
	}

	// Fetch pool UTXOs. Caller is responsible for only returning confirmed,
	// spendable outputs; we trust the slice verbatim.
	utxos, err := b.utxoSource.PoolUTXOs(from)
	if err != nil {
		return empty, fmt.Errorf("btc/payout: fetch pool UTXOs: %w", err)
	}
	if len(utxos) == 0 {
		return empty, fmt.Errorf("btc/payout: pool %s has no spendable UTXOs", from)
	}

	totalInSat := int64(0)
	for i, u := range utxos {
		if u.AmountSat <= 0 {
			return empty, fmt.Errorf("btc/payout: pool UTXO %d has non-positive amount", i)
		}
		totalInSat += u.AmountSat
	}

	// Mining fee: first pass assumes the tx includes a change output (and, when
	// embedWindow is true, an OP_RETURN output carrying the window
	// metadata). Each OP_RETURN output adds one to the output count used by
	// the vsize estimator — the extra bytes are ~43 vbytes which is close
	// enough to the p2wpkhOutput heuristic (31 vbytes) for fee-rate purposes.
	numInputs := len(utxos)
	opReturnCount := 0
	if embedWindow {
		opReturnCount = 1
	}
	numOutputs := len(planned) + opReturnCount + 1 // +1 for change, adjusted below if dust
	estVSize := estimatePayoutVSize(numInputs, numOutputs)
	miningFee := int64(float64(estVSize) * b.feeRateSatPerVByte)
	if miningFee < 1 {
		miningFee = 1
	}

	// Invariant: total outputs + mining fee must fit within total inputs.
	if totalOutSat+miningFee > totalInSat {
		return empty, fmt.Errorf(
			"btc/payout: insufficient balance: outputs=%d sat + fee=%d sat > inputs=%d sat",
			totalOutSat, miningFee, totalInSat,
		)
	}

	change := totalInSat - totalOutSat - miningFee
	if change < 0 {
		// Already caught above but keep the defensive branch.
		return empty, fmt.Errorf("btc/payout: negative change %d sat", change)
	}

	// If change is below dust, re-estimate fee without the change output and
	// drop the leftover into the mining fee (it's tiny — below 546 sat). The
	// OP_RETURN output (if any) stays — it carries audit metadata, not funds,
	// and an attester left out of the window proves its claim against it.
	if change < b.dustThreshold {
		numOutputs = len(planned) + opReturnCount
		estVSize = estimatePayoutVSize(numInputs, numOutputs)
		miningFee = totalInSat - totalOutSat
		if miningFee < 1 {
			return empty, fmt.Errorf(
				"btc/payout: after dropping dust change, fee would be %d sat (insufficient for relay)",
				miningFee,
			)
		}
		change = 0
	}

	// Assemble tx.
	tx := NewMsgTx(2)
	for _, u := range utxos {
		txHash, err := TxIDFromDisplayHex(u.TxID)
		if err != nil {
			return empty, fmt.Errorf("btc/payout: utxo txid %q: %w", u.TxID, err)
		}
		scriptCode := p2wpkhScriptCode(u.PubKeyHash160)
		tx.AddTxIn(&TxIn{
			PreviousOutPoint: OutPoint{Hash: txHash, Index: u.Vout},
			Sequence:         0xFFFFFFFE,
			InputValue:       u.AmountSat,
			// For P2WPKH inputs the scriptCode (not a redeem script) is what
			// goes into the BIP143 preimage. We stash it in WitnessScript so
			// ComputeBIP143SighashP2WPKH (below) can retrieve it per-input.
			WitnessScript: scriptCode,
		})
	}
	for _, p := range planned {
		tx.AddTxOut(&TxOut{Value: p.value, PkScript: p.script})
	}
	if change > 0 {
		tx.AddTxOut(&TxOut{Value: change, PkScript: poolScript})
	}
	// OP_RETURN output carrying the window metadata goes last so existing
	// output-ordering invariants (recipients first, change next) are
	// preserved for older auditors that slice outputs by index.
	if embedWindow {
		tx.AddTxOut(&TxOut{Value: 0, PkScript: encodeWitnessWindowOpReturn(windowID, attestationLogRoot)})
	}

	// Compute per-input sighashes (SIGHASH_ALL).
	sighashes := make([][]byte, len(tx.TxIn))
	inputScripts := make([][]byte, len(tx.TxIn))
	inputValues := make([]int64, len(tx.TxIn))
	for i := range tx.TxIn {
		h, err := tx.ComputeBIP143SighashP2WPKH(i, SighashAll)
		if err != nil {
			return empty, fmt.Errorf("btc/payout: compute sighash input %d: %w", i, err)
		}
		sighashes[i] = append([]byte(nil), h[:]...)
		inputScripts[i] = append([]byte(nil), tx.TxIn[i].WitnessScript...)
		inputValues[i] = tx.TxIn[i].InputValue
	}

	raw, err := tx.Serialize()
	if err != nil {
		return empty, fmt.Errorf("btc/payout: serialize: %w", err)
	}

	return witness.UnsignedBatch{
		ChainID:      b.chainID,
		Currency:     "BTC",
		Kind:         witness.BatchKindBTCMultiOutput,
		Payload:      raw,
		Sighashes:    sighashes,
		InputScripts: inputScripts,
		InputValues:  inputValues,
	}, nil
}

// p2wpkhScriptCode returns the BIP143 scriptCode for a P2WPKH input, which
// is the encoded P2PKH script for the input's pubkey hash:
//
//	OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
//	= 0x19 0x76 0xa9 0x14 {20 bytes} 0x88 0xac
//
// Length byte (0x19 = 25) is included by writeVarBytes inside
// ComputeBIP143SighashP2WPKH — callers store only the 25-byte script.
func p2wpkhScriptCode(pubKeyHash160 [20]byte) []byte {
	out := make([]byte, 0, 25)
	out = append(out, 0x76) // OP_DUP
	out = append(out, 0xa9) // OP_HASH160
	out = append(out, 0x14) // push 20 bytes
	out = append(out, pubKeyHash160[:]...)
	out = append(out, 0x88) // OP_EQUALVERIFY
	out = append(out, 0xac) // OP_CHECKSIG
	return out
}

// estimatePayoutVSize estimates the virtual size of a payout tx assuming
// P2WPKH inputs and P2WPKH outputs. Values match Bitcoin Core's standard
// accounting:
//
//	tx overhead  = 10.5 vbytes (version + locktime + segwit discount)
//	P2WPKH input = 68 vbytes (outpoint + sequence + 27 witness bytes)
//	P2WPKH out   = 31 vbytes (value + scriptPubKey)
//
// We ceil to integer vbytes and round overhead to 11.
func estimatePayoutVSize(numInputs, numOutputs int) int {
	const (
		txOverhead   = 11
		p2wpkhInput  = 68
		p2wpkhOutput = 31
	)
	return txOverhead + numInputs*p2wpkhInput + numOutputs*p2wpkhOutput
}

// BigToInt64Sat is a small helper exposed for tests and callers that need to
// turn a *big.Int amount into int64 satoshis with clamping.
func BigToInt64Sat(v *big.Int) int64 { return bigToSat(v) }

// encodeWitnessWindowOpReturn produces the scriptPubKey for the OP_RETURN
// output that carries the first-writer-wins window metadata on BTC. Layout:
//
//	OP_RETURN   0x6a
//	OP_PUSHBYTES_44   0x2c
//	magic       "WWDW" (4 bytes)
//	windowID    uint64 big-endian (8 bytes)
//	root        32 bytes
//
// Total scriptPubKey = 2 + 44 = 46 bytes. Under the 80-byte standard relay
// limit so mempool policy (Bitcoin Core default) accepts the tx.
func encodeWitnessWindowOpReturn(windowID uint64, attestationLogRoot [32]byte) []byte {
	const (
		opReturn   = 0x6a
		payloadLen = 4 + 8 + 32 // magic + windowID + root = 44
		pushOpcode = byte(payloadLen)
	)
	out := make([]byte, 0, 2+payloadLen)
	out = append(out, opReturn, pushOpcode)
	out = append(out, WitnessWindowOpReturnMagic...)
	var idBuf [8]byte
	binary.BigEndian.PutUint64(idBuf[:], windowID)
	out = append(out, idBuf[:]...)
	out = append(out, attestationLogRoot[:]...)
	return out
}
