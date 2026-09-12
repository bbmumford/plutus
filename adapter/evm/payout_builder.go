/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package evm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/sha3"

	"github.com/bbmumford/plutus/witness"
)

// DefaultMulticall3Address is Multicall3's deterministic CREATE2 deployment
// address, identical on every major EVM chain (Ethereum/Polygon/Arbitrum/
// BSC/Optimism/Base/Avalanche, etc.). Source: https://multicall3.com/
const DefaultMulticall3Address = "0xcA11bde05977b3631167028862bE2a173976CA11"

// Multicall3 function selectors. These are the first 4 bytes of the
// keccak256 hash of the canonical function signature.
var (
	// aggregate3((address,bool,bytes)[])            => 0x82ad56cb
	selectorAggregate3 = mustKeccakSelector("aggregate3((address,bool,bytes)[])")
	// aggregate3Value((address,bool,uint256,bytes)[]) => 0x174dea71
	selectorAggregate3Value = mustKeccakSelector("aggregate3Value((address,bool,uint256,bytes)[])")
	// distributeWindow(bytes32,uint64,bytes32,address,address[],uint256[]) =>
	// the first-writer-wins entrypoint on the Protocol Registry Contract
	// (DESIGN §17). Computed at package init so drift from the contract
	// signature surfaces as a failing selector test.
	selectorDistributeWindow = mustKeccakSelector(
		"distributeWindow(bytes32,uint64,bytes32,address,address[],uint256[])")
)

// Gas heuristics used when no eth_estimateGas is performed. The real gas is
// computed by the Broadcaster at send time. These are intentionally
// conservative so the signed transaction lands even with a few extra
// recipients. See adapter/evm/payout_builder.go:BuildBatchPayout.
const (
	baseGasOverhead   uint64 = 21000 // tx-base gas
	perRecipientGas   uint64 = 40000 // safe upper bound for a Call3 native transfer
	erc20PerTransfer  uint64 = 65000 // safe upper bound for an ERC20 transfer
	multicallOverhead uint64 = 30000 // Multicall3 dispatch overhead
)

// EVMPayoutBuilder builds Multicall3-encoded batch payouts for a specific
// (chainID, currency) pair on an EVM-compatible chain. It implements
// witness.PayoutBuilder.
//
// One builder instance is bound to exactly one chain and one currency. The
// registry wires up one builder per supported pair.
//
// Native-currency payouts (ETH/MATIC/BNB/...): encoded as aggregate3Value,
// where each Call3Value carries target=recipient, allowFailure=false,
// value=payout amount, callData="". The aggregate tx's value = sum(payouts).
//
// ERC20 payouts: encoded as aggregate3, where each Call3 carries
// target=tokenAddress, allowFailure=false, callData=transfer(recipient,amount).
// The aggregate tx's value = 0.
type EVMPayoutBuilder struct {
	// ChainID matches the witness distributor's chainID (e.g. "polygon",
	// "ethereum"). Stored on every UnsignedBatch so the signer/broadcaster
	// route correctly.
	ChainID string
	// EVMChainID is the numeric chain ID used in EIP-155 signing.
	EVMChainID uint64
	// Currency is the symbol this builder handles (e.g. "POL", "ETH", "USDC").
	Currency string
	// Multicall3Address is the Multicall3 contract address. Defaults to
	// DefaultMulticall3Address, which is deployed at the same address on every
	// supported chain. Override only for non-canonical deployments.
	Multicall3Address string
	// PRCAddress is the on-chain Protocol Registry Contract address for this
	// chain. When populated AND the builder is invoked via the window-aware
	// path (BuildWindowedBatchPayout), the tx targets PRC.distributeWindow
	// directly — the DESIGN §17 first-writer-wins idempotency gate. Empty
	// means the window-aware path is unavailable and BuildWindowedBatchPayout
	// falls back to the Multicall3 path.
	PRCAddress string
	// TokenAddress is the ERC20 contract address. Empty for native-currency
	// builders; required for ERC20 builders. The PRC.distributeWindow path
	// can ONLY disburse ERC20 tokens (it calls safeTransfer on the supplied
	// token address); native-currency builders that want first-writer-wins
	// must deploy a wrapped native token (WETH/WMATIC/WBNB) and wire its
	// address here instead.
	TokenAddress string
	// IsERC20 selects the ABI path. When true, uses aggregate3 with
	// ERC20.transfer calldata; when false, uses aggregate3Value with empty
	// callData per recipient.
	IsERC20 bool
	// ChainIDHash is the keccak256-hash-encoded chain identifier the PRC uses
	// as the first key into `distributedWindows[chainID][windowID]`. When
	// zero, BuildWindowedBatchPayout falls back to keccak256(ChainID) so
	// every Go-side builder produces a stable value; production deployments
	// that want a non-string-derived chain ID (e.g. the uint256 eth-chainID
	// encoded as bytes32) set this explicitly at construction.
	ChainIDHash [32]byte
}

// EVMPayoutBuilderConfig configures a new EVMPayoutBuilder.
type EVMPayoutBuilderConfig struct {
	ChainID           string
	EVMChainID        uint64
	Currency          string
	Multicall3Address string // optional; defaults to DefaultMulticall3Address
	// PRCAddress is optional. When set and non-empty, BuildWindowedBatchPayout
	// encodes a call to PRC.distributeWindow on this address; otherwise it
	// falls back to the Multicall3 path. Production wiring pulls the value
	// from canonical.CanonicalPRCAddress or canonical.PRC[chainID].
	PRCAddress   string
	TokenAddress string // required when IsERC20 is true
	IsERC20      bool
	// ChainIDHash is the canonical bytes32 chain identifier the PRC's
	// `distributedWindows` mapping uses. Zero means derive via keccak256(ChainID).
	ChainIDHash [32]byte
}

// NewEVMPayoutBuilder validates the config and returns a builder.
func NewEVMPayoutBuilder(cfg EVMPayoutBuilderConfig) (*EVMPayoutBuilder, error) {
	if cfg.ChainID == "" {
		return nil, errors.New("evm/payout_builder: chainID is empty")
	}
	if cfg.EVMChainID == 0 {
		return nil, errors.New("evm/payout_builder: EVM chain ID is zero")
	}
	if cfg.Currency == "" {
		return nil, errors.New("evm/payout_builder: currency is empty")
	}
	multicall := cfg.Multicall3Address
	if multicall == "" {
		multicall = DefaultMulticall3Address
	}
	if !isHexAddress(multicall) {
		return nil, fmt.Errorf("evm/payout_builder: invalid Multicall3 address %q", multicall)
	}
	if cfg.IsERC20 {
		if cfg.TokenAddress == "" {
			return nil, errors.New("evm/payout_builder: ERC20 currency requires token address")
		}
		if !isHexAddress(cfg.TokenAddress) {
			return nil, fmt.Errorf("evm/payout_builder: invalid ERC20 token address %q", cfg.TokenAddress)
		}
	}
	if cfg.PRCAddress != "" && !isHexAddress(cfg.PRCAddress) {
		return nil, fmt.Errorf("evm/payout_builder: invalid PRC address %q", cfg.PRCAddress)
	}
	chainIDHash := cfg.ChainIDHash
	var zero [32]byte
	if chainIDHash == zero {
		chainIDHash = keccakBytes32([]byte(cfg.ChainID))
	}
	return &EVMPayoutBuilder{
		ChainID:           cfg.ChainID,
		EVMChainID:        cfg.EVMChainID,
		Currency:          cfg.Currency,
		Multicall3Address: multicall,
		PRCAddress:        cfg.PRCAddress,
		TokenAddress:      cfg.TokenAddress,
		IsERC20:           cfg.IsERC20,
		ChainIDHash:       chainIDHash,
	}, nil
}

// keccakBytes32 returns the keccak256 digest of data as a [32]byte. Used to
// derive the PRC's `distributedWindows` chainID key from a string chain name.
func keccakBytes32(data []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Compile-time check: EVMPayoutBuilder implements witness.PayoutBuilder.
var _ witness.PayoutBuilder = (*EVMPayoutBuilder)(nil)

// Compile-time check: EVMPayoutBuilder implements the window-aware extension
// so the distributor can drive PRC.distributeWindow directly.
var _ witness.WindowAwarePayoutBuilder = (*EVMPayoutBuilder)(nil)

// BuildBatchPayout assembles the payouts into either (a) a single Multicall3
// transaction when useMulticall3 is true, or (b) N individual transactions —
// one per payout item — when useMulticall3 is false. The `from` parameter is
// informational (the pool address that owns the funds); the actual sender is
// set by the signer from its wallet key.
//
// For useMulticall3 == true, the returned UnsignedBatch has:
//   - Kind    = BatchKindEVMMulticall3
//   - Payload = one marshaled aggregate EVMBatchEnvelope targeting Multicall3
//
// For useMulticall3 == false, the returned UnsignedBatch has:
//   - Kind         = BatchKindEVMIndividual
//   - Payload      = nil
//   - Items        = per-witness to/amount summaries (len == len(payouts))
//   - ItemPayloads = one marshaled EVMBatchEnvelope per payout, in item order.
//     For native-currency builders each envelope is a bare value-transfer
//     (to = recipient, value = amount, data = empty). For ERC20 builders each
//     envelope is an ERC20.transfer call (to = token contract, value = 0,
//     data = transfer(recipient, amount)).
//
// In individual mode, Nonce and GasPrice are intentionally left unset on each
// envelope — the EVMEnvelopeFinalizer stamps a sequentially-incrementing nonce
// and a shared suggested gas price across the whole batch before the signer
// consumes it.
func (b *EVMPayoutBuilder) BuildBatchPayout(from string, payouts []witness.Payout, useMulticall3 bool) (witness.UnsignedBatch, error) {
	if len(payouts) == 0 {
		return witness.UnsignedBatch{}, errors.New("evm/payout_builder: no payouts")
	}

	// Validate each payout address up front so we fail loudly instead of
	// encoding a malformed tx.
	for i, p := range payouts {
		if !isHexAddress(p.WitnessAddr) {
			return witness.UnsignedBatch{}, fmt.Errorf("evm/payout_builder: payout %d has invalid address %q", i, p.WitnessAddr)
		}
		if p.Amount == nil || p.Amount.Sign() <= 0 {
			return witness.UnsignedBatch{}, fmt.Errorf("evm/payout_builder: payout %d has non-positive amount", i)
		}
	}

	if !useMulticall3 {
		return b.buildIndividual(from, payouts)
	}

	var (
		payload  []byte
		txValue  = new(big.Int)
		gasLimit uint64
		err      error
	)

	if b.IsERC20 {
		payload, err = b.encodeAggregate3ERC20(payouts)
		if err != nil {
			return witness.UnsignedBatch{}, err
		}
		gasLimit = baseGasOverhead + multicallOverhead + uint64(len(payouts))*erc20PerTransfer
	} else {
		payload, err = b.encodeAggregate3Value(payouts)
		if err != nil {
			return witness.UnsignedBatch{}, err
		}
		for _, p := range payouts {
			txValue.Add(txValue, p.Amount)
		}
		gasLimit = baseGasOverhead + multicallOverhead + uint64(len(payouts))*perRecipientGas
	}

	// The witness package's UnsignedBatch does not carry To/Value/GasLimit
	// fields directly — those are part of the Payload for EVM builders. We
	// serialize an EVMBatchEnvelope as the Payload so the signer can decode
	// the full tx inputs deterministically.
	env := EVMBatchEnvelope{
		To:         b.Multicall3Address,
		Value:      new(big.Int).Set(txValue),
		Data:       payload,
		GasLimit:   gasLimit,
		EVMChainID: b.EVMChainID,
		From:       from,
	}
	envBytes, err := env.Marshal()
	if err != nil {
		return witness.UnsignedBatch{}, fmt.Errorf("evm/payout_builder: marshal envelope: %w", err)
	}

	return witness.UnsignedBatch{
		ChainID:  b.ChainID,
		Currency: b.Currency,
		Kind:     witness.BatchKindEVMMulticall3,
		Payload:  envBytes,
	}, nil
}

// BuildWindowedBatchPayout is the DESIGN §17 first-writer-wins entry point.
// When the builder has a PRCAddress configured AND the currency is ERC20
// (the PRC.distributeWindow selector transfers an ERC20 token via
// SafeERC20.safeTransfer, so native currencies cannot use this path — they
// must use wrapped natives or fall back to Multicall3), it encodes a call
// to PRC.distributeWindow that:
//
//   - Writes distributedWindows[chainID][windowID] = attestationLogRoot as
//     the on-chain idempotency marker (a racing witness's second call reverts).
//   - Disburses token to each (recipient, amount) tuple in a single tx.
//   - Emits WindowDistributed for audit consumers.
//
// The returned UnsignedBatch has Kind=BatchKindEVMMulticall3 (same signer
// path as the Multicall3 batch — it's still a single EVM tx with calldata,
// just targeting a different contract) so existing signer/finalizer
// plumbing does not need to branch. Callers that need to distinguish the
// two can inspect env.To against the PRC address.
//
// Fallback behaviour:
//
//   - PRCAddress == "" OR currency is native (!IsERC20): falls back to
//     BuildBatchPayout, which emits a Multicall3 aggregate3Value /
//     aggregate3 tx. Callers still see the distributor stamp windowID +
//     attestationLogRoot onto the UnsignedBatch envelope, but the tx does
//     NOT enforce first-writer-wins on-chain. This is the backward-compat
//     escape hatch for chains without a deployed PRC.
//   - windowID == 0 or zero root: same fallback — the distributor promises
//     to pass non-zero metadata, but defence-in-depth matches the
//     documented contract in WindowAwarePayoutBuilder.
func (b *EVMPayoutBuilder) BuildWindowedBatchPayout(
	from string,
	payouts []witness.Payout,
	useMulticall3 bool,
	windowID uint64,
	attestationLogRoot [32]byte,
) (witness.UnsignedBatch, error) {
	var zero [32]byte
	// Fall back to the legacy path when the preconditions for
	// PRC.distributeWindow are not met. Each branch documents why.
	switch {
	case b.PRCAddress == "":
		// No PRC for this (chainID, currency) pair — can't target distributeWindow.
		return b.BuildBatchPayout(from, payouts, useMulticall3)
	case !b.IsERC20:
		// distributeWindow transfers an ERC20 token; native-currency payouts
		// have no compatible on-chain primitive here. DESIGN §17 notes that
		// native distributions must use a wrapped-native token or settle via
		// Multicall3 with off-chain (rather than contract-enforced) idempotency.
		return b.BuildBatchPayout(from, payouts, useMulticall3)
	case windowID == 0 || attestationLogRoot == zero:
		// Metadata not populated — contract would revert on zero root anyway,
		// so don't even encode the call.
		return b.BuildBatchPayout(from, payouts, useMulticall3)
	}

	if len(payouts) == 0 {
		return witness.UnsignedBatch{}, errors.New("evm/payout_builder: no payouts")
	}
	for i, p := range payouts {
		if !isHexAddress(p.WitnessAddr) {
			return witness.UnsignedBatch{}, fmt.Errorf("evm/payout_builder: payout %d has invalid address %q", i, p.WitnessAddr)
		}
		if p.Amount == nil || p.Amount.Sign() <= 0 {
			return witness.UnsignedBatch{}, fmt.Errorf("evm/payout_builder: payout %d has non-positive amount", i)
		}
	}

	payload, err := b.encodeDistributeWindow(b.ChainIDHash, windowID, attestationLogRoot, b.TokenAddress, payouts)
	if err != nil {
		return witness.UnsignedBatch{}, err
	}

	// Gas heuristic: the PRC call does one SLOAD + one SSTORE for the
	// idempotency mapping (~20k), then one SafeERC20 transfer per recipient
	// (~65k each — USDT-style code path is the worst case). Base + dispatch
	// overhead ~35k.
	gasLimit := baseGasOverhead + multicallOverhead + uint64(len(payouts))*erc20PerTransfer + 5000

	env := EVMBatchEnvelope{
		To:         b.PRCAddress,
		Value:      new(big.Int), // PRC.distributeWindow is non-payable; value=0
		Data:       payload,
		GasLimit:   gasLimit,
		EVMChainID: b.EVMChainID,
		From:       from,
	}
	envBytes, err := env.Marshal()
	if err != nil {
		return witness.UnsignedBatch{}, fmt.Errorf("evm/payout_builder: marshal envelope: %w", err)
	}

	return witness.UnsignedBatch{
		ChainID:  b.ChainID,
		Currency: b.Currency,
		Kind:     witness.BatchKindEVMMulticall3,
		Payload:  envBytes,
	}, nil
}

// buildIndividual produces one EVMBatchEnvelope per payout — a true
// per-item, per-tx batch. For native currency each envelope is a bare value
// transfer; for ERC20 each envelope invokes transfer(recipient, amount) on the
// token contract. The caller's finalizer populates Nonce (sequentially) and
// GasPrice before the signer runs.
func (b *EVMPayoutBuilder) buildIndividual(from string, payouts []witness.Payout) (witness.UnsignedBatch, error) {
	items := make([]witness.UnsignedBatchItem, 0, len(payouts))
	itemPayloads := make([][]byte, 0, len(payouts))

	for i, p := range payouts {
		var (
			to       string
			value    *big.Int
			data     []byte
			gasLimit uint64
		)
		if b.IsERC20 {
			to = b.TokenAddress
			value = new(big.Int) // ERC20 transfer sends zero native value.
			data = encodeCall(selectorTransfer, padAddress(p.WitnessAddr), padUint256(p.Amount))
			gasLimit = baseGasOverhead + erc20PerTransfer
		} else {
			to = p.WitnessAddr
			value = new(big.Int).Set(p.Amount)
			data = nil
			gasLimit = baseGasOverhead + perRecipientGas
		}

		env := EVMBatchEnvelope{
			To:         to,
			Value:      value,
			Data:       data,
			GasLimit:   gasLimit,
			EVMChainID: b.EVMChainID,
			From:       from,
		}
		envBytes, err := env.Marshal()
		if err != nil {
			return witness.UnsignedBatch{}, fmt.Errorf("evm/payout_builder: marshal item %d envelope: %w", i, err)
		}
		itemPayloads = append(itemPayloads, envBytes)

		items = append(items, witness.UnsignedBatchItem{
			To:      p.WitnessAddr,
			Amount:  new(big.Int).Set(p.Amount),
			Payload: append([]byte(nil), data...),
		})
	}

	return witness.UnsignedBatch{
		ChainID:      b.ChainID,
		Currency:     b.Currency,
		Kind:         witness.BatchKindEVMIndividual,
		Payload:      nil,
		Items:        items,
		ItemPayloads: itemPayloads,
	}, nil
}

// --- ABI encoding ---

// encodeAggregate3Value encodes a call to
//
//	aggregate3Value((address target, bool allowFailure, uint256 value, bytes callData)[])
//
// where each tuple is a native-currency payout with empty callData.
//
// Per the Solidity ABI spec (https://docs.soliditylang.org/en/latest/abi-spec.html),
// the argument is a DYNAMIC array of DYNAMIC tuples (the tuple carries `bytes`,
// which makes the tuple itself dynamic). A dynamic array of dynamic elements
// uses a two-level head/tail layout:
//
//	selector                                    (4 bytes)
//	outer-offset = 0x20                         (32)   // offset to array start
//	array length = N                            (32)
//	-- array body begins here --
//	head[0]  = offset of tuple 0 in array body  (32)   // = N*32
//	...
//	head[N-1]= offset of tuple N-1 in array body(32)
//	tuple[0] encoding                           (tupleSize bytes)
//	...
//	tuple[N-1] encoding                         (tupleSize bytes)
//
// Each tuple is itself encoded as (address, bool, value, bytesOffset) followed
// by the bytes-tail. bytesOffset is RELATIVE TO THE START OF THAT TUPLE'S
// ENCODING, not to the array. For empty callData, tuple encoding is:
//
//	address  (32)
//	bool     (32)
//	value    (32)
//	bytesOff (32)  = 0x80 (= 4*32, right after the tuple head)
//	bytesLen (32)  = 0   (no padded data bytes follow because length is zero)
//
// Total tuple size for empty callData = 5 * 32 = 160 bytes.
//
// The PRIOR implementation produced a flat layout with no per-tuple head
// offsets and with callData offsets anchored to the wrong base; real Multicall3
// contracts would revert decoding it for N >= 2. See
// TestEncodeAggregate3Value_MatchesReferenceABI for the byte-level reference.
func (b *EVMPayoutBuilder) encodeAggregate3Value(payouts []witness.Payout) ([]byte, error) {
	const wordSize = uint64(32)
	// Per-tuple encoding (empty callData): 4 head words + 1 length word = 160.
	const tupleSizeEmpty = uint64(5) * wordSize

	numPayouts := uint64(len(payouts))
	// Array body = N head-offsets + N tuple encodings.
	arrayBodyLen := numPayouts*wordSize + numPayouts*tupleSizeEmpty

	out := make([]byte, 0, 4+int(wordSize)+int(wordSize)+int(arrayBodyLen))
	out = append(out, selectorAggregate3Value...)
	// Outer arg offset: offset from start of args region to start of array
	// encoding (length word). Always 0x20 — one word ahead.
	out = append(out, padUint256(big.NewInt(32))...)
	// Array length N.
	out = append(out, padUint256(big.NewInt(int64(numPayouts)))...)

	// Array-body heads: offset of tuple i relative to start of array body.
	// Array body = [N head words][tuple 0][tuple 1]... so
	//   head[i] = N*32 + i*tupleSizeEmpty
	for i := uint64(0); i < numPayouts; i++ {
		tupleOffset := numPayouts*wordSize + i*tupleSizeEmpty
		out = append(out, padUint256(new(big.Int).SetUint64(tupleOffset))...)
	}

	// Tuple bodies. bytesOffset is relative to the start of THIS tuple's
	// encoding, so it's the same constant (0x80 = 4 words) for every tuple.
	const bytesOffsetInTuple = uint64(4) * wordSize
	for _, p := range payouts {
		out = append(out, padAddress(p.WitnessAddr)...)
		out = append(out, padBool(false)...) // allowFailure = false
		out = append(out, padUint256(p.Amount)...)
		out = append(out, padUint256(new(big.Int).SetUint64(bytesOffsetInTuple))...)
		// bytes length = 0 (empty callData). No padded data follows.
		out = append(out, make([]byte, 32)...)
	}
	return out, nil
}

// encodeAggregate3ERC20 encodes a call to
//
//	aggregate3((address target, bool allowFailure, bytes callData)[])
//
// where each tuple's target is the ERC20 token contract and callData is a
// transfer(recipient, amount) invocation.
//
// Layout mirrors encodeAggregate3Value except the tuple is 3 fields (no value)
// and callData is 68 bytes (4+32+32), which pads to 96 and adds a 32-byte
// length word for a per-tuple callData-tail of 128 bytes. The full tuple
// encoding is therefore:
//
//	address  (32)
//	bool     (32)
//	bytesOff (32)  = 0x60 (= 3*32)
//	bytesLen (32)  = 68
//	paddedCD (96)  = selectorTransfer(4) + addr(32) + amount(32) + zero-pad(28)
//
// Total tuple size = 7 * 32 = 224 bytes. See
// TestEncodeAggregate3ERC20_MatchesReferenceABI for byte-level validation.
func (b *EVMPayoutBuilder) encodeAggregate3ERC20(payouts []witness.Payout) ([]byte, error) {
	const wordSize = uint64(32)
	const transferCallDataLen = 68
	const transferPaddedLen = uint64((transferCallDataLen + 31) / 32 * 32) // 96
	// 3 tuple-head words + 1 length word + padded data.
	const tupleSize = uint64(3)*wordSize + wordSize + transferPaddedLen // 224

	numPayouts := uint64(len(payouts))
	arrayBodyLen := numPayouts*wordSize + numPayouts*tupleSize

	out := make([]byte, 0, 4+int(wordSize)+int(wordSize)+int(arrayBodyLen))
	out = append(out, selectorAggregate3...)
	out = append(out, padUint256(big.NewInt(32))...)
	out = append(out, padUint256(big.NewInt(int64(numPayouts)))...)

	// Array-body heads.
	for i := uint64(0); i < numPayouts; i++ {
		tupleOffset := numPayouts*wordSize + i*tupleSize
		out = append(out, padUint256(new(big.Int).SetUint64(tupleOffset))...)
	}

	// Tuple bodies. bytesOffset is relative to the start of THIS tuple and is
	// always 0x60 (3 * 32) — the three head words precede the bytes tail.
	const bytesOffsetInTuple = uint64(3) * wordSize
	for _, p := range payouts {
		callData := encodeCall(selectorTransfer, padAddress(p.WitnessAddr), padUint256(p.Amount))
		out = append(out, padAddress(b.TokenAddress)...)
		out = append(out, padBool(false)...)
		out = append(out, padUint256(new(big.Int).SetUint64(bytesOffsetInTuple))...)
		// length word (68) + padded data (96).
		out = append(out, padUint256(big.NewInt(int64(len(callData))))...)
		padded := make([]byte, transferPaddedLen)
		copy(padded, callData)
		out = append(out, padded...)
	}
	return out, nil
}

// encodeDistributeWindow ABI-encodes a call to
//
//	distributeWindow(
//	    bytes32 chainID,
//	    uint64  windowID,
//	    bytes32 attestationLogRoot,
//	    address token,
//	    address[] recipients,
//	    uint256[] amounts
//	)
//
// per the Solidity ABI spec. The function has two dynamic tail arguments
// (recipients, amounts); the four static head words come first, followed by
// offsets to each dynamic argument's tail data.
//
// Layout (bytes from selector):
//
//	offset  bytes  meaning
//	------  -----  -------
//	  0      4     selector                              = 0x??????
//	  4      32    chainID                               (static)
//	 36      32    windowID (padded to 32)               (static; uint64 left-padded)
//	 68      32    attestationLogRoot                    (static)
//	100      32    token (address, left-padded to 32)    (static)
//	132      32    offset to recipients[] tail from args-region start
//	164      32    offset to amounts[] tail from args-region start
//	-- recipients tail --
//	  tail+0    32    N (length of recipients)
//	  tail+32   N*32  left-padded addresses
//	-- amounts tail --
//	  tail+0    32    N (length of amounts)
//	  tail+32   N*32  uint256 amounts
//
// Dynamic-argument offsets are measured from the start of the argument-data
// region (i.e. byte 4, immediately after the selector), matching the spec's
// "the offsets are counted from the beginning of the value of the enclosing
// type" rule applied to the outermost tuple.
//
// args-region size for the static head = 6 words = 192 bytes. So:
//
//	recipients-tail offset = 192
//	amounts-tail offset    = 192 + 32 + N*32    // after recipients' length + body
func (b *EVMPayoutBuilder) encodeDistributeWindow(
	chainIDHash [32]byte,
	windowID uint64,
	attestationLogRoot [32]byte,
	token string,
	payouts []witness.Payout,
) ([]byte, error) {
	const wordSize = 32
	const staticHeadWords = 6 // chainID, windowID, root, token, offR, offA
	n := uint64(len(payouts))

	out := make([]byte, 0, 4+staticHeadWords*wordSize+2*wordSize+2*n*wordSize+2*wordSize)
	out = append(out, selectorDistributeWindow...)

	// static head
	out = append(out, padBytes32(chainIDHash[:])...)
	out = append(out, padUint256(new(big.Int).SetUint64(windowID))...)
	out = append(out, padBytes32(attestationLogRoot[:])...)
	out = append(out, padAddress(token)...)

	// dynamic offsets (relative to start of args region, not selector).
	// recipients tail sits immediately after the static head.
	recipientsTailOffset := uint64(staticHeadWords) * wordSize
	// amounts tail sits after recipients' length word + body.
	amountsTailOffset := recipientsTailOffset + wordSize + n*wordSize
	out = append(out, padUint256(new(big.Int).SetUint64(recipientsTailOffset))...)
	out = append(out, padUint256(new(big.Int).SetUint64(amountsTailOffset))...)

	// recipients tail: length word + N left-padded addresses.
	out = append(out, padUint256(new(big.Int).SetUint64(n))...)
	for _, p := range payouts {
		out = append(out, padAddress(p.WitnessAddr)...)
	}

	// amounts tail: length word + N uint256s.
	out = append(out, padUint256(new(big.Int).SetUint64(n))...)
	for _, p := range payouts {
		out = append(out, padUint256(p.Amount)...)
	}

	return out, nil
}

// --- envelope ---

// EVMBatchEnvelope is the serialized form of the EVM transaction inputs that
// the signer needs to produce a valid signed tx. It lives inside
// UnsignedBatch.Payload so the witness package stays chain-agnostic.
//
// Nonce and GasPrice are optional at builder time — the builder may not know
// the account nonce or suggested gas price yet. A downstream signer/broadcaster
// must ensure both are populated (either by re-marshalling the envelope with
// live values, or by calling witness.WalletSigner with overrides) before the
// raw signed bytes can land on-chain.
type EVMBatchEnvelope struct {
	To         string   `json:"to"`
	Value      *big.Int `json:"-"`
	ValueHex   string   `json:"value"` // marshaled form of Value
	Data       []byte   `json:"-"`
	DataHex    string   `json:"data"`
	GasLimit   uint64   `json:"gasLimit"`
	EVMChainID uint64   `json:"evmChainID"`
	From       string   `json:"from,omitempty"`
	// Nonce is the sender account's EIP-155 nonce. Zero is ambiguous (could
	// mean "unknown" or "literally zero"); the signer layer treats zero as
	// unset unless NonceSet is true.
	Nonce uint64 `json:"nonce,omitempty"`
	// NonceSet indicates whether Nonce was explicitly populated by the caller
	// (distinguishing "nonce is 0" from "nonce unknown").
	NonceSet bool `json:"nonceSet,omitempty"`
	// GasPrice is the legacy EIP-155 gas price in wei. Nil means the signer
	// should supply its own value; callers that want to pin a price must set
	// this explicitly.
	GasPrice    *big.Int `json:"-"`
	GasPriceHex string   `json:"gasPrice,omitempty"`
}

// Marshal serializes the envelope to bytes. The format is a small
// hex+json envelope — compact, debuggable, and does not drag in RLP or any
// EVM library. Signers decode this, build the EVM tx struct, sign with the
// appropriate key, and return the raw signed bytes.
func (e EVMBatchEnvelope) Marshal() ([]byte, error) {
	// Manual marshal to keep the big.Int value exact and avoid JSON number
	// precision loss for amounts > 2^53.
	var b strings.Builder
	b.WriteString(`{"to":"`)
	b.WriteString(e.To)
	b.WriteString(`","value":"0x`)
	if e.Value != nil && e.Value.Sign() > 0 {
		b.WriteString(e.Value.Text(16))
	} else {
		b.WriteString("0")
	}
	b.WriteString(`","data":"0x`)
	b.WriteString(hex.EncodeToString(e.Data))
	b.WriteString(`","gasLimit":`)
	fmt.Fprintf(&b, "%d", e.GasLimit)
	b.WriteString(`,"evmChainID":`)
	fmt.Fprintf(&b, "%d", e.EVMChainID)
	if e.From != "" {
		b.WriteString(`,"from":"`)
		b.WriteString(e.From)
		b.WriteString(`"`)
	}
	if e.NonceSet {
		b.WriteString(`,"nonce":`)
		fmt.Fprintf(&b, "%d", e.Nonce)
		b.WriteString(`,"nonceSet":true`)
	}
	if e.GasPrice != nil && e.GasPrice.Sign() > 0 {
		b.WriteString(`,"gasPrice":"0x`)
		b.WriteString(e.GasPrice.Text(16))
		b.WriteString(`"`)
	}
	b.WriteString(`}`)
	return []byte(b.String()), nil
}

// envelopeWire is the JSON wire shape we (un)marshal through encoding/json.
// Value and GasPrice arrive as 0x-hex strings (arbitrary precision); every
// integer field goes through json.Number so we don't lose precision or
// silently float-parse a wei-scale amount.
type envelopeWire struct {
	To         string      `json:"to"`
	Value      string      `json:"value"`
	Data       string      `json:"data"`
	GasLimit   json.Number `json:"gasLimit"`
	EVMChainID json.Number `json:"evmChainID"`
	From       string      `json:"from,omitempty"`
	Nonce      json.Number `json:"nonce,omitempty"`
	NonceSet   bool        `json:"nonceSet,omitempty"`
	GasPrice   string      `json:"gasPrice,omitempty"`
}

// UnmarshalEVMBatchEnvelope parses an envelope produced by Marshal. It is used
// by signer tests and by signer implementations that need to reconstruct the
// tx inputs. The function is intentionally narrow: it does not validate
// against the chain config — the signer layer is expected to sanity-check.
//
// Implementation uses encoding/json + json.Number so the big.Int fields
// (Value, GasPrice) and the uint64 fields (GasLimit, EVMChainID, Nonce)
// survive the parse without precision loss. The previous implementation was
// a hand-rolled substring hunter that silently mis-parsed fields whose
// values happened to contain the target key as a substring.
func UnmarshalEVMBatchEnvelope(raw []byte) (EVMBatchEnvelope, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var w envelopeWire
	if err := dec.Decode(&w); err != nil {
		return EVMBatchEnvelope{}, fmt.Errorf("evm/payout_builder: decode envelope: %w", err)
	}
	env := EVMBatchEnvelope{
		To:       w.To,
		From:     w.From,
		NonceSet: w.NonceSet,
		ValueHex: w.Value,
	}
	if w.Value != "" {
		hexStr := strings.TrimPrefix(strings.TrimPrefix(w.Value, "0x"), "0X")
		n := new(big.Int)
		if hexStr != "" {
			if _, ok := n.SetString(hexStr, 16); !ok {
				return env, fmt.Errorf("evm/payout_builder: invalid value hex %q", w.Value)
			}
		}
		env.Value = n
	} else {
		env.Value = new(big.Int)
	}
	if w.Data != "" {
		hexStr := strings.TrimPrefix(strings.TrimPrefix(w.Data, "0x"), "0X")
		data, err := hex.DecodeString(hexStr)
		if err != nil {
			return env, fmt.Errorf("evm/payout_builder: invalid data hex: %w", err)
		}
		env.Data = data
		env.DataHex = w.Data
	}
	if w.GasLimit != "" {
		n, err := parseJSONNumberUint64(w.GasLimit)
		if err != nil {
			return env, fmt.Errorf("evm/payout_builder: invalid gasLimit %q: %w", w.GasLimit, err)
		}
		env.GasLimit = n
	}
	if w.EVMChainID != "" {
		n, err := parseJSONNumberUint64(w.EVMChainID)
		if err != nil {
			return env, fmt.Errorf("evm/payout_builder: invalid evmChainID %q: %w", w.EVMChainID, err)
		}
		env.EVMChainID = n
	}
	if w.Nonce != "" {
		n, err := parseJSONNumberUint64(w.Nonce)
		if err != nil {
			return env, fmt.Errorf("evm/payout_builder: invalid nonce %q: %w", w.Nonce, err)
		}
		env.Nonce = n
		// A populated "nonce" field means NonceSet=true even if the
		// marshaller didn't emit the redundant nonceSet:true line (older
		// writers may not have).
		env.NonceSet = true
	}
	if w.GasPrice != "" {
		hexStr := strings.TrimPrefix(strings.TrimPrefix(w.GasPrice, "0x"), "0X")
		n := new(big.Int)
		if hexStr != "" {
			if _, ok := n.SetString(hexStr, 16); !ok {
				return env, fmt.Errorf("evm/payout_builder: invalid gasPrice hex %q", w.GasPrice)
			}
		}
		env.GasPrice = n
		env.GasPriceHex = w.GasPrice
	}
	return env, nil
}

// parseJSONNumberUint64 parses a json.Number into a uint64, using the
// number's string form directly so we never round-trip through float64.
func parseJSONNumberUint64(n json.Number) (uint64, error) {
	i, err := n.Int64()
	if err != nil {
		return 0, err
	}
	if i < 0 {
		return 0, fmt.Errorf("negative value %d", i)
	}
	return uint64(i), nil
}

// --- helpers ---

// isHexAddress loosely validates a 20-byte 0x-prefixed hex address.
func isHexAddress(s string) bool {
	s = strings.TrimPrefix(s, "0x")
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// mustKeccakSelector computes the 4-byte Keccak-256 selector for a canonical
// Solidity function signature. Called once at package init for each constant.
func mustKeccakSelector(signature string) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(signature))
	sum := h.Sum(nil)
	out := make([]byte, 4)
	copy(out, sum[:4])
	return out
}
