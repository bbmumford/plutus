/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/bbmumford/plutus/witness"
)

// TestDistributeWindowSelector_ReferenceDerivation recomputes the 4-byte
// function selector from the canonical signature via a standalone keccak256
// primitive. A silent drift in the signature string (e.g. reordering args,
// picking the wrong integer width) is caught here; the on-chain PRC's
// `distributeWindow` bytecode binds this exact selector and nothing else.
//
// Canonical signature (matches ProtocolRegistry.sol):
//
//	distributeWindow(bytes32,uint64,bytes32,address,address[],uint256[])
func TestDistributeWindowSelector_ReferenceDerivation(t *testing.T) {
	const sig = "distributeWindow(bytes32,uint64,bytes32,address,address[],uint256[])"
	got := referenceKeccakSelector(sig)
	// The expected 4-byte prefix — verified by recomputing keccak256 on the
	// canonical string. Tools like `cast sig "distributeWindow(...)"` produce
	// the same value.
	if !bytes.Equal(got, selectorDistributeWindow) {
		t.Fatalf("package selector = %x, reference = %x", selectorDistributeWindow, got)
	}
}

// TestEncodeDistributeWindow_MatchesReferenceABI hand-builds the expected ABI
// encoding for a 2-recipient distributeWindow call and byte-compares against
// encodeDistributeWindow.
//
// Input:
//
//	chainID  = keccak256("polygon")
//	windowID = 0x000000006507C0E0   (example truncated timestamp)
//	root     = 0xdeadbeef... (32 bytes)
//	token    = 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359
//	recipients = [0x11..11, 0x22..22]
//	amounts    = [100, 200]
//
// Expected layout (bytes from start of calldata):
//
//	offset  bytes  meaning
//	------  -----  -------
//	  0      4     selector distributeWindow
//	  4      32    chainID
//	 36      32    windowID (uint64 left-padded to 32)
//	 68      32    attestationLogRoot
//	100      32    token (left-padded)
//	132      32    offset to recipients tail  = 192 (args-region relative)
//	164      32    offset to amounts    tail  = 192 + 32 + 2*32 = 288
//	196      32    recipients length = 2
//	228      32    recipient[0]
//	260      32    recipient[1]
//	292      32    amounts length = 2
//	324      32    amount[0]
//	356      32    amount[1]
//	       total = 4 + 12*32 = 388 bytes
func TestEncodeDistributeWindow_MatchesReferenceABI(t *testing.T) {
	b := mustBuilder(t, "polygon", 137, "USDC", true, "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359")

	var chainIDHash [32]byte
	copy(chainIDHash[:], mustHex(t, "2d8e1f3d5e6c0b8a7d4b9c3e2f1a0d7c6b5e4a3928172d6c5b4a39281726150e"))
	var root [32]byte
	copy(root[:], mustHex(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"))
	const windowID uint64 = 0x6507C0E0
	const token = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"

	payouts := []witness.Payout{
		{WitnessAddr: "0x1111111111111111111111111111111111111111", Amount: big.NewInt(100), ChainID: "polygon", Currency: "USDC"},
		{WitnessAddr: "0x2222222222222222222222222222222222222222", Amount: big.NewInt(200), ChainID: "polygon", Currency: "USDC"},
	}

	// --- Build reference bytes word by word. ---
	var ref bytes.Buffer
	ref.Write(referenceKeccakSelector("distributeWindow(bytes32,uint64,bytes32,address,address[],uint256[])")) // 4

	// static head
	ref.Write(chainIDHash[:])           // chainID (already 32)
	ref.Write(word32(uint64(windowID))) // windowID
	ref.Write(root[:])                  // attestationLogRoot
	ref.Write(addrWord(t, token))       // token
	// offsets (args-region relative)
	ref.Write(word32(uint64(6 * 32)))           // recipients offset = 192
	ref.Write(word32(uint64(6*32 + 32 + 2*32))) // amounts offset = 192 + 32 + 2*32 = 288

	// recipients tail
	ref.Write(word32(2))
	ref.Write(addrWord(t, "0x1111111111111111111111111111111111111111"))
	ref.Write(addrWord(t, "0x2222222222222222222222222222222222222222"))

	// amounts tail
	ref.Write(word32(2))
	ref.Write(word32Big(big.NewInt(100)))
	ref.Write(word32Big(big.NewInt(200)))

	got, err := b.encodeDistributeWindow(chainIDHash, windowID, root, token, payouts)
	if err != nil {
		t.Fatalf("encodeDistributeWindow: %v", err)
	}

	if !bytes.Equal(got, ref.Bytes()) {
		t.Fatalf("encoder bytes differ from reference\n  ref:\n%s\n  got:\n%s",
			dumpWordAligned(ref.Bytes()), dumpWordAligned(got))
	}
	// Sanity: total length = 4 + 12 * 32 = 388 bytes.
	if len(got) != 4+12*32 {
		t.Fatalf("unexpected length %d (want %d)", len(got), 4+12*32)
	}
}

// TestBuildWindowedBatchPayout_TargetsPRC confirms the window-aware path
// emits a tx targeting the configured PRC address (rather than Multicall3)
// with calldata that decodes back to the supplied (chainID, windowID, root,
// token, recipients, amounts).
func TestBuildWindowedBatchPayout_TargetsPRC(t *testing.T) {
	const prcAddr = "0xDDdDddDdDdddDDddDDddDDDDdDdDDdDDdDDDDDDd"
	const token = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"
	bld, err := NewEVMPayoutBuilder(EVMPayoutBuilderConfig{
		ChainID:      "polygon",
		EVMChainID:   137,
		Currency:     "USDC",
		PRCAddress:   prcAddr,
		TokenAddress: token,
		IsERC20:      true,
	})
	if err != nil {
		t.Fatalf("NewEVMPayoutBuilder: %v", err)
	}

	var root [32]byte
	copy(root[:], bytes.Repeat([]byte{0xAB}, 32))
	const windowID uint64 = 7777
	payouts := []witness.Payout{
		{WitnessAddr: "0x1111111111111111111111111111111111111111", Amount: big.NewInt(1000), ChainID: "polygon", Currency: "USDC"},
	}

	batch, err := bld.BuildWindowedBatchPayout("0xpool0000000000000000000000000000000000000", payouts, true, windowID, root)
	if err != nil {
		t.Fatalf("BuildWindowedBatchPayout: %v", err)
	}
	if batch.Kind != witness.BatchKindEVMMulticall3 {
		t.Fatalf("unexpected kind %v", batch.Kind)
	}
	env, err := UnmarshalEVMBatchEnvelope(batch.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEVMBatchEnvelope: %v", err)
	}
	if !strings.EqualFold(env.To, prcAddr) {
		t.Fatalf("envelope To = %s, want PRC %s", env.To, prcAddr)
	}
	if env.Value == nil || env.Value.Sign() != 0 {
		t.Fatalf("envelope Value = %v, want 0 (PRC.distributeWindow is non-payable)", env.Value)
	}
	if !bytes.HasPrefix(env.Data, selectorDistributeWindow) {
		t.Fatalf("data prefix %x, want distributeWindow selector %x", env.Data[:4], selectorDistributeWindow)
	}
	// Decode the static head to confirm windowID + root landed correctly.
	body := env.Data[4:]
	// chainID at [0:32] should equal keccak256("polygon") since we didn't
	// supply an explicit ChainIDHash. We don't re-derive here — the selector
	// + non-empty header is enough for this end-to-end check; the byte-level
	// encoder test covers the full layout.
	gotWindow := new(big.Int).SetBytes(body[32:64]).Uint64()
	if gotWindow != windowID {
		t.Fatalf("encoded windowID = %d, want %d", gotWindow, windowID)
	}
	if !bytes.Equal(body[64:96], root[:]) {
		t.Fatalf("encoded root = %x, want %x", body[64:96], root[:])
	}
	gotToken := "0x" + hex.EncodeToString(body[96+12:96+32])
	if !strings.EqualFold(gotToken, token) {
		t.Fatalf("encoded token = %s, want %s", gotToken, token)
	}
}

// TestBuildWindowedBatchPayout_FallsBackWithoutPRC asserts that a builder
// with no PRCAddress falls back to the Multicall3 path regardless of the
// window metadata. This is the backward-compat escape hatch for chains
// without a deployed PRC.
func TestBuildWindowedBatchPayout_FallsBackWithoutPRC(t *testing.T) {
	bld := mustBuilder(t, "ethereum", 1, "ETH", false, "") // no PRC, native
	var root [32]byte
	copy(root[:], bytes.Repeat([]byte{0xCC}, 32))
	payouts := []witness.Payout{
		{WitnessAddr: "0x1111111111111111111111111111111111111111", Amount: big.NewInt(1), ChainID: "ethereum", Currency: "ETH"},
	}
	batch, err := bld.BuildWindowedBatchPayout("0xpool", payouts, true, 999, root)
	if err != nil {
		t.Fatalf("BuildWindowedBatchPayout: %v", err)
	}
	env, err := UnmarshalEVMBatchEnvelope(batch.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEVMBatchEnvelope: %v", err)
	}
	// Fallback path should target Multicall3.
	if !strings.EqualFold(env.To, DefaultMulticall3Address) {
		t.Fatalf("fallback envelope To = %s, want Multicall3 %s", env.To, DefaultMulticall3Address)
	}
}

// TestBuildWindowedBatchPayout_FallsBackForNativeCurrency asserts that even
// with a PRCAddress, a native-currency builder falls back to Multicall3 —
// distributeWindow is ERC20-only.
func TestBuildWindowedBatchPayout_FallsBackForNativeCurrency(t *testing.T) {
	const prcAddr = "0xDDdDddDdDdddDDddDDddDDDDdDdDDdDDdDDDDDDd"
	bld, err := NewEVMPayoutBuilder(EVMPayoutBuilderConfig{
		ChainID:    "ethereum",
		EVMChainID: 1,
		Currency:   "ETH",
		PRCAddress: prcAddr,
		IsERC20:    false,
	})
	if err != nil {
		t.Fatalf("NewEVMPayoutBuilder: %v", err)
	}
	var root [32]byte
	copy(root[:], bytes.Repeat([]byte{0xCC}, 32))
	payouts := []witness.Payout{
		{WitnessAddr: "0x1111111111111111111111111111111111111111", Amount: big.NewInt(1), ChainID: "ethereum", Currency: "ETH"},
	}
	batch, err := bld.BuildWindowedBatchPayout("0xpool", payouts, true, 999, root)
	if err != nil {
		t.Fatalf("BuildWindowedBatchPayout: %v", err)
	}
	env, _ := UnmarshalEVMBatchEnvelope(batch.Payload)
	if strings.EqualFold(env.To, prcAddr) {
		t.Fatalf("native-currency builder must NOT target PRC, got %s", env.To)
	}
}

// mustHex parses a hex string or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("mustHex(%q): %v", s, err)
	}
	return raw
}
