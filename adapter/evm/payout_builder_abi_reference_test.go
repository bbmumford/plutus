/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package evm

// This file contains permanent byte-level cross-check tests that validate
// the Multicall3 encoders in payout_builder.go against an INDEPENDENT,
// hand-computed reference derived straight from the Solidity ABI spec
// (https://docs.soliditylang.org/en/latest/abi-spec.html).
//
// These tests are intentionally written so they share NO code with the
// encoders themselves (apart from the trivial `hex.DecodeString` / keccak
// primitive). They build the expected byte sequence literally, word by word,
// exactly as the spec dictates. A drift between the encoder and the spec
// will surface as a byte-level diff here — without these tests, a bug like
// the one corrected in 2026-04 (missing per-tuple head offsets and a wrong
// callData offset base) could silently re-appear.
//
// Do NOT simplify these tests by calling the encoder's helpers. That would
// defeat their purpose.

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/bbmumford/plutus/witness"
)

// referenceKeccakSelector computes the 4-byte selector from scratch, without
// touching the mustKeccakSelector helper in payout_builder.go. This keeps the
// selector test self-contained.
func referenceKeccakSelector(signature string) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(signature))
	sum := h.Sum(nil)
	out := make([]byte, 4)
	copy(out, sum[:4])
	return out
}

// word32 returns a 32-byte big-endian encoding of v. Standalone implementation
// — does not share code with padUint256.
func word32(v uint64) []byte {
	out := make([]byte, 32)
	big.NewInt(0).SetUint64(v).FillBytes(out)
	return out
}

// word32Big returns a 32-byte big-endian encoding of v.
func word32Big(v *big.Int) []byte {
	out := make([]byte, 32)
	v.FillBytes(out)
	return out
}

// addrWord returns a 32-byte big-endian left-padded encoding of a 20-byte hex
// address. Standalone — does not use padAddress.
func addrWord(t *testing.T, hexAddr string) []byte {
	t.Helper()
	if len(hexAddr) >= 2 && (hexAddr[:2] == "0x" || hexAddr[:2] == "0X") {
		hexAddr = hexAddr[2:]
	}
	if len(hexAddr) != 40 {
		t.Fatalf("addrWord: bad hex length %d", len(hexAddr))
	}
	raw, err := hex.DecodeString(hexAddr)
	if err != nil {
		t.Fatalf("addrWord: %v", err)
	}
	out := make([]byte, 32)
	copy(out[12:], raw)
	return out
}

// --- aggregate3Value reference ------------------------------------------

// TestAggregate3ValueSelector_ReferenceDerivation recomputes the selector from
// the canonical signature string via the raw keccak primitive, independent of
// mustKeccakSelector. Guards against a silent mangle of the signature string
// (e.g. missing a space, wrong tuple order).
func TestAggregate3ValueSelector_ReferenceDerivation(t *testing.T) {
	const sig = "aggregate3Value((address,bool,uint256,bytes)[])"
	got := referenceKeccakSelector(sig)
	// Known-good published value, independently verifiable via `cast sig`.
	wantHex := "174dea71"
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("reference selector = %x, want %s (sig %q)", got, wantHex, sig)
	}
	if !bytes.Equal(got, selectorAggregate3Value) {
		t.Fatalf("package selector = %x, reference = %x", selectorAggregate3Value, got)
	}
}

// TestAggregate3Selector_ReferenceDerivation is the same for aggregate3.
func TestAggregate3Selector_ReferenceDerivation(t *testing.T) {
	const sig = "aggregate3((address,bool,bytes)[])"
	got := referenceKeccakSelector(sig)
	wantHex := "82ad56cb"
	if hex.EncodeToString(got) != wantHex {
		t.Fatalf("reference selector = %x, want %s (sig %q)", got, wantHex, sig)
	}
	if !bytes.Equal(got, selectorAggregate3) {
		t.Fatalf("package selector = %x, reference = %x", selectorAggregate3, got)
	}
}

// TestEncodeAggregate3Value_MatchesReferenceABI hand-builds the expected ABI
// encoding for a 2-payout native call and byte-compares against the encoder.
//
// Input:
//
//	target1 = 0x1111...1111, value = 1 wei, no callData
//	target2 = 0x2222...2222, value = 2 wei, no callData
//
// Reference byte layout (per Solidity ABI spec, section "Use of Dynamic Types"):
//
//	offset  bytes  meaning
//	------  -----  -------
//	  0      4     selector aggregate3Value        = 0x174dea71
//	  4      32    outer arg 0 offset to array     = 0x20
//	 36      32    array length                    = 0x02
//	 68      32    head[0] — tuple 0 offset in     = 0x40  (= N*32, N=2)
//	               array body
//	100      32    head[1] — tuple 1 offset in     = 0xe0  (= 0x40 + 160)
//	               array body
//	       -- tuple 0 encoding (160 bytes) starts at body-offset 0x40 --
//	132      32    address target1                 = 0x11..11
//	164      32    bool allowFailure               = 0
//	196      32    uint256 value                   = 1
//	228      32    bytes offset within tuple       = 0x80  (= 4*32)
//	260      32    bytes length                    = 0
//	       -- tuple 1 encoding (160 bytes) starts at body-offset 0xe0 --
//	292      32    address target2                 = 0x22..22
//	324      32    bool allowFailure               = 0
//	356      32    uint256 value                   = 2
//	388      32    bytes offset within tuple       = 0x80
//	420      32    bytes length                    = 0
//	       total = 452 bytes
//
// Notes on head offsets:
//   - "array body" begins immediately after the array-length word (body-offset 0).
//   - head[i] is relative to array-body start.
//   - bytesOffset inside each tuple is relative to the TUPLE start, not the
//     array and not the calldata payload. Per the ABI spec, "the offsets are
//     counted from the beginning of the value of the enclosing dynamic type"
//     — here, the enclosing dynamic type is the tuple, not the outer call.
//
// The prior buggy encoder:
//   - Omitted the head[0]/head[1] words entirely.
//   - Embedded a `bytesOffset` that tried to anchor to "array body start"
//     with an ad-hoc formula (headLen + i*32).
//   - Consequence: real Multicall3 contracts would read garbage for N >= 2
//     and revert the batch on-chain.
func TestEncodeAggregate3Value_MatchesReferenceABI(t *testing.T) {
	b := mustBuilder(t, "ethereum", 1, "ETH", false, "")
	payouts := []witness.Payout{
		{WitnessAddr: "0x1111111111111111111111111111111111111111", Amount: big.NewInt(1), ChainID: "ethereum", Currency: "ETH"},
		{WitnessAddr: "0x2222222222222222222222222222222222222222", Amount: big.NewInt(2), ChainID: "ethereum", Currency: "ETH"},
	}

	// --- Build reference bytes word by word. ---
	var ref bytes.Buffer
	ref.Write(referenceKeccakSelector("aggregate3Value((address,bool,uint256,bytes)[])")) // 4
	ref.Write(word32(0x20))                                                               // outer offset
	ref.Write(word32(2))                                                                  // array length
	// array body: head[0] = N*32 = 64, head[1] = 64 + tupleSize(=160) = 224
	const tupleSize = 5 * 32
	ref.Write(word32(2 * 32))              // head[0] = 0x40
	ref.Write(word32(2*32 + tupleSize))    // head[1] = 0xe0
	// tuple 0
	ref.Write(addrWord(t, "0x1111111111111111111111111111111111111111"))
	ref.Write(word32(0))                   // allowFailure = false
	ref.Write(word32Big(big.NewInt(1)))    // value = 1
	ref.Write(word32(0x80))                // bytes offset within tuple (= 4*32)
	ref.Write(word32(0))                   // bytes length = 0
	// tuple 1
	ref.Write(addrWord(t, "0x2222222222222222222222222222222222222222"))
	ref.Write(word32(0))
	ref.Write(word32Big(big.NewInt(2)))
	ref.Write(word32(0x80))
	ref.Write(word32(0))

	// --- Encoder output. ---
	got, err := b.encodeAggregate3Value(payouts)
	if err != nil {
		t.Fatalf("encodeAggregate3Value: %v", err)
	}

	// --- Byte-level compare with diagnostic on mismatch. ---
	if !bytes.Equal(got, ref.Bytes()) {
		t.Fatalf("encoder bytes differ from reference\n  ref:\n%s\n  got:\n%s",
			dumpWordAligned(ref.Bytes()), dumpWordAligned(got))
	}
	// Sanity: total length equals the reference layout above (452 bytes).
	if len(got) != 452 {
		t.Fatalf("unexpected length %d (want 452)", len(got))
	}
}

// TestEncodeAggregate3ERC20_MatchesReferenceABI hand-builds the expected ABI
// encoding for a 2-payout ERC20 transfer batch and byte-compares against the
// encoder.
//
// Input:
//
//	token   = 0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359  (USDC on Polygon)
//	target1 = 0x1111...1111, amount = 100
//	target2 = 0x2222...2222, amount = 200
//
// Reference layout (per ABI spec):
//
//	offset  bytes  meaning
//	------  -----  -------
//	  0      4     selector aggregate3              = 0x82ad56cb
//	  4      32    outer arg 0 offset               = 0x20
//	 36      32    array length                     = 2
//	 68      32    head[0]                          = 0x40  (= 2*32)
//	100      32    head[1]                          = 0x100 (= 0x40 + 224)
//	       -- tuple 0 encoding (224 bytes) --
//	132      32    address target (= token)         = 0x3c49..3359
//	164      32    bool allowFailure                = 0
//	196      32    bytes offset within tuple        = 0x60  (= 3*32)
//	228      32    bytes length                     = 68
//	260      96    padded callData:
//	                 4   selectorTransfer (a9059cbb)
//	                 32  recipient (left-padded)
//	                 32  amount    (big-endian)
//	                 28  zero pad
//	       -- tuple 1 encoding (224 bytes) --
//	356+..  (same shape)
//	       total = 4 + 32 + 32 + 2*32 + 2*224 = 580 bytes
//
// bytesOffset is 0x60 because the tuple has 3 head words (address, bool,
// offset) before the bytes tail.
func TestEncodeAggregate3ERC20_MatchesReferenceABI(t *testing.T) {
	const token = "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"
	b := mustBuilder(t, "polygon", 137, "USDC", true, token)
	payouts := []witness.Payout{
		{WitnessAddr: "0x1111111111111111111111111111111111111111", Amount: big.NewInt(100), ChainID: "polygon", Currency: "USDC"},
		{WitnessAddr: "0x2222222222222222222222222222222222222222", Amount: big.NewInt(200), ChainID: "polygon", Currency: "USDC"},
	}

	// --- Build reference bytes word by word. ---
	var ref bytes.Buffer
	ref.Write(referenceKeccakSelector("aggregate3((address,bool,bytes)[])")) // 4
	ref.Write(word32(0x20))
	ref.Write(word32(2))
	const tupleSize = 3*32 + 32 + 96 // head(3) + bytes-length(1) + padded(96) = 224
	ref.Write(word32(2 * 32))            // head[0] = 0x40
	ref.Write(word32(2*32 + tupleSize))  // head[1] = 0x100

	// selectorTransfer = keccak256("transfer(address,uint256)")[:4] = a9059cbb
	transferSelector, err := hex.DecodeString("a9059cbb")
	if err != nil {
		t.Fatalf("hex decode transfer selector: %v", err)
	}

	buildTuple := func(recipient string, amount uint64) []byte {
		var t0 bytes.Buffer
		t0.Write(addrWord(t, token))
		t0.Write(word32(0)) // allowFailure
		t0.Write(word32(0x60))
		t0.Write(word32(68)) // bytes length = 68
		// padded callData: 4 + 32 + 32 = 68, padded to 96
		padded := make([]byte, 96)
		copy(padded[0:4], transferSelector)
		cp := addrWord(t, recipient)
		copy(padded[4:36], cp)
		amt := word32(amount)
		copy(padded[36:68], amt)
		// bytes 68..96 remain zero
		t0.Write(padded)
		return t0.Bytes()
	}

	ref.Write(buildTuple("0x1111111111111111111111111111111111111111", 100))
	ref.Write(buildTuple("0x2222222222222222222222222222222222222222", 200))

	// --- Encoder output. ---
	got, err := b.encodeAggregate3ERC20(payouts)
	if err != nil {
		t.Fatalf("encodeAggregate3ERC20: %v", err)
	}

	if !bytes.Equal(got, ref.Bytes()) {
		t.Fatalf("encoder bytes differ from reference\n  ref:\n%s\n  got:\n%s",
			dumpWordAligned(ref.Bytes()), dumpWordAligned(got))
	}
	// Layout: 4 + 32 + 32 + 2*32 + 2*224 = 580.
	if len(got) != 580 {
		t.Fatalf("unexpected length %d (want 580)", len(got))
	}
}

// TestEncodeAggregate3Value_SingleAndTriple sanity-checks the encoder at the
// boundary cases N=1 (no head pointer between length and tuple-body) and N=3
// (ensures head offsets scale linearly).
func TestEncodeAggregate3Value_SingleAndTriple(t *testing.T) {
	b := mustBuilder(t, "ethereum", 1, "ETH", false, "")
	for _, n := range []int{1, 3, 7} {
		n := n
		t.Run(fmt.Sprintf("N=%d", n), func(t *testing.T) {
			payouts := make([]witness.Payout, n)
			for i := 0; i < n; i++ {
				payouts[i] = witness.Payout{
					WitnessAddr: fmt.Sprintf("0x%040x", i+1),
					Amount:      big.NewInt(int64(i + 1)),
					ChainID:     "ethereum",
					Currency:    "ETH",
				}
			}
			got, err := b.encodeAggregate3Value(payouts)
			if err != nil {
				t.Fatalf("encode: %v", err)
			}
			// Reference: 4 + 32 + 32 + N*32 + N*160
			wantLen := 4 + 32 + 32 + n*32 + n*160
			if len(got) != wantLen {
				t.Fatalf("N=%d: length = %d, want %d", n, len(got), wantLen)
			}
			// Check head[0] = N*32, head[N-1] = N*32 + (N-1)*160.
			body := got[4:]
			if new(big.Int).SetBytes(body[64:96]).Int64() != int64(n*32) {
				t.Fatalf("N=%d: head[0] = %d, want %d", n, new(big.Int).SetBytes(body[64:96]).Int64(), n*32)
			}
			lastHead := new(big.Int).SetBytes(body[64+int64(n-1)*32 : 64+int64(n)*32]).Int64()
			wantLast := int64(n*32 + (n-1)*160)
			if lastHead != wantLast {
				t.Fatalf("N=%d: head[%d] = %d, want %d", n, n-1, lastHead, wantLast)
			}
		})
	}
}

// dumpWordAligned renders bytes as 32-byte rows (with the 4-byte selector
// row first). Used in diff messages to make byte-level drift obvious.
func dumpWordAligned(b []byte) string {
	var out bytes.Buffer
	i := 0
	if len(b) >= 4 {
		fmt.Fprintf(&out, "    selector: %x\n", b[:4])
		i = 4
	}
	row := 0
	for i+32 <= len(b) {
		fmt.Fprintf(&out, "    w%03d[%04d]: %x\n", row, i, b[i:i+32])
		i += 32
		row++
	}
	if i < len(b) {
		fmt.Fprintf(&out, "    tail[%04d]: %x\n", i, b[i:])
	}
	return out.String()
}
