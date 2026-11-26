/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package blob

// Byte-level reference tests for the StorageEscrowClient ABI encoders.
// Every selector is computed here from scratch (without touching
// mustKeccakSelector) so a drift between the code and the Solidity ABI
// spec would surface as a diff here. These tests are deliberately
// self-contained — do NOT shorten them by calling the encoder's helpers.

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/bbmumford/diststore/onchain"
	"github.com/bbmumford/plutus/evmsign"
)

// referenceKeccakSelector computes the 4-byte selector from scratch.
// Standalone — does NOT touch mustKeccakSelector.
func referenceKeccakSelector(signature string) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(signature))
	sum := h.Sum(nil)
	out := make([]byte, 4)
	copy(out, sum[:4])
	return out
}

// The following 4-byte hex constants are the reference selectors — they
// were computed INDEPENDENTLY by running
//
//	h := sha3.NewLegacyKeccak256(); h.Write([]byte(SIG)); h.Sum(nil)[:4]
//
// and cross-checked against Remix's auto-generated ABI (which uses the
// same primitive). Any divergence here means EITHER the canonical
// signature string has drifted from the contract OR the encoder is
// broken — both are load-bearing invariants.
const (
	expectedSelOpenChallenge   = "60efc6fe"
	expectedSelExpireChallenge = "ec0f2a67"
	expectedSelRespond         = "1982f1d3"
	expectedSelWithdrawBond    = "66eb9cec"
	expectedSelBondReplicator  = "9edb6fc1"
)

func TestSelectors_MatchReferenceKeccak(t *testing.T) {
	t.Parallel()
	cases := []struct {
		signature string
		want      string
	}{
		{"openChallenge(bytes32,bytes32)", expectedSelOpenChallenge},
		{"expireChallenge()", expectedSelExpireChallenge},
		{"respond(bytes32)", expectedSelRespond},
		{"withdrawBond()", expectedSelWithdrawBond},
		{"bondReplicator()", expectedSelBondReplicator},
	}
	for _, tc := range cases {
		ref := referenceKeccakSelector(tc.signature)
		refHex := hex.EncodeToString(ref)
		if refHex != tc.want {
			t.Errorf("reference selector for %s: got %s, want %s",
				tc.signature, refHex, tc.want)
		}
	}
}

func TestSelectors_MatchProductionImpl(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"openChallenge", selOpenChallenge, expectedSelOpenChallenge},
		{"expireChallenge", selExpireChallenge, expectedSelExpireChallenge},
		{"respond", selRespond, expectedSelRespond},
		{"withdrawBond", selWithdrawBond, expectedSelWithdrawBond},
		{"bondReplicator", selBondReplicator, expectedSelBondReplicator},
	}
	for _, tc := range cases {
		gotHex := hex.EncodeToString(tc.got)
		if gotHex != tc.want {
			t.Errorf("%s selector: impl=%s, reference=%s", tc.name, gotHex, tc.want)
		}
		if len(tc.got) != 4 {
			t.Errorf("%s selector: length %d, want 4", tc.name, len(tc.got))
		}
	}
}

func TestEncodeOpenChallenge_Shape(t *testing.T) {
	t.Parallel()
	// openChallenge(bytes32 nonce, bytes32 expectedHash)
	// Calldata = selector(4) + nonce(32) + expectedHash(32) = 68 bytes.
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(0xA0 + i)
	}
	var expected [32]byte
	for i := range expected {
		expected[i] = byte(0xB0 + i)
	}

	got := EncodeOpenChallenge(nonce, expected)
	if len(got) != 68 {
		t.Fatalf("calldata length: got %d, want 68", len(got))
	}

	// Reconstruct the reference bytes independently.
	want := make([]byte, 0, 68)
	want = append(want, referenceKeccakSelector("openChallenge(bytes32,bytes32)")...)
	want = append(want, nonce[:]...)
	want = append(want, expected[:]...)

	if !bytes.Equal(got, want) {
		t.Errorf("EncodeOpenChallenge byte mismatch:\n got: %s\nwant: %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestEncodeExpireChallenge_Shape(t *testing.T) {
	t.Parallel()
	got := EncodeExpireChallenge()
	if len(got) != 4 {
		t.Fatalf("calldata length: got %d, want 4", len(got))
	}
	want := referenceKeccakSelector("expireChallenge()")
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeExpireChallenge byte mismatch: got %s, want %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestEncodeRespond_Shape(t *testing.T) {
	t.Parallel()
	var response [32]byte
	for i := range response {
		response[i] = byte(0xC0 + i)
	}
	got := EncodeRespond(response)
	if len(got) != 36 {
		t.Fatalf("calldata length: got %d, want 36", len(got))
	}
	want := append(referenceKeccakSelector("respond(bytes32)"), response[:]...)
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeRespond byte mismatch:\n got: %s\nwant: %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestEncodeWithdrawBond_Shape(t *testing.T) {
	t.Parallel()
	got := EncodeWithdrawBond()
	if len(got) != 4 {
		t.Fatalf("calldata length: got %d, want 4", len(got))
	}
	want := referenceKeccakSelector("withdrawBond()")
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeWithdrawBond byte mismatch: got %s, want %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestEncodeBondReplicator_Shape(t *testing.T) {
	t.Parallel()
	got := EncodeBondReplicator()
	if len(got) != 4 {
		t.Fatalf("calldata length: got %d, want 4", len(got))
	}
	want := referenceKeccakSelector("bondReplicator()")
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeBondReplicator byte mismatch: got %s, want %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}
}

func TestCIDHashForString_MatchesContract(t *testing.T) {
	t.Parallel()
	// Contract sets cidHash = keccak256(cid-ASCII) at construction.
	// Our helper MUST produce the same bytes.
	cid := "bafyreigh2akiscaildcqabsyg3dfr6chu3fgpregiymsck7e7aqa4s52zy"
	got := CIDHashForString(cid)

	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(cid))
	var want [32]byte
	copy(want[:], h.Sum(nil))

	if got != want {
		t.Errorf("CIDHashForString mismatch:\n got: %x\nwant: %x", got[:], want[:])
	}
}

// ─── End-to-end mutating path tests ───────────────────────────────────

// fakeSigner records calls and returns a deterministic signed-blob.
type fakeSigner struct {
	mu     sync.Mutex
	called []evmsign.LegacyTx
	out    []byte
	err    error
}

func (f *fakeSigner) SignLegacyTx(_ context.Context, tx evmsign.LegacyTx) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = append(f.called, tx)
	if f.err != nil {
		return nil, f.err
	}
	if f.out != nil {
		return f.out, nil
	}
	return []byte{0x01, 0x02, 0x03}, nil
}

// fakeBroadcaster records (chainID, signedTx) and returns a canned hash.
type fakeBroadcaster struct {
	mu       sync.Mutex
	chainIDs []string
	txs      [][]byte
	hashOut  string
	err      error
}

func (f *fakeBroadcaster) BroadcastTx(_ context.Context, chainID string, signedTx []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.chainIDs = append(f.chainIDs, chainID)
	f.txs = append(f.txs, append([]byte(nil), signedTx...))
	if f.err != nil {
		return "", f.err
	}
	if f.hashOut != "" {
		return f.hashOut, nil
	}
	return "0xdeadbeef", nil
}

func newTestClient(t *testing.T, signer *fakeSigner, bc *fakeBroadcaster, reg EscrowRegistry) *StorageEscrowClient {
	t.Helper()
	c, err := NewStorageEscrowClient(StorageEscrowClientConfig{
		ChainID:     "polygon",
		EVMChainID:  137,
		Signer:      signer,
		Broadcaster: bc,
		NonceFn: func(context.Context) (uint64, error) {
			return 42, nil
		},
		GasPriceFn: func(context.Context) (*big.Int, error) {
			return big.NewInt(30_000_000_000), nil
		},
		Registry: reg,
	})
	if err != nil {
		t.Fatalf("NewStorageEscrowClient: %v", err)
	}
	return c
}

func TestOpenChallengeAt_EndToEnd(t *testing.T) {
	t.Parallel()
	sgn := &fakeSigner{out: []byte{0xAA, 0xBB}}
	bc := &fakeBroadcaster{hashOut: "0x1234"}
	c := newTestClient(t, sgn, bc, NoopRegistry{})

	var nonce, expected [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	for i := range expected {
		expected[i] = byte(0x80 + i)
	}
	hash, err := c.OpenChallengeAt(context.Background(),
		"0xcA11bde05977b3631167028862bE2a173976CA11", nonce, expected)
	if err != nil {
		t.Fatalf("OpenChallengeAt: %v", err)
	}
	if hash != "0x1234" {
		t.Errorf("hash: got %s, want 0x1234", hash)
	}
	if got := len(sgn.called); got != 1 {
		t.Fatalf("signer calls: got %d, want 1", got)
	}
	tx := sgn.called[0]
	if tx.Nonce != 42 {
		t.Errorf("nonce: %d", tx.Nonce)
	}
	if tx.EVMChainID != 137 {
		t.Errorf("chainID: %d", tx.EVMChainID)
	}
	// Calldata should be our encoder's output byte-for-byte.
	if !bytes.Equal(tx.Data, EncodeOpenChallenge(nonce, expected)) {
		t.Errorf("calldata mismatch:\n got: %s", hex.EncodeToString(tx.Data))
	}
	if !strings.EqualFold(tx.To, "0xcA11bde05977b3631167028862bE2a173976CA11") {
		t.Errorf("To: %s", tx.To)
	}
}

func TestOpenChallenge_MissingRegistryEntry(t *testing.T) {
	t.Parallel()
	sgn := &fakeSigner{}
	bc := &fakeBroadcaster{}
	c := newTestClient(t, sgn, bc, NoopRegistry{})
	var cid, nonce, expected [32]byte
	_, err := c.OpenChallenge(context.Background(), cid, nonce, expected)
	if !errors.Is(err, ErrNoEscrowForCID) {
		t.Fatalf("err: %v, want ErrNoEscrowForCID", err)
	}
	if len(sgn.called) != 0 {
		t.Errorf("signer should not have been called")
	}
}

func TestOpenChallenge_WithRegistry(t *testing.T) {
	t.Parallel()
	sgn := &fakeSigner{}
	bc := &fakeBroadcaster{hashOut: "0xfeed"}
	reg := NewMemoryRegistry()
	var cid [32]byte
	for i := range cid {
		cid[i] = byte(i)
	}
	reg.Set(cid, "0x000102030405060708090a0b0c0d0e0f10111213")
	c := newTestClient(t, sgn, bc, reg)

	var nonce, expected [32]byte
	_, err := c.OpenChallenge(context.Background(), cid, nonce, expected)
	if err != nil {
		t.Fatalf("OpenChallenge: %v", err)
	}
	if len(sgn.called) != 1 {
		t.Fatalf("signer calls: %d", len(sgn.called))
	}
	if sgn.called[0].To != "0x000102030405060708090a0b0c0d0e0f10111213" {
		t.Errorf("To: %s", sgn.called[0].To)
	}
}

func TestExpireChallengeAt_CalldataOnly(t *testing.T) {
	t.Parallel()
	sgn := &fakeSigner{}
	bc := &fakeBroadcaster{hashOut: "0x5678"}
	c := newTestClient(t, sgn, bc, NoopRegistry{})

	hash, err := c.ExpireChallengeAt(context.Background(),
		"0x0000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("ExpireChallengeAt: %v", err)
	}
	if hash != "0x5678" {
		t.Errorf("hash: %s", hash)
	}
	if len(sgn.called) != 1 {
		t.Fatalf("signer calls: %d", len(sgn.called))
	}
	if !bytes.Equal(sgn.called[0].Data, EncodeExpireChallenge()) {
		t.Errorf("calldata: %s", hex.EncodeToString(sgn.called[0].Data))
	}
}

func TestWithdrawBondFrom_Calldata(t *testing.T) {
	t.Parallel()
	sgn := &fakeSigner{}
	bc := &fakeBroadcaster{hashOut: "0xdef"}
	c := newTestClient(t, sgn, bc, NoopRegistry{})
	hash, err := c.WithdrawBondFrom(context.Background(),
		"0x0000000000000000000000000000000000000002")
	if err != nil {
		t.Fatalf("WithdrawBondFrom: %v", err)
	}
	if hash != "0xdef" {
		t.Errorf("hash: %s", hash)
	}
	if !bytes.Equal(sgn.called[0].Data, EncodeWithdrawBond()) {
		t.Errorf("calldata: %s", hex.EncodeToString(sgn.called[0].Data))
	}
}

func TestPostBond_UsesBondReplicatorSelector(t *testing.T) {
	t.Parallel()
	sgn := &fakeSigner{}
	bc := &fakeBroadcaster{hashOut: "0xbond"}
	c := newTestClient(t, sgn, bc, NoopRegistry{})
	hash, err := c.PostBond(context.Background(),
		"0x0000000000000000000000000000000000000003")
	if err != nil {
		t.Fatalf("PostBond: %v", err)
	}
	if hash != "0xbond" {
		t.Errorf("hash: %s", hash)
	}
	if !bytes.Equal(sgn.called[0].Data, EncodeBondReplicator()) {
		t.Errorf("calldata: %s", hex.EncodeToString(sgn.called[0].Data))
	}
}

func TestCreatePin_ReturnsExplicitTODOError(t *testing.T) {
	t.Parallel()
	sgn := &fakeSigner{}
	bc := &fakeBroadcaster{}
	c := newTestClient(t, sgn, bc, NoopRegistry{})
	_, err := c.CreatePin(context.Background(), onchain.CreatePinParams{})
	if err == nil {
		t.Fatalf("expected TODO error")
	}
	if !strings.Contains(err.Error(), "CreatePin") {
		t.Errorf("err should mention CreatePin: %v", err)
	}
}

func TestSendTx_MissingSignerReturnsErrNoSigner(t *testing.T) {
	t.Parallel()
	c, err := NewStorageEscrowClient(StorageEscrowClientConfig{
		ChainID:    "polygon",
		EVMChainID: 137,
	})
	if err != nil {
		t.Fatalf("NewStorageEscrowClient: %v", err)
	}
	_, err = c.ExpireChallengeAt(context.Background(),
		"0x0000000000000000000000000000000000000001")
	if !errors.Is(err, ErrNoSigner) {
		t.Errorf("err: %v, want ErrNoSigner", err)
	}
}

func TestSendTx_InvalidAddress(t *testing.T) {
	t.Parallel()
	sgn := &fakeSigner{}
	bc := &fakeBroadcaster{}
	c := newTestClient(t, sgn, bc, NoopRegistry{})
	_, err := c.ExpireChallengeAt(context.Background(), "not-an-address")
	if err == nil {
		t.Fatalf("expected invalid-address error")
	}
	if !strings.Contains(err.Error(), "invalid") {
		t.Errorf("err: %v", err)
	}
}

func TestSendTx_NonceFnError(t *testing.T) {
	t.Parallel()
	sgn := &fakeSigner{}
	bc := &fakeBroadcaster{}
	nonceErr := errors.New("rpc down")
	c, err := NewStorageEscrowClient(StorageEscrowClientConfig{
		ChainID:     "polygon",
		EVMChainID:  137,
		Signer:      sgn,
		Broadcaster: bc,
		NonceFn:     func(context.Context) (uint64, error) { return 0, nonceErr },
		GasPriceFn:  func(context.Context) (*big.Int, error) { return big.NewInt(1), nil },
	})
	if err != nil {
		t.Fatalf("NewStorageEscrowClient: %v", err)
	}
	_, err = c.ExpireChallengeAt(context.Background(),
		"0x0000000000000000000000000000000000000001")
	if err == nil || !strings.Contains(err.Error(), "nonce lookup") {
		t.Errorf("err: %v", err)
	}
}

func TestIsBenignChallengeExpireRevert(t *testing.T) {
	t.Parallel()
	cases := []struct {
		err  error
		want bool
	}{
		{nil, false},
		{errors.New("execution reverted: ChallengeWindowNotExpired()"), true},
		{errors.New("execution reverted: NoOpenChallenge()"), true},
		{errors.New("execution reverted: OnlyReplicator()"), false},
		{errors.New("nonce too low"), false},
	}
	for _, tc := range cases {
		got := IsBenignChallengeExpireRevert(tc.err)
		if got != tc.want {
			t.Errorf("IsBenignChallengeExpireRevert(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
