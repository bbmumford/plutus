/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package witness

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// fakeEVMClient is a deterministic EVMChainClient for tests.
type fakeEVMClient struct {
	nonce    uint64
	gasPrice *big.Int
	nonceErr error
	gasErr   error
	lastAddr string
}

func (f *fakeEVMClient) PendingNonceAt(_ context.Context, address string) (uint64, error) {
	f.lastAddr = address
	if f.nonceErr != nil {
		return 0, f.nonceErr
	}
	return f.nonce, nil
}

func (f *fakeEVMClient) SuggestGasPrice(_ context.Context) (*big.Int, error) {
	if f.gasErr != nil {
		return nil, f.gasErr
	}
	if f.gasPrice == nil {
		return nil, nil
	}
	return new(big.Int).Set(f.gasPrice), nil
}

// sampleEVMEnvelope returns a minimal envelope payload matching the
// adapter/evm EVMBatchEnvelope JSON layout.
func sampleEVMEnvelope(from string) []byte {
	return []byte(`{"to":"0xcA11bde05977b3631167028862bE2a173976CA11","value":"0x0","data":"0xdeadbeef","gasLimit":100000,"evmChainID":137,"from":"` + from + `"}`)
}

func TestEVMEnvelopeFinalizer_RoundTrip(t *testing.T) {
	poolAddr := "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
	client := &fakeEVMClient{
		nonce:    42,
		gasPrice: big.NewInt(25_000_000_000), // 25 gwei
	}
	f := &EVMEnvelopeFinalizer{
		Clients: map[string]EVMChainClient{"polygon": client},
	}

	batch := UnsignedBatch{
		ChainID:  "polygon",
		Currency: "POL",
		Kind:     BatchKindEVMMulticall3,
		Payload:  sampleEVMEnvelope(poolAddr),
	}

	out, err := f.Finalize(context.Background(), batch)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if out.ChainID != batch.ChainID || out.Kind != batch.Kind {
		t.Fatalf("envelope identity changed: %+v", out)
	}
	// Parse back via the internal helper to verify the fields landed.
	env, err := parseEVMEnvelope(out.Payload)
	if err != nil {
		t.Fatalf("parse output: %v", err)
	}
	if env.nonce != 42 || !env.nonceSet {
		t.Errorf("want nonce=42 (set), got nonce=%d set=%v", env.nonce, env.nonceSet)
	}
	if env.gasPrice == nil || env.gasPrice.Cmp(big.NewInt(25_000_000_000)) != 0 {
		t.Errorf("want gasPrice=25 gwei, got %v", env.gasPrice)
	}
	if client.lastAddr != poolAddr {
		t.Errorf("finalizer queried wrong address: got %q want %q", client.lastAddr, poolAddr)
	}
	// Unchanged metadata from the source envelope:
	if env.to != "0xcA11bde05977b3631167028862bE2a173976CA11" {
		t.Errorf("to field clobbered: %q", env.to)
	}
	if env.evmChainID != 137 {
		t.Errorf("evmChainID clobbered: %d", env.evmChainID)
	}
}

func TestEVMEnvelopeFinalizer_NoOpForNonEVM(t *testing.T) {
	f := &EVMEnvelopeFinalizer{
		Clients: map[string]EVMChainClient{"polygon": &fakeEVMClient{nonce: 1, gasPrice: big.NewInt(1)}},
	}
	// BTC batch should pass through untouched.
	payload := []byte("opaque-btc-bytes")
	batch := UnsignedBatch{
		ChainID:  "bitcoin",
		Currency: "BTC",
		Kind:     BatchKindBTCMultiOutput,
		Payload:  payload,
	}
	out, err := f.Finalize(context.Background(), batch)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if string(out.Payload) != string(payload) {
		t.Errorf("BTC payload mutated: got %q want %q", out.Payload, payload)
	}
}

func TestEVMEnvelopeFinalizer_UnknownChainID(t *testing.T) {
	f := &EVMEnvelopeFinalizer{
		Clients: map[string]EVMChainClient{"polygon": &fakeEVMClient{nonce: 1, gasPrice: big.NewInt(1)}},
	}
	batch := UnsignedBatch{
		ChainID: "arbitrum",
		Kind:    BatchKindEVMMulticall3,
		Payload: sampleEVMEnvelope("0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"),
	}
	if _, err := f.Finalize(context.Background(), batch); err == nil {
		t.Fatalf("expected error for unknown chainID")
	} else if !strings.Contains(err.Error(), "no EVM chain client") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEVMEnvelopeFinalizer_NilReceiver(t *testing.T) {
	var f *EVMEnvelopeFinalizer
	payload := []byte("anything")
	batch := UnsignedBatch{ChainID: "x", Kind: BatchKindBTCMultiOutput, Payload: payload}
	out, err := f.Finalize(context.Background(), batch)
	if err != nil {
		t.Fatalf("nil receiver returned error: %v", err)
	}
	if string(out.Payload) != string(payload) {
		t.Errorf("nil receiver mutated payload")
	}
}

func TestEVMEnvelopeFinalizer_ClientError(t *testing.T) {
	f := &EVMEnvelopeFinalizer{
		Clients: map[string]EVMChainClient{"polygon": &fakeEVMClient{nonceErr: errors.New("boom")}},
	}
	batch := UnsignedBatch{
		ChainID: "polygon",
		Kind:    BatchKindEVMMulticall3,
		Payload: sampleEVMEnvelope("0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"),
	}
	if _, err := f.Finalize(context.Background(), batch); err == nil {
		t.Fatalf("expected error from nonce failure")
	}
}

// sampleIndividualEnvelope produces one per-item envelope (no nonce/gasPrice
// set yet) for use in individual-mode finalizer tests.
func sampleIndividualEnvelope(from, to string, value int64) []byte {
	return []byte(`{"to":"` + to + `","value":"0x` + new(big.Int).SetInt64(value).Text(16) + `","data":"0x","gasLimit":61000,"evmChainID":137,"from":"` + from + `"}`)
}

func TestEVMEnvelopeFinalizer_IndividualSequentialNonces(t *testing.T) {
	poolAddr := "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
	startNonce := uint64(100)
	gasPrice := big.NewInt(30_000_000_000) // 30 gwei
	client := &fakeEVMClient{
		nonce:    startNonce,
		gasPrice: gasPrice,
	}
	f := &EVMEnvelopeFinalizer{
		Clients: map[string]EVMChainClient{"polygon": client},
	}

	items := [][]byte{
		sampleIndividualEnvelope(poolAddr, "0x1111111111111111111111111111111111111111", 100),
		sampleIndividualEnvelope(poolAddr, "0x2222222222222222222222222222222222222222", 200),
		sampleIndividualEnvelope(poolAddr, "0x3333333333333333333333333333333333333333", 300),
	}
	batch := UnsignedBatch{
		ChainID:      "polygon",
		Currency:     "POL",
		Kind:         BatchKindEVMIndividual,
		ItemPayloads: items,
	}

	out, err := f.Finalize(context.Background(), batch)
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}
	if out.Kind != BatchKindEVMIndividual {
		t.Fatalf("kind changed: %v", out.Kind)
	}
	if len(out.ItemPayloads) != len(items) {
		t.Fatalf("ItemPayloads=%d want %d", len(out.ItemPayloads), len(items))
	}
	for i, raw := range out.ItemPayloads {
		env, err := parseEVMEnvelope(raw)
		if err != nil {
			t.Fatalf("parse item %d: %v", i, err)
		}
		wantNonce := startNonce + uint64(i)
		if !env.nonceSet || env.nonce != wantNonce {
			t.Errorf("item %d: nonce=%d set=%v want nonce=%d set=true", i, env.nonce, env.nonceSet, wantNonce)
		}
		if env.gasPrice == nil || env.gasPrice.Cmp(gasPrice) != 0 {
			t.Errorf("item %d: gasPrice=%v want %v", i, env.gasPrice, gasPrice)
		}
	}
	if client.lastAddr != poolAddr {
		t.Errorf("finalizer queried wrong address: got %q want %q", client.lastAddr, poolAddr)
	}
}

func TestEVMEnvelopeFinalizer_IndividualEmptyItemsError(t *testing.T) {
	f := &EVMEnvelopeFinalizer{
		Clients: map[string]EVMChainClient{"polygon": &fakeEVMClient{nonce: 1, gasPrice: big.NewInt(1)}},
	}
	batch := UnsignedBatch{
		ChainID:      "polygon",
		Kind:         BatchKindEVMIndividual,
		ItemPayloads: nil,
	}
	if _, err := f.Finalize(context.Background(), batch); err == nil {
		t.Fatal("want error for empty ItemPayloads")
	}
}

func TestEVMEnvelopeFinalizer_IndividualNonceError(t *testing.T) {
	f := &EVMEnvelopeFinalizer{
		Clients: map[string]EVMChainClient{"polygon": &fakeEVMClient{nonceErr: errors.New("rpc down")}},
	}
	poolAddr := "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
	batch := UnsignedBatch{
		ChainID: "polygon",
		Kind:    BatchKindEVMIndividual,
		ItemPayloads: [][]byte{
			sampleIndividualEnvelope(poolAddr, "0x1111111111111111111111111111111111111111", 100),
		},
	}
	if _, err := f.Finalize(context.Background(), batch); err == nil {
		t.Fatal("want error when PendingNonceAt fails")
	} else if !strings.Contains(err.Error(), "PendingNonceAt") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestEVMEnvelopeFinalizer_IndividualSenderMismatch(t *testing.T) {
	f := &EVMEnvelopeFinalizer{
		Clients: map[string]EVMChainClient{"polygon": &fakeEVMClient{nonce: 5, gasPrice: big.NewInt(1)}},
	}
	a := "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
	b := "0xBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBbBb"
	batch := UnsignedBatch{
		ChainID: "polygon",
		Kind:    BatchKindEVMIndividual,
		ItemPayloads: [][]byte{
			sampleIndividualEnvelope(a, "0x1111111111111111111111111111111111111111", 100),
			sampleIndividualEnvelope(b, "0x2222222222222222222222222222222222222222", 200),
		},
	}
	if _, err := f.Finalize(context.Background(), batch); err == nil {
		t.Fatal("want error when items have different From addresses")
	}
}

func TestStubEVMChainClient_Defaults(t *testing.T) {
	stub := &StubEVMChainClient{ChainID: "polygon"}
	n, err := stub.PendingNonceAt(context.Background(), "0xabc")
	if err != nil {
		t.Fatalf("PendingNonceAt: %v", err)
	}
	if n != 0 {
		t.Errorf("expected nonce=0 default, got %d", n)
	}
	gp, err := stub.SuggestGasPrice(context.Background())
	if err != nil {
		t.Fatalf("SuggestGasPrice: %v", err)
	}
	// Default 20 gwei.
	want := new(big.Int).Mul(big.NewInt(20), big.NewInt(1_000_000_000))
	if gp.Cmp(want) != 0 {
		t.Errorf("want 20 gwei default, got %v", gp)
	}
}
