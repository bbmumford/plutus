/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"errors"
	"math/big"
	"testing"
)

// capturingSigner records the last batch it received so tests can assert the
// finalizer mutated the envelope before delegation.
type capturingSigner struct {
	last UnsignedBatch
	err  error
}

func (c *capturingSigner) SignBatchPayout(_ context.Context, batch UnsignedBatch) (SignedBatch, error) {
	c.last = batch
	if c.err != nil {
		return SignedBatch{}, c.err
	}
	return SignedBatch{ChainID: batch.ChainID, Txs: [][]byte{{0x01}}}, nil
}

func TestFinalizingSigner_AppliesFinalizer(t *testing.T) {
	client := &fakeEVMClient{nonce: 7, gasPrice: big.NewInt(1_000_000_000)}
	fin := &EVMEnvelopeFinalizer{Clients: map[string]EVMChainClient{"polygon": client}}
	inner := &capturingSigner{}

	s := &FinalizingSigner{Inner: inner, Finalizer: fin}
	batch := UnsignedBatch{
		ChainID: "polygon",
		Kind:    BatchKindEVMMulticall3,
		Payload: sampleEVMEnvelope("0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"),
	}
	if _, err := s.SignBatchPayout(context.Background(), batch); err != nil {
		t.Fatalf("SignBatchPayout: %v", err)
	}
	env, err := parseEVMEnvelope(inner.last.Payload)
	if err != nil {
		t.Fatalf("parse received payload: %v", err)
	}
	if env.nonce != 7 || !env.nonceSet {
		t.Errorf("inner signer did not see finalized nonce: %+v", env)
	}
}

func TestFinalizingSigner_PassthroughWhenFinalizerNil(t *testing.T) {
	inner := &capturingSigner{}
	s := &FinalizingSigner{Inner: inner}
	payload := []byte("raw-bytes")
	batch := UnsignedBatch{ChainID: "bitcoin", Kind: BatchKindBTCMultiOutput, Payload: payload}
	if _, err := s.SignBatchPayout(context.Background(), batch); err != nil {
		t.Fatalf("SignBatchPayout: %v", err)
	}
	if string(inner.last.Payload) != string(payload) {
		t.Errorf("passthrough mutated payload: got %q want %q", inner.last.Payload, payload)
	}
}

func TestFinalizingSigner_PropagatesFinalizerError(t *testing.T) {
	fin := &EVMEnvelopeFinalizer{
		Clients: map[string]EVMChainClient{"polygon": &fakeEVMClient{nonceErr: errors.New("boom")}},
	}
	s := &FinalizingSigner{Inner: &capturingSigner{}, Finalizer: fin}
	batch := UnsignedBatch{
		ChainID: "polygon",
		Kind:    BatchKindEVMMulticall3,
		Payload: sampleEVMEnvelope("0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"),
	}
	if _, err := s.SignBatchPayout(context.Background(), batch); err == nil {
		t.Fatalf("expected finalizer error to propagate")
	}
}

func TestFinalizingSigner_NilInner(t *testing.T) {
	s := &FinalizingSigner{}
	if _, err := s.SignBatchPayout(context.Background(), UnsignedBatch{}); err == nil {
		t.Fatalf("expected error for nil inner signer")
	}
}
