/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// EVMChainClient is the minimal subset of an Ethereum JSON-RPC client that the
// EVMEnvelopeFinalizer needs to populate Nonce + GasPrice on an
// adapter/evm-produced batch envelope before the signer consumes it.
//
// The interface is deliberately narrow so the finalizer can operate without
// pulling go-ethereum into the witness package (Portal Network + a proper
// live RPC client are a separate piece of wiring — see
// TODO(mesh_embed/evm-rpc-client) below).
type EVMChainClient interface {
	// PendingNonceAt returns the sender account's next pending transaction
	// nonce (inclusive of mempool state). address is a 0x-prefixed hex string.
	PendingNonceAt(ctx context.Context, address string) (uint64, error)
	// SuggestGasPrice returns the chain's currently suggested legacy
	// gas-price, in wei.
	SuggestGasPrice(ctx context.Context) (*big.Int, error)
}

// EVMEnvelopeFinalizer takes an UnsignedBatch produced by
// adapter/evm.EVMPayoutBuilder.BuildBatchPayout and, before handing it to a
// FeeDistributionSigner, replaces its JSON envelope with one whose Nonce and
// GasPrice fields are populated from live chain state.
//
// The finalizer is chain-keyed: each (chainID → EVMChainClient) entry tells
// the finalizer how to reach the RPC for that chain. An unknown chainID on an
// EVM-kind batch is a configuration error. Non-EVM batch kinds pass through
// untouched (no-op).
//
// The finalizer hooks BETWEEN PayoutBuilder.BuildBatchPayout and
// Signer.SignBatchPayout. The distributor itself is unaware of it — callers
// wrap the signer in a FinalizingSigner so the round pipeline picks it up.
type EVMEnvelopeFinalizer struct {
	// Clients maps chainID → EVMChainClient. Missing entries for EVM batches
	// produce a configuration error.
	Clients map[string]EVMChainClient
	// Logger is optional; when nil, no logs are emitted.
	Logger Logger
}

// Finalize re-marshals batch's payload (when it is an EVM envelope) to inject
// Nonce + GasPrice read from Clients[batch.ChainID]. No-op for non-EVM kinds.
//
// For BatchKindEVMMulticall3 the single aggregate envelope in Payload is
// stamped with one nonce + gas price.
//
// For BatchKindEVMIndividual the finalizer queries PendingNonceAt and
// SuggestGasPrice exactly once, then stamps ItemPayloads[i] with
// Nonce = startNonce + i and the shared gas price. This preserves the
// fee_distributor's invariant that each sub-tx on an individual-mode batch
// is independently submittable.
//
// Returns an error when the batch's ChainID has no configured EVMChainClient
// or when the configured client fails.
func (f *EVMEnvelopeFinalizer) Finalize(ctx context.Context, batch UnsignedBatch) (UnsignedBatch, error) {
	if f == nil {
		return batch, nil
	}
	// Only EVM kinds carry an EVMBatchEnvelope that needs Nonce/GasPrice.
	if batch.Kind != BatchKindEVMMulticall3 && batch.Kind != BatchKindEVMIndividual {
		return batch, nil
	}
	client, ok := f.Clients[batch.ChainID]
	if !ok {
		return UnsignedBatch{}, fmt.Errorf(
			"witness/evm_envelope_finalizer: no EVM chain client configured for chain %q",
			batch.ChainID,
		)
	}
	if client == nil {
		return UnsignedBatch{}, fmt.Errorf(
			"witness/evm_envelope_finalizer: nil EVM chain client for chain %q",
			batch.ChainID,
		)
	}

	if batch.Kind == BatchKindEVMIndividual {
		return f.finalizeIndividual(ctx, batch, client)
	}

	env, err := parseEVMEnvelope(batch.Payload)
	if err != nil {
		return UnsignedBatch{}, fmt.Errorf(
			"witness/evm_envelope_finalizer: parse envelope for %q: %w",
			batch.ChainID, err,
		)
	}
	if env.from == "" {
		return UnsignedBatch{}, fmt.Errorf(
			"witness/evm_envelope_finalizer: envelope for %q has empty From; cannot query nonce",
			batch.ChainID,
		)
	}

	nonce, err := client.PendingNonceAt(ctx, env.from)
	if err != nil {
		return UnsignedBatch{}, fmt.Errorf(
			"witness/evm_envelope_finalizer: PendingNonceAt on %q for %s: %w",
			batch.ChainID, env.from, err,
		)
	}
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return UnsignedBatch{}, fmt.Errorf(
			"witness/evm_envelope_finalizer: SuggestGasPrice on %q: %w",
			batch.ChainID, err,
		)
	}
	if gasPrice == nil {
		return UnsignedBatch{}, fmt.Errorf(
			"witness/evm_envelope_finalizer: nil gas price from client for %q",
			batch.ChainID,
		)
	}

	env.nonce = nonce
	env.nonceSet = true
	env.gasPrice = new(big.Int).Set(gasPrice)

	payload := marshalEVMEnvelope(env)

	out := batch
	out.Payload = payload
	return out, nil
}

// finalizeIndividual stamps per-item envelopes with sequential nonces and a
// shared gas price. The starting nonce comes from a single PendingNonceAt
// call against the From address of the first envelope (all items are assumed
// to share the same sender — the pool wallet).
func (f *EVMEnvelopeFinalizer) finalizeIndividual(
	ctx context.Context,
	batch UnsignedBatch,
	client EVMChainClient,
) (UnsignedBatch, error) {
	if len(batch.ItemPayloads) == 0 {
		return UnsignedBatch{}, fmt.Errorf(
			"witness/evm_envelope_finalizer: individual batch for %q has no ItemPayloads",
			batch.ChainID,
		)
	}

	// Parse every envelope up front so we fail the whole batch deterministically
	// if any one item is malformed.
	parsed := make([]evmEnvelope, len(batch.ItemPayloads))
	for i, raw := range batch.ItemPayloads {
		env, err := parseEVMEnvelope(raw)
		if err != nil {
			return UnsignedBatch{}, fmt.Errorf(
				"witness/evm_envelope_finalizer: parse item %d envelope for %q: %w",
				i, batch.ChainID, err,
			)
		}
		if env.from == "" {
			return UnsignedBatch{}, fmt.Errorf(
				"witness/evm_envelope_finalizer: item %d envelope for %q has empty From; cannot query nonce",
				i, batch.ChainID,
			)
		}
		parsed[i] = env
	}

	// Every item must share the same sender — per-item signing is always
	// from the single pool wallet key. Divergence is a builder bug.
	sender := parsed[0].from
	for i := 1; i < len(parsed); i++ {
		if parsed[i].from != sender {
			return UnsignedBatch{}, fmt.Errorf(
				"witness/evm_envelope_finalizer: item %d envelope From=%q differs from item 0 From=%q",
				i, parsed[i].from, sender,
			)
		}
	}

	startNonce, err := client.PendingNonceAt(ctx, sender)
	if err != nil {
		return UnsignedBatch{}, fmt.Errorf(
			"witness/evm_envelope_finalizer: PendingNonceAt on %q for %s: %w",
			batch.ChainID, sender, err,
		)
	}
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		return UnsignedBatch{}, fmt.Errorf(
			"witness/evm_envelope_finalizer: SuggestGasPrice on %q: %w",
			batch.ChainID, err,
		)
	}
	if gasPrice == nil {
		return UnsignedBatch{}, fmt.Errorf(
			"witness/evm_envelope_finalizer: nil gas price from client for %q",
			batch.ChainID,
		)
	}

	stamped := make([][]byte, len(parsed))
	for i := range parsed {
		parsed[i].nonce = startNonce + uint64(i)
		parsed[i].nonceSet = true
		parsed[i].gasPrice = new(big.Int).Set(gasPrice)
		stamped[i] = marshalEVMEnvelope(parsed[i])
	}

	out := batch
	out.ItemPayloads = stamped
	return out, nil
}

// StubEVMChainClient is a placeholder EVMChainClient that returns sensible
// defaults (nonce=0, gasPrice=20 gwei) without talking to any live RPC
// endpoint. It exists so callers can stand up a finalizer BEFORE the Portal
// Network client lands — using it in production will produce invalid
// transactions (nonce collisions, underpriced gas) so every Finalize call logs
// a TODO(mesh_embed/evm-rpc-client) breadcrumb.
//
// Real RPC integration is tracked separately:
//   - mesh_embed: wire the stub to a live Portal Network / go-ethereum client
//     when Portal Network Phase 1 ships.
//   - mercury-node: same.
type StubEVMChainClient struct {
	// ChainID identifies the chain this stub is attached to. Used only in log
	// output; the client otherwise behaves identically for every chain.
	ChainID string
	// Nonce is the fixed nonce returned from PendingNonceAt. Zero by default.
	Nonce uint64
	// GasPriceWei is the fixed suggested gas price. Nil defaults to 20 gwei.
	GasPriceWei *big.Int
	// Logger is optional; when nil, the package nopLogger is used.
	Logger Logger
}

// stubDefaultGasPrice is 20 gwei — a middle-of-the-road default for most
// mainnet L1/L2 traffic. Deliberately non-zero so a stubbed Finalize still
// produces a tx that won't be outright rejected by mempool policy.
var stubDefaultGasPrice = new(big.Int).Mul(big.NewInt(20), big.NewInt(1_000_000_000))

// PendingNonceAt satisfies EVMChainClient.
func (s *StubEVMChainClient) PendingNonceAt(_ context.Context, address string) (uint64, error) {
	s.warn("PendingNonceAt (stub)", address)
	return s.Nonce, nil
}

// SuggestGasPrice satisfies EVMChainClient.
func (s *StubEVMChainClient) SuggestGasPrice(_ context.Context) (*big.Int, error) {
	s.warn("SuggestGasPrice (stub)", "")
	if s.GasPriceWei != nil {
		return new(big.Int).Set(s.GasPriceWei), nil
	}
	return new(big.Int).Set(stubDefaultGasPrice), nil
}

func (s *StubEVMChainClient) warn(op, addr string) {
	log := s.Logger
	if log == nil {
		log = nopLogger{}
	}
	if addr != "" {
		log.Printf("TODO(mesh_embed/evm-rpc-client): stub %s on chain %q for %s", op, s.ChainID, addr)
		return
	}
	log.Printf("TODO(mesh_embed/evm-rpc-client): stub %s on chain %q", op, s.ChainID)
}

// marshalEVMEnvelope re-emits an evmEnvelope in the same compact JSON format
// adapter/evm.EVMBatchEnvelope.Marshal uses. Lives here (not in
// wallet_signer.go) because only the finalizer round-trips envelopes; the
// signer is read-only.
func marshalEVMEnvelope(e evmEnvelope) []byte {
	var b strings.Builder
	b.WriteString(`{"to":"`)
	b.WriteString(e.to)
	b.WriteString(`","value":"0x`)
	if e.value != nil && e.value.Sign() > 0 {
		b.WriteString(e.value.Text(16))
	} else {
		b.WriteString("0")
	}
	b.WriteString(`","data":"0x`)
	b.WriteString(hex.EncodeToString(e.data))
	b.WriteString(`","gasLimit":`)
	fmt.Fprintf(&b, "%d", e.gasLimit)
	b.WriteString(`,"evmChainID":`)
	fmt.Fprintf(&b, "%d", e.evmChainID)
	if e.from != "" {
		b.WriteString(`,"from":"`)
		b.WriteString(e.from)
		b.WriteString(`"`)
	}
	if e.nonceSet {
		b.WriteString(`,"nonce":`)
		fmt.Fprintf(&b, "%d", e.nonce)
		b.WriteString(`,"nonceSet":true`)
	}
	if e.gasPrice != nil && e.gasPrice.Sign() > 0 {
		b.WriteString(`,"gasPrice":"0x`)
		b.WriteString(e.gasPrice.Text(16))
		b.WriteString(`"`)
	}
	b.WriteString(`}`)
	return []byte(b.String())
}
