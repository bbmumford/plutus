/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/bbmumford/whisper"
)

// --- fakes -----------------------------------------------------------------

type fakeEarnings struct {
	records []EarningRecord
	err     error
}

func (f *fakeEarnings) CollectEarnings(_ context.Context, _, _ time.Time) ([]EarningRecord, error) {
	return f.records, f.err
}

type fakePool struct {
	bals map[string]*big.Int // key: chainID + ":" + currency
	err  error
}

func (f *fakePool) PoolBalance(_ context.Context, chainID, currency string) (*big.Int, error) {
	if f.err != nil {
		return nil, f.err
	}
	if v, ok := f.bals[chainID+":"+currency]; ok {
		return new(big.Int).Set(v), nil
	}
	return nil, nil
}

type fakeAdapters struct {
	byKey map[string]PayoutBuilder
	err   error
}

func (f *fakeAdapters) ResolvePayoutBuilder(chainID, currency string) (PayoutBuilder, error) {
	if f.err != nil {
		return nil, f.err
	}
	if b, ok := f.byKey[chainID+":"+currency]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("no builder for %s/%s", chainID, currency)
}

type fakeBuilder struct {
	calls int
	last  []Payout
	kind  BatchKind
}

func (b *fakeBuilder) BuildBatchPayout(from string, payouts []Payout, useMulticall3 bool) (UnsignedBatch, error) {
	b.calls++
	cp := append([]Payout(nil), payouts...)
	b.last = cp
	kind := b.kind
	if kind == BatchKindUnspecified {
		if useMulticall3 {
			kind = BatchKindEVMMulticall3
		} else {
			kind = BatchKindEVMIndividual
		}
	}
	out := UnsignedBatch{
		ChainID:  payouts[0].ChainID,
		Currency: payouts[0].Currency,
		Kind:     kind,
		Payload:  []byte(fmt.Sprintf("batch-%s-%d", from, len(payouts))),
	}
	if kind == BatchKindEVMIndividual {
		for _, p := range payouts {
			out.Items = append(out.Items, UnsignedBatchItem{
				To:     p.WitnessAddr,
				Amount: new(big.Int).Set(p.Amount),
			})
		}
	}
	return out, nil
}

type fakeSigner struct {
	err error
}

func (s *fakeSigner) SignBatchPayout(_ context.Context, batch UnsignedBatch) (SignedBatch, error) {
	if s.err != nil {
		return SignedBatch{}, s.err
	}
	if batch.Kind == BatchKindEVMIndividual {
		txs := make([][]byte, 0, len(batch.Items))
		for _, it := range batch.Items {
			txs = append(txs, []byte(fmt.Sprintf("signed-%s-%s", it.To, it.Amount.String())))
		}
		return SignedBatch{ChainID: batch.ChainID, Txs: txs}, nil
	}
	return SignedBatch{ChainID: batch.ChainID, Txs: [][]byte{append([]byte("signed:"), batch.Payload...)}}, nil
}

type fakeBroadcaster struct {
	mu       sync.Mutex
	sentTxs  [][]byte
	txHash   string
	err      error
	counter  int
}

func (b *fakeBroadcaster) BroadcastTx(_ context.Context, chainID string, signedTx []byte) (string, error) {
	if b.err != nil {
		return "", b.err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.sentTxs = append(b.sentTxs, append([]byte(nil), signedTx...))
	b.counter++
	if b.txHash != "" {
		return fmt.Sprintf("%s-%d", b.txHash, b.counter), nil
	}
	return fmt.Sprintf("0xhash%d", b.counter), nil
}

// newFakeRegistry spins up a WitnessRegistry backed by a real whisper engine
// and seeds it with n witnesses on the given chain. Returns the hex-encoded
// pubkeys so tests can refer to them.
//
// Each witness is registered with a real Ed25519 signature (so Register's
// Verify() gate is satisfied) and with a synthetic per-chain payout address
// of the form "0xPAYOUT-<witIdx>-<chainID>" for every chain in chainIDs, so
// fee_distributor code paths that call resolvePayoutAddress succeed.
func newFakeRegistry(t *testing.T, chainIDs []string, n int) (*WitnessRegistry, []string) {
	t.Helper()
	engine := whisper.NewEngine()
	reg := NewWitnessRegistry(engine, nil)
	keys := make([]string, 0, n)
	for i := 0; i < n; i++ {
		pub, priv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("generate key: %v", err)
		}
		payouts := make(map[string]string, len(chainIDs))
		for _, cid := range chainIDs {
			payouts[cid] = fmt.Sprintf("0xPAYOUT-%d-%s", i, cid)
		}
		wr := WitnessRegistration{
			PubKey:          pub,
			ChainIDs:        chainIDs,
			Capabilities:    []string{"balance"},
			Reputation:      0.5,
			RegisteredAt:    time.Now(),
			PayoutAddresses: payouts,
		}
		if err := wr.Sign(priv); err != nil {
			t.Fatalf("sign witness: %v", err)
		}
		if err := reg.Register(wr); err != nil {
			t.Fatalf("register witness: %v", err)
		}
		keys = append(keys, hex.EncodeToString(pub))
	}
	return reg, keys
}

func newTestDistributor(t *testing.T, reg *WitnessRegistry, src *fakeEarnings, cfgTweaks func(*FeeDistributorConfig)) (*WitnessFeeDistributor, *fakeBuilder, *fakeBroadcaster) {
	t.Helper()
	builder := &fakeBuilder{}
	bcast := &fakeBroadcaster{txHash: "0xtx"}
	cfg := FeeDistributorConfig{
		Registry: reg,
		Source:   src,
		Adapters: &fakeAdapters{byKey: map[string]PayoutBuilder{
			"ethereum:USDC": builder,
			"polygon:USDC":  builder,
			"bitcoin:BTC":   builder,
		}},
		Signer:      &fakeSigner{},
		Broadcaster: bcast,
		PoolAddresses: map[string]string{
			"ethereum": "0xpool",
			"polygon":  "0xpool",
			"bitcoin":  "bc1qpool",
		},
		Window:    24 * time.Hour,
		MinPayout: big.NewInt(0),
	}
	if cfgTweaks != nil {
		cfgTweaks(&cfg)
	}
	d, err := NewWitnessFeeDistributor(cfg)
	if err != nil {
		t.Fatalf("new distributor: %v", err)
	}
	return d, builder, bcast
}

// --- tests -----------------------------------------------------------------

func TestFeeDistributorHappyPath(t *testing.T) {
	reg, keys := newFakeRegistry(t, []string{"ethereum"}, 3)
	// Three orders; each order pays each of the three witnesses 100.
	var records []EarningRecord
	for order := 0; order < 3; order++ {
		for _, k := range keys {
			records = append(records, EarningRecord{
				OrderID:       fmt.Sprintf("order-%d", order),
				ChainID:       "ethereum",
				Currency:      "USDC",
				WitnessPubKey: k,
				Amount:        big.NewInt(100),
				AttestationID: []byte(fmt.Sprintf("att-%d-%s", order, k[:8])),
				SettledAt:     time.Now(),
			})
		}
	}
	d, builder, bcast := newTestDistributor(t, reg, &fakeEarnings{records: records}, func(c *FeeDistributorConfig) {
		c.UseMulticall3 = true
	})

	end := time.Now()
	start := end.Add(-time.Hour)
	result, err := d.Run(context.Background(), start, end)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if builder.calls != 1 {
		t.Fatalf("expected 1 builder call, got %d", builder.calls)
	}
	if len(bcast.sentTxs) != 1 {
		t.Fatalf("expected 1 broadcast (Multicall3), got %d", len(bcast.sentTxs))
	}
	if len(result.Receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(result.Receipts))
	}
	receipt := result.Receipts[0]
	if len(receipt.Payouts) != 3 {
		t.Fatalf("expected 3 payouts, got %d", len(receipt.Payouts))
	}
	for _, p := range receipt.Payouts {
		if p.Amount.Cmp(big.NewInt(300)) != 0 {
			t.Errorf("expected each witness to receive 300, got %s for %s", p.Amount, hex.EncodeToString(p.WitnessPubKey)[:16])
		}
	}
	if len(result.Skipped) != 0 {
		t.Errorf("expected no skipped payouts, got %d", len(result.Skipped))
	}
}

func TestFeeDistributorDustThreshold(t *testing.T) {
	reg, keys := newFakeRegistry(t, []string{"ethereum"}, 2)
	records := []EarningRecord{
		{OrderID: "o1", ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[0], Amount: big.NewInt(5)},
		{OrderID: "o1", ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[1], Amount: big.NewInt(5000)},
	}
	d, _, bcast := newTestDistributor(t, reg, &fakeEarnings{records: records}, func(c *FeeDistributorConfig) {
		c.MinPayout = big.NewInt(1000)
	})

	result, err := d.Run(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Skipped) != 1 {
		t.Fatalf("expected 1 skipped payout (dust), got %d", len(result.Skipped))
	}
	if result.Skipped[0].Reason != "below min payout" {
		t.Errorf("unexpected skip reason: %s", result.Skipped[0].Reason)
	}
	if len(bcast.sentTxs) != 1 {
		t.Fatalf("expected 1 broadcast for the non-dust witness, got %d", len(bcast.sentTxs))
	}
	// Residual should track the dust amount so the next round can see it.
	key := "ethereum:USDC"
	if residual, ok := result.ResidualByGroup[key]; !ok || residual.Cmp(big.NewInt(5)) != 0 {
		t.Errorf("expected residual 5 for %s, got %v", key, residual)
	}
}

func TestFeeDistributorMultipleChains(t *testing.T) {
	reg, keys := newFakeRegistry(t, []string{"ethereum", "polygon", "bitcoin"}, 2)
	records := []EarningRecord{
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[0], Amount: big.NewInt(1000)},
		{ChainID: "polygon", Currency: "USDC", WitnessPubKey: keys[0], Amount: big.NewInt(1000)},
		{ChainID: "bitcoin", Currency: "BTC", WitnessPubKey: keys[1], Amount: big.NewInt(10000)},
	}
	d, builder, bcast := newTestDistributor(t, reg, &fakeEarnings{records: records}, nil)

	result, err := d.Run(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if builder.calls != 3 {
		t.Fatalf("expected 3 builder calls (one per group), got %d", builder.calls)
	}
	if len(bcast.sentTxs) != 3 {
		t.Fatalf("expected 3 broadcasts, got %d", len(bcast.sentTxs))
	}
	if len(result.Receipts) != 3 {
		t.Fatalf("expected 3 receipts, got %d", len(result.Receipts))
	}
	// Check receipts cover the expected chains.
	seen := map[string]bool{}
	for _, r := range result.Receipts {
		seen[r.ChainID+":"+r.Currency] = true
	}
	for _, want := range []string{"ethereum:USDC", "polygon:USDC", "bitcoin:BTC"} {
		if !seen[want] {
			t.Errorf("missing receipt for %s", want)
		}
	}
}

func TestFeeDistributorMissingPayoutAddress(t *testing.T) {
	reg, keys := newFakeRegistry(t, []string{"ethereum"}, 1)
	// An EarningRecord for an unknown witness pubkey (hex of random bytes).
	unknownPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	unknownHex := hex.EncodeToString(unknownPub)
	records := []EarningRecord{
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[0], Amount: big.NewInt(500)},
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: unknownHex, Amount: big.NewInt(250)},
	}
	d, _, bcast := newTestDistributor(t, reg, &fakeEarnings{records: records}, nil)

	result, err := d.Run(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Skipped) != 1 {
		t.Fatalf("expected 1 skipped payout (missing address), got %d", len(result.Skipped))
	}
	if result.Skipped[0].WitnessPubKey != unknownHex {
		t.Errorf("unexpected skipped witness: %s", result.Skipped[0].WitnessPubKey)
	}
	// The unknown witness's 250 must stay in the residual; it must NOT be
	// silently absorbed by another witness.
	key := "ethereum:USDC"
	if residual, ok := result.ResidualByGroup[key]; !ok || residual.Cmp(big.NewInt(250)) != 0 {
		t.Errorf("expected residual 250, got %v", residual)
	}
	// One payout for the registered witness still went out.
	if len(bcast.sentTxs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(bcast.sentTxs))
	}
}

func TestFeeDistributorIdempotency(t *testing.T) {
	reg, keys := newFakeRegistry(t, []string{"ethereum"}, 1)
	records := []EarningRecord{
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[0], Amount: big.NewInt(1000)},
	}
	d, _, bcast := newTestDistributor(t, reg, &fakeEarnings{records: records}, nil)

	start := time.Unix(1_700_000_000, 0)
	end := start.Add(time.Hour)

	first, err := d.Run(context.Background(), start, end)
	if err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if len(first.Receipts) != 1 {
		t.Fatalf("first run: expected 1 receipt, got %d", len(first.Receipts))
	}
	// Second call with the same window must not double-pay.
	second, err := d.Run(context.Background(), start, end)
	if !errors.Is(err, ErrRoundAlreadyProcessed) {
		t.Fatalf("expected ErrRoundAlreadyProcessed, got %v", err)
	}
	if second == nil || second.RoundID != first.RoundID {
		t.Fatalf("idempotent call must return the original round result, got %+v", second)
	}
	if len(bcast.sentTxs) != 1 {
		t.Fatalf("expected exactly 1 broadcast after idempotent retry, got %d", len(bcast.sentTxs))
	}
}

func TestFeeDistributorEmptyWindow(t *testing.T) {
	reg, _ := newFakeRegistry(t, []string{"ethereum"}, 1)
	d, builder, bcast := newTestDistributor(t, reg, &fakeEarnings{records: nil}, nil)

	result, err := d.Run(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Run on empty window: %v", err)
	}
	if len(result.Receipts) != 0 {
		t.Errorf("expected no receipts, got %d", len(result.Receipts))
	}
	if builder.calls != 0 {
		t.Errorf("expected no builder calls, got %d", builder.calls)
	}
	if len(bcast.sentTxs) != 0 {
		t.Errorf("expected no broadcasts, got %d", len(bcast.sentTxs))
	}
}

func TestFeeDistributorSingleWitness(t *testing.T) {
	reg, keys := newFakeRegistry(t, []string{"ethereum"}, 1)
	records := []EarningRecord{
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[0], Amount: big.NewInt(500)},
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[0], Amount: big.NewInt(500)},
	}
	d, _, bcast := newTestDistributor(t, reg, &fakeEarnings{records: records}, nil)

	result, err := d.Run(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Receipts) != 1 {
		t.Fatalf("expected 1 receipt, got %d", len(result.Receipts))
	}
	receipt := result.Receipts[0]
	if len(receipt.Payouts) != 1 {
		t.Fatalf("expected 1 aggregated payout, got %d", len(receipt.Payouts))
	}
	if receipt.Payouts[0].Amount.Cmp(big.NewInt(1000)) != 0 {
		t.Errorf("expected aggregated amount 1000, got %s", receipt.Payouts[0].Amount)
	}
	if len(bcast.sentTxs) != 1 {
		t.Errorf("expected 1 broadcast, got %d", len(bcast.sentTxs))
	}
}

func TestFeeDistributorPoolBalanceCap(t *testing.T) {
	reg, keys := newFakeRegistry(t, []string{"ethereum"}, 3)
	records := []EarningRecord{
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[0], Amount: big.NewInt(1000)},
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[1], Amount: big.NewInt(1000)},
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[2], Amount: big.NewInt(1000)},
	}
	// Pool only has 1500 on-chain. Pro-rata cap scales every payout by
	// poolBal/sumRequested = 1500/3000 = 0.5; every witness still gets paid,
	// each receives 500, and the 1500 of unpaid requested amount carries
	// over to the next round's residual so witnesses later-sorted don't
	// starve (which was the old lex-drop failure mode).
	d, _, bcast := newTestDistributor(t, reg, &fakeEarnings{records: records}, func(c *FeeDistributorConfig) {
		c.PoolProvider = &fakePool{bals: map[string]*big.Int{"ethereum:USDC": big.NewInt(1500)}}
		c.UseMulticall3 = true
	})

	result, err := d.Run(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Default builder produces a Multicall3 batch → exactly 1 broadcast.
	if len(bcast.sentTxs) != 1 {
		t.Fatalf("expected 1 broadcast, got %d", len(bcast.sentTxs))
	}
	receipt := result.Receipts[0]
	if len(receipt.Payouts) != 3 {
		t.Fatalf("pro-rata cap must preserve all 3 payouts, got %d", len(receipt.Payouts))
	}
	// Each payout should be scaled to 500 (1500 pool / 3000 requested × 1000).
	for i, p := range receipt.Payouts {
		if p.Amount.Cmp(big.NewInt(500)) != 0 {
			t.Errorf("payout[%d] Amount=%s, want 500 (pro-rata)", i, p.Amount)
		}
	}
	// Residual must equal the sum of unpaid remainders (3×500 = 1500) so the
	// next round can make them whole.
	key := "ethereum:USDC"
	if residual, ok := result.ResidualByGroup[key]; !ok || residual.Cmp(big.NewInt(1500)) != 0 {
		t.Errorf("expected residual 1500 after pro-rata cap, got %v", residual)
	}
}

func TestFeeDistributorRoundIDDeterministic(t *testing.T) {
	start := time.Unix(1700000000, 0)
	end := start.Add(time.Hour)
	a := roundIDFor(start, end)
	b := roundIDFor(start, end)
	if a != b {
		t.Fatalf("roundIDFor not deterministic: %s vs %s", a, b)
	}
	c := roundIDFor(start, end.Add(time.Second))
	if a == c {
		t.Fatalf("roundIDFor collision across different windows")
	}
}

// TestFeeDistributorIndividualPartialBroadcastFailure simulates an
// EVM-individual batch where the builder emits one tx per payout and the
// broadcaster fails on the middle tx. We must:
//   - record ONE receipt per successfully-broadcast tx (index 0),
//   - attribute each receipt to the SINGLE payout that tx paid (not the full
//     slice, which was the pre-fix over-report),
//   - roll only the failing-and-later payouts into the residual (not already
//     confirmed ones).
func TestFeeDistributorIndividualPartialBroadcastFailure(t *testing.T) {
	reg, keys := newFakeRegistry(t, []string{"ethereum"}, 3)
	// Each witness earned 1000 on ethereum.
	records := []EarningRecord{
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[0], Amount: big.NewInt(1000)},
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[1], Amount: big.NewInt(1000)},
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[2], Amount: big.NewInt(1000)},
	}
	// Builder emits per-item payloads and declares the kind as individual.
	builder := &fakeBuilder{kind: BatchKindEVMIndividual}
	// Broadcaster that fails on tx[1] so tx[0] has already landed.
	broadcaster := &midFailBroadcaster{failAt: 1}

	cfg := FeeDistributorConfig{
		Registry: reg,
		Source:   &fakeEarnings{records: records},
		Adapters: &fakeAdapters{byKey: map[string]PayoutBuilder{
			"ethereum:USDC": builder,
		}},
		Signer:      &fakeSigner{},
		Broadcaster: broadcaster,
		PoolAddresses: map[string]string{
			"ethereum": "0xpool",
		},
		Window:        24 * time.Hour,
		MinPayout:     big.NewInt(0),
		UseMulticall3: false,
	}
	d, err := NewWitnessFeeDistributor(cfg)
	if err != nil {
		t.Fatalf("NewWitnessFeeDistributor: %v", err)
	}

	result, err := d.Run(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// broadcaster.failAt=1 means index 0 succeeds; indices 1 and 2 never get
	// broadcast. We expect exactly 1 receipt (index 0), and the receipt must
	// reference ONLY the one payout it paid.
	if len(result.Receipts) != 1 {
		t.Fatalf("receipts=%d, want 1 (only the pre-failure tx)", len(result.Receipts))
	}
	if len(result.Receipts[0].Payouts) != 1 {
		t.Fatalf("receipt[0].Payouts=%d, want 1 (not the whole batch slice)", len(result.Receipts[0].Payouts))
	}
	// Residual must be exactly the two un-broadcast payouts: 1000 + 1000 = 2000.
	// If we had added index-0's 1000 back in (the pre-fix bug), we'd see 3000.
	key := "ethereum:USDC"
	residual, ok := result.ResidualByGroup[key]
	if !ok {
		t.Fatalf("missing residual for %s", key)
	}
	if residual.Cmp(big.NewInt(2000)) != 0 {
		t.Errorf("residual=%s, want 2000 (only payouts[1..2] failed, payout[0] already landed)", residual)
	}
}

// midFailBroadcaster is a FeeDistributionBroadcaster that succeeds for the
// first `failAt` calls and returns an error on the `failAt`-th call. The
// counter ignores chainID (tests only exercise one chain).
type midFailBroadcaster struct {
	failAt int
	count  int
}

func (b *midFailBroadcaster) BroadcastTx(_ context.Context, _ string, _ []byte) (string, error) {
	idx := b.count
	b.count++
	if idx == b.failAt {
		return "", errors.New("simulated mid-batch broadcast failure")
	}
	return fmt.Sprintf("0xmid-%d", idx), nil
}

// TestFeeDistributorProRataCapPreservesAllWitnesses verifies the
// capPayoutsToBalance fix: when the pool is less than the aggregate, every
// witness still receives a proportional share instead of the old lex-drop
// behaviour where late-sorted witnesses were starved.
func TestFeeDistributorProRataCapPreservesAllWitnesses(t *testing.T) {
	reg, keys := newFakeRegistry(t, []string{"ethereum"}, 4)
	// Aggregate requested = 4 × 500 = 2000. Pool = 1000. Scale = 0.5.
	// Every witness should get 250; residual = 4 × 250 = 1000.
	records := []EarningRecord{
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[0], Amount: big.NewInt(500)},
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[1], Amount: big.NewInt(500)},
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[2], Amount: big.NewInt(500)},
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[3], Amount: big.NewInt(500)},
	}
	d, _, _ := newTestDistributor(t, reg, &fakeEarnings{records: records}, func(c *FeeDistributorConfig) {
		c.PoolProvider = &fakePool{bals: map[string]*big.Int{"ethereum:USDC": big.NewInt(1000)}}
		c.UseMulticall3 = true
	})

	result, err := d.Run(context.Background(), time.Now().Add(-time.Hour), time.Now())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Receipts) != 1 {
		t.Fatalf("receipts=%d, want 1 (Multicall3 aggregate)", len(result.Receipts))
	}
	r := result.Receipts[0]
	if len(r.Payouts) != 4 {
		t.Fatalf("payouts=%d, want 4 (pro-rata must preserve every witness)", len(r.Payouts))
	}
	for i, p := range r.Payouts {
		if p.Amount.Cmp(big.NewInt(250)) != 0 {
			t.Errorf("payouts[%d].Amount=%s, want 250", i, p.Amount)
		}
	}
}

// TestFeeDistributorWindowMetadata verifies Run populates deterministic
// windowID + attestationLogRoot and threads them onto the UnsignedBatch the
// signer receives (stamped AFTER BuildBatchPayout, so we capture at the
// signer rather than the builder).
func TestFeeDistributorWindowMetadata(t *testing.T) {
	reg, keys := newFakeRegistry(t, []string{"ethereum"}, 2)
	// Records carry non-empty AttestationIDs so the root is non-zero.
	records := []EarningRecord{
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[0], Amount: big.NewInt(100), AttestationID: []byte("att-0")},
		{ChainID: "ethereum", Currency: "USDC", WitnessPubKey: keys[1], Amount: big.NewInt(200), AttestationID: []byte("att-1")},
	}
	// Reuse capturingSigner from finalizing_signer_test.go: it records the
	// batch it received and returns a valid SignedBatch by default.
	capturing := &capturingSigner{}
	cfg := FeeDistributorConfig{
		Registry: reg,
		Source:   &fakeEarnings{records: records},
		Adapters: &fakeAdapters{byKey: map[string]PayoutBuilder{
			"ethereum:USDC": &fakeBuilder{kind: BatchKindEVMMulticall3},
		}},
		Signer:      capturing,
		Broadcaster: &fakeBroadcaster{txHash: "0xtx"},
		PoolAddresses: map[string]string{
			"ethereum": "0xpool",
		},
		Window: 24 * time.Hour,
	}
	d, err := NewWitnessFeeDistributor(cfg)
	if err != nil {
		t.Fatalf("NewWitnessFeeDistributor: %v", err)
	}

	// Pick fixed window bounds so truncateToWindow is deterministic.
	start := time.Unix(1_700_000_000, 0).UTC()
	end := start.Add(24 * time.Hour)
	if _, err := d.Run(context.Background(), start, end); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if capturing.last.WindowID == 0 {
		t.Errorf("WindowID is zero, want truncated start unix")
	}
	var zero [32]byte
	if capturing.last.AttestationLogRoot == zero {
		t.Errorf("AttestationLogRoot is zero, want non-zero Merkle root from populated AttestationIDs")
	}
}

func TestAggregateEarningsDropsInvalid(t *testing.T) {
	records := []EarningRecord{
		{ChainID: "", Currency: "USDC", WitnessPubKey: "abc", Amount: big.NewInt(100)},
		{ChainID: "eth", Currency: "USDC", WitnessPubKey: "", Amount: big.NewInt(100)},
		{ChainID: "eth", Currency: "USDC", WitnessPubKey: "abc", Amount: nil},
		{ChainID: "eth", Currency: "USDC", WitnessPubKey: "abc", Amount: big.NewInt(0)},
		{ChainID: "eth", Currency: "USDC", WitnessPubKey: "abc", Amount: big.NewInt(100)},
	}
	out := aggregateEarnings(records)
	if len(out) != 1 {
		t.Fatalf("expected one group, got %d", len(out))
	}
	gk := groupKey{chainID: "eth", currency: "USDC"}
	if out[gk]["abc"].amount.Cmp(big.NewInt(100)) != 0 {
		t.Fatalf("expected 100, got %s", out[gk]["abc"].amount)
	}
}
