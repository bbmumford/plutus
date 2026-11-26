/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/bbmumford/whisper"
)

// fakeProvider implements ChainBalanceProvider with a scripted BalanceSnapshot.
type fakeProvider struct {
	snap BalanceSnapshot
	err  error
}

func (f *fakeProvider) QueryBalance(ctx context.Context, addr, token string) (BalanceSnapshot, error) {
	if f.err != nil {
		return BalanceSnapshot{}, f.err
	}
	return f.snap, nil
}

// newTestEngine is a stdlib-only helper that returns a fresh whisper engine.
// All BalanceVerifiers created against the same engine share the in-memory
// subscriber list, so client and witnesses communicate in-process.
func newTestEngine() *whisper.Engine {
	return whisper.NewEngine()
}

// newTestWitness spins up a BalanceVerifier in witness mode against the shared
// engine with the given provider for "testchain". It runs Run in a goroutine
// until ctx is cancelled.
func newTestWitness(t *testing.T, ctx context.Context, engine *whisper.Engine, chain string, p ChainBalanceProvider) *BalanceVerifier {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	v := NewBalanceVerifier(engine, BalanceVerifierConfig{
		Providers:      map[string]ChainBalanceProvider{chain: p},
		WitnessPrivKey: priv,
	})
	go func() { _ = v.Run(ctx) }()
	return v
}

// mustSnap builds a BalanceSnapshot with the given value and a fresh timestamp.
func mustSnap(bal int64, block uint64) BalanceSnapshot {
	return BalanceSnapshot{
		Balance:     big.NewInt(bal),
		Decimals:    18,
		BlockHash:   "0xabcd",
		BlockNumber: block,
		Timestamp:   time.Now(),
	}
}

func TestBalanceVerifierRoundtripQuorum(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestEngine()

	// Three witnesses, all agreeing on balance 1000 at block 100.
	for i := 0; i < 3; i++ {
		newTestWitness(t, ctx, engine, "testchain", &fakeProvider{snap: mustSnap(1000, 100)})
	}

	// Client verifier.
	client := NewBalanceVerifier(engine, BalanceVerifierConfig{})

	qctx, qcancel := context.WithTimeout(ctx, 3*time.Second)
	defer qcancel()
	result, err := client.QueryBalance(qctx, BalanceQuery{
		ChainID:       "testchain",
		Address:       "0xdeadbeef",
		MaxAgeSeconds: 60,
	})
	if err != nil {
		t.Fatalf("QueryBalance: %v", err)
	}
	if result.Balance.Int64() != 1000 {
		t.Errorf("balance: got %d, want 1000", result.Balance.Int64())
	}
	if result.QuorumCount < 2 {
		t.Errorf("quorum count: got %d, want >= 2", result.QuorumCount)
	}
}

func TestBalanceVerifierDisagreement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestEngine()

	// Two witnesses say 100, one says 99. Expect quorum to settle on 100.
	newTestWitness(t, ctx, engine, "testchain", &fakeProvider{snap: mustSnap(100, 50)})
	newTestWitness(t, ctx, engine, "testchain", &fakeProvider{snap: mustSnap(100, 50)})
	newTestWitness(t, ctx, engine, "testchain", &fakeProvider{snap: mustSnap(99, 50)})

	client := NewBalanceVerifier(engine, BalanceVerifierConfig{})
	qctx, qcancel := context.WithTimeout(ctx, 3*time.Second)
	defer qcancel()
	result, err := client.QueryBalance(qctx, BalanceQuery{
		ChainID:       "testchain",
		Address:       "0xaddr",
		MaxAgeSeconds: 60,
	})
	if err != nil {
		t.Fatalf("QueryBalance: %v", err)
	}
	if result.Balance.Int64() != 100 {
		t.Errorf("disagreement: got %d, want 100", result.Balance.Int64())
	}
	if result.QuorumCount != 2 {
		t.Errorf("quorum count: got %d, want 2", result.QuorumCount)
	}
}

func TestBalanceVerifierStaleRejection(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestEngine()

	// Witness returns a snapshot that is 10s old, but query requires 5s.
	stale := mustSnap(42, 1)
	stale.Timestamp = time.Now().Add(-10 * time.Second)
	newTestWitness(t, ctx, engine, "testchain", &fakeProvider{snap: stale})
	newTestWitness(t, ctx, engine, "testchain", &fakeProvider{snap: stale})
	newTestWitness(t, ctx, engine, "testchain", &fakeProvider{snap: stale})

	client := NewBalanceVerifier(engine, BalanceVerifierConfig{
		Policy: VerificationPolicy{MinWitnesses: 3, MinAgreement: 2, Timeout: 1 * time.Second},
	})
	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	_, err := client.QueryBalance(qctx, BalanceQuery{
		ChainID:       "testchain",
		Address:       "0xstale",
		MaxAgeSeconds: 5,
	})
	if !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("expected ErrNoQuorum on stale rejection, got %v", err)
	}
}

func TestBalanceVerifierReplayRejection(t *testing.T) {
	engine := newTestEngine()
	client := NewBalanceVerifier(engine, BalanceVerifierConfig{
		Policy: VerificationPolicy{MinWitnesses: 1, MinAgreement: 1, Timeout: 500 * time.Millisecond},
	})

	// Manually craft an attestation with a mismatched nonce.
	_, priv, _ := ed25519.GenerateKey(nil)
	att := &BalanceAttestation{
		ChainID:       "testchain",
		Address:       "0xreplay",
		Balance:       big.NewInt(1).Bytes(),
		Decimals:      18,
		BlockNumber:   1,
		Timestamp:     time.Now().Unix(),
		RequestNonce:  []byte{0xFF, 0xFF, 0xFF, 0xFF}, // bogus
		WitnessPubKey: priv.Public().(ed25519.PublicKey),
	}
	att.Signature = ed25519.Sign(priv, balanceAttestationDigest(att))

	// Put a pending request expecting a different nonce.
	pending := &balancePendingRequest{
		query: BalanceQuery{
			ChainID:       "testchain",
			Address:       "0xreplay",
			RequestNonce:  []byte{0x01, 0x02, 0x03, 0x04},
			MaxAgeSeconds: 60,
		},
		done: make(chan struct{}, 1),
	}
	client.mu.Lock()
	client.pending["replay-1"] = pending
	client.mu.Unlock()

	resp := balanceResponse{RequestID: "replay-1", Attestation: att}
	data, _ := marshalJSON(resp)
	client.handleResponse(data)

	if len(pending.responses) != 0 {
		t.Fatalf("replay nonce should be rejected; got %d responses", len(pending.responses))
	}
}

func TestBalanceVerifierNoWitnessesTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestEngine()
	client := NewBalanceVerifier(engine, BalanceVerifierConfig{
		Policy: VerificationPolicy{MinWitnesses: 2, MinAgreement: 2, Timeout: 300 * time.Millisecond},
	})

	qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
	defer qcancel()
	_, err := client.QueryBalance(qctx, BalanceQuery{
		ChainID:       "nonexistent",
		Address:       "0xnobody",
		MaxAgeSeconds: 60,
	})
	if !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("expected ErrNoQuorum with no witnesses, got %v", err)
	}
}

func TestBalanceVerifierCacheHit(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestEngine()

	// One provider whose QueryBalance counter we increment.
	var calls int32
	var mu sync.Mutex
	prov := providerFunc(func(ctx context.Context, addr, token string) (BalanceSnapshot, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		return mustSnap(7, 1), nil
	})

	// 2 witnesses — MinAgreement=2 — so we get a quorum with a fresh query.
	newTestWitness(t, ctx, engine, "testchain", prov)
	newTestWitness(t, ctx, engine, "testchain", prov)

	client := NewBalanceVerifier(engine, BalanceVerifierConfig{
		Policy:   VerificationPolicy{MinWitnesses: 2, MinAgreement: 2, Timeout: 2 * time.Second},
		CacheTTL: 10 * time.Second,
	})

	qctx, qcancel := context.WithTimeout(ctx, 3*time.Second)
	defer qcancel()
	q := BalanceQuery{ChainID: "testchain", Address: "0xcache", MaxAgeSeconds: 60}
	if _, err := client.QueryBalance(qctx, q); err != nil {
		t.Fatalf("first query: %v", err)
	}
	mu.Lock()
	first := calls
	mu.Unlock()
	if first == 0 {
		t.Fatal("expected provider calls on first query")
	}

	// Second query should hit cache — no new provider calls.
	if _, err := client.QueryBalance(qctx, q); err != nil {
		t.Fatalf("second query: %v", err)
	}
	mu.Lock()
	second := calls
	mu.Unlock()
	if second != first {
		t.Errorf("cache miss: provider calls went from %d to %d", first, second)
	}
}

func TestBalanceVerifierMultipleChains(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestEngine()

	// Witnesses for chainA return 50; witnesses for chainB return 200.
	for i := 0; i < 2; i++ {
		newTestWitness(t, ctx, engine, "chainA", &fakeProvider{snap: mustSnap(50, 10)})
		newTestWitness(t, ctx, engine, "chainB", &fakeProvider{snap: mustSnap(200, 20)})
	}

	client := NewBalanceVerifier(engine, BalanceVerifierConfig{
		Policy: VerificationPolicy{MinWitnesses: 2, MinAgreement: 2, Timeout: 2 * time.Second},
	})

	qctx, qcancel := context.WithTimeout(ctx, 3*time.Second)
	defer qcancel()
	ra, err := client.QueryBalance(qctx, BalanceQuery{ChainID: "chainA", Address: "0xA", MaxAgeSeconds: 60})
	if err != nil {
		t.Fatalf("chainA: %v", err)
	}
	rb, err := client.QueryBalance(qctx, BalanceQuery{ChainID: "chainB", Address: "0xB", MaxAgeSeconds: 60})
	if err != nil {
		t.Fatalf("chainB: %v", err)
	}
	if ra.Balance.Int64() != 50 {
		t.Errorf("chainA balance: got %d, want 50", ra.Balance.Int64())
	}
	if rb.Balance.Int64() != 200 {
		t.Errorf("chainB balance: got %d, want 200", rb.Balance.Int64())
	}
}

func TestBalanceVerifierRecordsAttestersForSettlement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	engine := newTestEngine()

	// Three witnesses all agreeing on balance 500; QueryBalance should record
	// all three attester pubkeys against the caller-supplied OrderContext.
	for i := 0; i < 3; i++ {
		newTestWitness(t, ctx, engine, "testchain", &fakeProvider{snap: mustSnap(500, 10)})
	}

	client := NewBalanceVerifier(engine, BalanceVerifierConfig{
		Policy: VerificationPolicy{MinWitnesses: 3, MinAgreement: 2, Timeout: 2 * time.Second},
	})

	qctx, qcancel := context.WithTimeout(ctx, 3*time.Second)
	defer qcancel()
	const orderID = "order-witness-split-1"
	_, err := client.QueryBalance(qctx, BalanceQuery{
		ChainID:       "testchain",
		Address:       "0xorder1",
		MaxAgeSeconds: 60,
		OrderContext:  orderID,
	})
	if err != nil {
		t.Fatalf("QueryBalance: %v", err)
	}

	attesters := client.RecentBalanceAttesters(orderID)
	if len(attesters) != 3 {
		t.Fatalf("RecentBalanceAttesters: got %d, want 3", len(attesters))
	}
	// All three pubkeys must be unique (no duplicates).
	seen := make(map[string]bool)
	for _, k := range attesters {
		if seen[k] {
			t.Errorf("duplicate attester pubkey %s", k)
		}
		seen[k] = true
	}

	// Querying under a different order context must not inherit the log.
	if other := client.RecentBalanceAttesters("order-other"); len(other) != 0 {
		t.Errorf("unrelated context leaked %d attesters", len(other))
	}
}

func TestRecordBalanceAttestationBoundedWindow(t *testing.T) {
	engine := newTestEngine()
	v := NewBalanceVerifier(engine, BalanceVerifierConfig{})

	// Insert one more than the cap under the same orderContext.
	for i := 0; i <= balanceAttestWindowSize; i++ {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("generate key %d: %v", i, err)
		}
		v.RecordBalanceAttestation(pub, "order-cap")
	}

	v.mu.Lock()
	got := len(v.attestLog["order-cap"].entries)
	v.mu.Unlock()
	if got != balanceAttestWindowSize {
		t.Errorf("window size: got %d, want %d", got, balanceAttestWindowSize)
	}
}

func TestRecordBalanceAttestationDedupePreservesOrder(t *testing.T) {
	engine := newTestEngine()
	v := NewBalanceVerifier(engine, BalanceVerifierConfig{})

	pub1, _, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	v.RecordBalanceAttestation(pub1, "order-dedup")
	v.RecordBalanceAttestation(pub2, "order-dedup")
	v.RecordBalanceAttestation(pub1, "order-dedup") // duplicate

	att := v.RecentBalanceAttesters("order-dedup")
	if len(att) != 2 {
		t.Fatalf("RecentBalanceAttesters after dedupe: got %d, want 2", len(att))
	}
}

func TestRecordBalanceAttestationEmptyContextIsNoop(t *testing.T) {
	engine := newTestEngine()
	v := NewBalanceVerifier(engine, BalanceVerifierConfig{})

	pub, _, _ := ed25519.GenerateKey(nil)
	v.RecordBalanceAttestation(pub, "")

	if att := v.RecentBalanceAttesters(""); len(att) != 0 {
		t.Errorf("empty orderContext should be no-op; got %d entries", len(att))
	}
}

func TestSplitWitnessFeeEqualSplitsAndPreservesTotal(t *testing.T) {
	// 100 wei split across 3 attesters = 33 + 33 + 33 = 99, dust (1) to first.
	attesters := []string{"a", "b", "c"}
	dist := SplitWitnessFee(big.NewInt(100), attesters)
	if len(dist) != 3 {
		t.Fatalf("map size: got %d, want 3", len(dist))
	}
	sum := new(big.Int)
	for _, v := range dist {
		sum.Add(sum, v)
	}
	if sum.Int64() != 100 {
		t.Errorf("sum preserved: got %d, want 100", sum.Int64())
	}
	// First attester absorbs the remainder (1 extra wei).
	if dist["a"].Int64() != 34 {
		t.Errorf("first attester: got %d, want 34 (33 share + 1 dust)", dist["a"].Int64())
	}
}

func TestSplitWitnessFeeEmptyOrZeroReturnsNil(t *testing.T) {
	if SplitWitnessFee(big.NewInt(100), nil) != nil {
		t.Error("nil attesters should return nil map")
	}
	if SplitWitnessFee(big.NewInt(0), []string{"a"}) != nil {
		t.Error("zero fee should return nil map")
	}
	if SplitWitnessFee(nil, []string{"a"}) != nil {
		t.Error("nil fee should return nil map")
	}
}

// providerFunc adapts a closure to ChainBalanceProvider.
type providerFunc func(ctx context.Context, addr, token string) (BalanceSnapshot, error)

func (f providerFunc) QueryBalance(ctx context.Context, addr, token string) (BalanceSnapshot, error) {
	return f(ctx, addr, token)
}

// marshalJSON wraps json.Marshal for single-site use in the replay test.
func marshalJSON(v interface{}) ([]byte, error) {
	return json.Marshal(v)
}
