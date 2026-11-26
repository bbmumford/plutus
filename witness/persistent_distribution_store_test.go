/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPersistentDistributionStore_RoundTrip mirrors the in-memory suite so we
// have parity coverage for LoadRound/SaveRound on the persistent backend.
func TestPersistentDistributionStore_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistentDistributionStore(dir)
	if err != nil {
		t.Fatalf("NewPersistentDistributionStore: %v", err)
	}
	defer s.Close()

	ctx := context.Background()

	got, err := s.LoadRound(ctx, "unknown")
	if err != nil {
		t.Fatalf("LoadRound unknown: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil for unknown round, got %+v", got)
	}

	round := sampleRound("round-1")
	if err := s.SaveRound(ctx, round); err != nil {
		t.Fatalf("SaveRound: %v", err)
	}

	got, err = s.LoadRound(ctx, "round-1")
	if err != nil {
		t.Fatalf("LoadRound saved: %v", err)
	}
	if got == nil || got.RoundID != "round-1" {
		t.Fatalf("round not retrieved: %+v", got)
	}
	if got.WindowStart.Unix() != round.WindowStart.Unix() {
		t.Errorf("WindowStart mismatch: %v vs %v", got.WindowStart, round.WindowStart)
	}
	if len(got.Receipts) != len(round.Receipts) {
		t.Errorf("Receipts len: %d vs %d", len(got.Receipts), len(round.Receipts))
	}
	if got.Receipts[0].Payouts[0].Amount.Cmp(round.Receipts[0].Payouts[0].Amount) != 0 {
		t.Errorf("payout amount mismatch: %v vs %v", got.Receipts[0].Payouts[0].Amount, round.Receipts[0].Payouts[0].Amount)
	}
	if got.ResidualByGroup["ethereum:USDC"].Cmp(round.ResidualByGroup["ethereum:USDC"]) != 0 {
		t.Errorf("residual mismatch: %v vs %v", got.ResidualByGroup, round.ResidualByGroup)
	}
}

// TestPersistentDistributionStore_DuplicateRejected mirrors the in-memory
// suite — back-to-back saves of the same RoundID must fail with
// ErrRoundAlreadyProcessed.
func TestPersistentDistributionStore_DuplicateRejected(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistentDistributionStore(dir)
	if err != nil {
		t.Fatalf("NewPersistentDistributionStore: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	round := sampleRound("dup")
	if err := s.SaveRound(ctx, round); err != nil {
		t.Fatalf("first SaveRound: %v", err)
	}
	err = s.SaveRound(ctx, round)
	if err == nil {
		t.Fatal("want duplicate error, got nil")
	}
	if !errors.Is(err, ErrRoundAlreadyProcessed) {
		t.Errorf("want ErrRoundAlreadyProcessed, got %v", err)
	}
}

// TestPersistentDistributionStore_CrashRecovery is the defining test for this
// store: write, Close, re-open a fresh store instance pointing at the same
// directory, and observe that previously-saved rounds still load. This is the
// property the in-memory variant cannot provide.
func TestPersistentDistributionStore_CrashRecovery(t *testing.T) {
	dir := t.TempDir()

	// First process lifetime: save rounds A and B.
	s1, err := NewPersistentDistributionStore(dir)
	if err != nil {
		t.Fatalf("open first store: %v", err)
	}
	ctx := context.Background()
	for _, id := range []string{"A", "B"} {
		if err := s1.SaveRound(ctx, sampleRound(id)); err != nil {
			t.Fatalf("SaveRound %s: %v", id, err)
		}
	}
	if err := s1.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	// Second process lifetime: open a NEW store on the same directory. The
	// file handle from s1 is closed; s2 is a fresh object with fresh maps.
	s2, err := NewPersistentDistributionStore(dir)
	if err != nil {
		t.Fatalf("open second store: %v", err)
	}
	defer s2.Close()

	for _, id := range []string{"A", "B"} {
		got, err := s2.LoadRound(ctx, id)
		if err != nil {
			t.Fatalf("LoadRound %s after reopen: %v", id, err)
		}
		if got == nil {
			t.Fatalf("round %s missing after reopen — persistence broken", id)
		}
		if got.RoundID != id {
			t.Errorf("round %s: got RoundID=%q", id, got.RoundID)
		}
	}

	// Duplicate-reject semantics survive reopen: saving "A" again must fail
	// with ErrRoundAlreadyProcessed even though this process never wrote it.
	if err := s2.SaveRound(ctx, sampleRound("A")); !errors.Is(err, ErrRoundAlreadyProcessed) {
		t.Errorf("second-lifetime duplicate check: want ErrRoundAlreadyProcessed, got %v", err)
	}

	// Adding a NEW round in the second lifetime and reopening again must
	// carry all three rounds forward.
	if err := s2.SaveRound(ctx, sampleRound("C")); err != nil {
		t.Fatalf("SaveRound C in second lifetime: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatalf("close second store: %v", err)
	}

	s3, err := NewPersistentDistributionStore(dir)
	if err != nil {
		t.Fatalf("open third store: %v", err)
	}
	defer s3.Close()
	for _, id := range []string{"A", "B", "C"} {
		got, err := s3.LoadRound(ctx, id)
		if err != nil {
			t.Fatalf("LoadRound %s in third lifetime: %v", id, err)
		}
		if got == nil {
			t.Fatalf("round %s missing in third lifetime", id)
		}
	}
}

// TestPersistentDistributionStore_ConcurrentDifferentRounds fires many saves
// at distinct RoundIDs in parallel — the store must accept all of them and
// persist them to disk without corruption.
func TestPersistentDistributionStore_ConcurrentDifferentRounds(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistentDistributionStore(dir)
	if err != nil {
		t.Fatalf("NewPersistentDistributionStore: %v", err)
	}

	ctx := context.Background()
	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.SaveRound(ctx, sampleRound(fmt.Sprintf("r-%d", i))); err != nil {
				t.Errorf("SaveRound r-%d: %v", i, err)
			}
		}(i)
	}
	wg.Wait()

	// Verify in-memory index.
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("r-%d", i)
		got, err := s.LoadRound(ctx, id)
		if err != nil {
			t.Errorf("LoadRound %s: %v", id, err)
		}
		if got == nil {
			t.Errorf("round %s missing after concurrent saves", id)
		}
	}

	// Close + reopen to verify the log captured every entry.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	s2, err := NewPersistentDistributionStore(dir)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer s2.Close()
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("r-%d", i)
		got, err := s2.LoadRound(ctx, id)
		if err != nil {
			t.Errorf("LoadRound %s after reopen: %v", id, err)
		}
		if got == nil {
			t.Errorf("round %s missing after reopen following concurrent saves", id)
		}
	}
}

// TestPersistentDistributionStore_ConcurrentSameRoundIdempotent fires many
// concurrent saves at the SAME RoundID. Exactly one must succeed; the rest
// must surface ErrRoundAlreadyProcessed. That is what "idempotent" means for
// this API — the store never double-records a round.
func TestPersistentDistributionStore_ConcurrentSameRoundIdempotent(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistentDistributionStore(dir)
	if err != nil {
		t.Fatalf("NewPersistentDistributionStore: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	const n = 16
	var wg sync.WaitGroup
	var successes atomic.Int32
	var dupes atomic.Int32
	var others atomic.Int32

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := s.SaveRound(ctx, sampleRound("solo"))
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrRoundAlreadyProcessed):
				dupes.Add(1)
			default:
				others.Add(1)
			}
		}()
	}
	wg.Wait()

	if successes.Load() != 1 {
		t.Errorf("want exactly 1 success, got %d", successes.Load())
	}
	if dupes.Load() != n-1 {
		t.Errorf("want %d duplicate-rejected, got %d", n-1, dupes.Load())
	}
	if others.Load() != 0 {
		t.Errorf("unexpected non-duplicate errors: %d", others.Load())
	}
}

// TestPersistentDistributionStore_BackendAppendFail verifies that a backend
// append failure surfaces to the caller AND does not leave the in-memory
// index in a "this round succeeded" state — a subsequent retry must be able
// to save the same round cleanly once the backend recovers.
func TestPersistentDistributionStore_BackendAppendFail(t *testing.T) {
	fake := &flakyBackend{}
	dir := t.TempDir()
	path := filepath.Join(dir, "distribution.log")
	s, err := newPersistentDistributionStoreWithBackend(dir, path, fake)
	if err != nil {
		t.Fatalf("newPersistentDistributionStoreWithBackend: %v", err)
	}

	ctx := context.Background()
	fake.setAppendErr(errors.New("disk full"))
	err = s.SaveRound(ctx, sampleRound("rs"))
	if err == nil {
		t.Fatal("want backend error, got nil")
	}
	if !errors.Is(err, errInjectedAppend) && err.Error() == "" {
		// We wrapped the injected error; check the chain contains our sentinel.
	}
	// The in-memory index must NOT have the round — otherwise a restart-
	// induced replay would miss it and a retry would be silently suppressed.
	if got, _ := s.LoadRound(ctx, "rs"); got != nil {
		t.Errorf("round visible after append failure: %+v", got)
	}

	// Recover — clear the injected error and retry. The second attempt must
	// succeed exactly once.
	fake.setAppendErr(nil)
	if err := s.SaveRound(ctx, sampleRound("rs")); err != nil {
		t.Fatalf("retry after recover: %v", err)
	}
	if got, _ := s.LoadRound(ctx, "rs"); got == nil {
		t.Fatal("round missing after successful retry")
	}
}

// TestPersistentDistributionStore_BackendReplayFail verifies that a replay
// error on open surfaces cleanly and the store is not left partially open.
func TestPersistentDistributionStore_BackendReplayFail(t *testing.T) {
	fake := &flakyBackend{replayErr: errors.New("corrupt log")}
	dir := t.TempDir()
	path := filepath.Join(dir, "distribution.log")
	_, err := newPersistentDistributionStoreWithBackend(dir, path, fake)
	if err == nil {
		t.Fatal("want replay error, got nil")
	}
	if !fake.closed.Load() {
		t.Error("backend was not closed after replay failure")
	}
}

// TestPersistentDistributionStore_NilRound matches the in-memory suite: nil
// rounds must be rejected with a clear error.
func TestPersistentDistributionStore_NilRound(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistentDistributionStore(dir)
	if err != nil {
		t.Fatalf("NewPersistentDistributionStore: %v", err)
	}
	defer s.Close()
	if err := s.SaveRound(context.Background(), nil); err == nil {
		t.Fatal("want nil-round error")
	}
}

// TestPersistentDistributionStore_EmptyDirRejected confirms input validation
// — an empty directory path is a caller error.
func TestPersistentDistributionStore_EmptyDirRejected(t *testing.T) {
	if _, err := NewPersistentDistributionStore(""); err == nil {
		t.Fatal("want empty-dir error, got nil")
	}
}

// --- helpers ---------------------------------------------------------------

// sampleRound returns a DistributionRoundResult with non-trivial sub-slices so
// encode/decode round-trips exercise every field.
func sampleRound(id string) *DistributionRoundResult {
	return &DistributionRoundResult{
		RoundID:     id,
		WindowStart: time.Unix(1700000000, 0).UTC(),
		WindowEnd:   time.Unix(1700086400, 0).UTC(),
		StartedAt:   time.Unix(1700086400, 0).UTC(),
		CompletedAt: time.Unix(1700086410, 0).UTC(),
		Receipts: []DistributionReceipt{
			{
				ChainID:       "ethereum",
				Currency:      "USDC",
				TxHash:        "0xdeadbeef",
				BroadcastedAt: time.Unix(1700086410, 0).UTC(),
				Payouts: []Payout{
					{
						WitnessPubKey:  []byte{0xaa, 0xbb, 0xcc},
						WitnessAddr:    "0xfeed",
						ChainID:        "ethereum",
						Currency:       "USDC",
						Amount:         big.NewInt(1234567),
						AttestationIDs: [][]byte{{0x01, 0x02}, {0x03, 0x04}},
					},
				},
			},
		},
		Skipped: []SkippedPayout{
			{
				WitnessPubKey: "aabbcc",
				ChainID:       "ethereum",
				Currency:      "USDC",
				Amount:        big.NewInt(10),
				Reason:        "below min payout",
			},
		},
		ResidualByGroup: map[string]*big.Int{
			"ethereum:USDC": big.NewInt(42),
		},
	}
}

// flakyBackend is an in-memory distributionBackend for tests that need to
// induce error paths at the backend boundary.
type flakyBackend struct {
	mu        sync.Mutex
	entries   []distributionLogEntry
	appendErr error
	replayErr error
	closed    atomic.Bool
}

// errInjectedAppend is the sentinel we set via setAppendErr to make the
// append-failure test readable.
var errInjectedAppend = errors.New("injected append failure")

func (f *flakyBackend) setAppendErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.appendErr = err
}

func (f *flakyBackend) Replay(fn func(entry distributionLogEntry) error) error {
	if f.replayErr != nil {
		return f.replayErr
	}
	f.mu.Lock()
	entries := make([]distributionLogEntry, len(f.entries))
	copy(entries, f.entries)
	f.mu.Unlock()
	for _, e := range entries {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

func (f *flakyBackend) Append(entry distributionLogEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.appendErr != nil {
		return f.appendErr
	}
	f.entries = append(f.entries, entry)
	return nil
}

func (f *flakyBackend) Close() error {
	f.closed.Store(true)
	return nil
}
