/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package witness

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/bbmumford/plutus/adapter"
)

// mustBreakdown builds a minimal FeeBreakdown carrying a per-witness fee map.
func mustBreakdown(witnessFees map[string]*big.Int) adapter.FeeBreakdown {
	return adapter.FeeBreakdown{
		MaintainerFee:      big.NewInt(0),
		ServiceProviderFee: big.NewInt(0),
		ArbitratorFee:      big.NewInt(0),
		WitnessFee:         big.NewInt(0),
		WitnessFees:        witnessFees,
		SellerProceeds:     big.NewInt(0),
		Total:              big.NewInt(0),
	}
}

func findRecord(records []EarningRecord, chainID, currency, witHex string) *EarningRecord {
	for i := range records {
		r := &records[i]
		if r.ChainID == chainID && r.Currency == currency && r.WitnessPubKey == witHex {
			return r
		}
	}
	return nil
}

func TestEarningLog_RecordCollectRoundtrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	log, err := NewEarningLog(dir)
	if err != nil {
		t.Fatalf("NewEarningLog: %v", err)
	}
	defer log.Close()

	ctx := context.Background()
	at := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)

	err = log.Record(ctx, "order-1", "ethereum", "USDC", at, mustBreakdown(map[string]*big.Int{
		"aa": big.NewInt(100),
		"bb": big.NewInt(250),
	}))
	if err != nil {
		t.Fatalf("Record: %v", err)
	}

	records, err := log.CollectEarnings(ctx, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		t.Fatalf("CollectEarnings: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if r := findRecord(records, "ethereum", "USDC", "aa"); r == nil || r.Amount.Int64() != 100 {
		t.Errorf("aa record: %+v", r)
	}
	if r := findRecord(records, "ethereum", "USDC", "bb"); r == nil || r.Amount.Int64() != 250 {
		t.Errorf("bb record: %+v", r)
	}
}

func TestEarningLog_TimeWindowFilter(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	log, err := NewEarningLog(dir)
	if err != nil {
		t.Fatalf("NewEarningLog: %v", err)
	}
	defer log.Close()
	ctx := context.Background()

	base := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)

	// Three records: one before window, one inside, one exactly at end (excluded).
	for i, at := range []time.Time{
		base.Add(-time.Hour),  // before start — excluded
		base,                  // at start — included
		base.Add(time.Hour),   // at end — excluded (exclusive)
	} {
		err := log.Record(ctx, fmt.Sprintf("order-%d", i), "ethereum", "USDC", at,
			mustBreakdown(map[string]*big.Int{"aa": big.NewInt(int64(10 + i))}))
		if err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}

	records, err := log.CollectEarnings(ctx, base, base.Add(time.Hour))
	if err != nil {
		t.Fatalf("CollectEarnings: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1 (only middle entry)", len(records))
	}
	if records[0].Amount.Int64() != 11 {
		t.Errorf("got amount %d, want 11", records[0].Amount.Int64())
	}
}

func TestEarningLog_GroupingAcrossOrders(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	log, err := NewEarningLog(dir)
	if err != nil {
		t.Fatalf("NewEarningLog: %v", err)
	}
	defer log.Close()
	ctx := context.Background()
	at := time.Date(2026, 4, 16, 12, 0, 0, 0, time.UTC)

	// Order 1: witness "aa" earns 100, "bb" earns 50.
	err = log.Record(ctx, "order-1", "ethereum", "USDC", at,
		mustBreakdown(map[string]*big.Int{"aa": big.NewInt(100), "bb": big.NewInt(50)}))
	if err != nil {
		t.Fatalf("Record 1: %v", err)
	}
	// Order 2: witness "aa" earns 200 (same chain+currency+witness).
	err = log.Record(ctx, "order-2", "ethereum", "USDC", at.Add(time.Minute),
		mustBreakdown(map[string]*big.Int{"aa": big.NewInt(200)}))
	if err != nil {
		t.Fatalf("Record 2: %v", err)
	}
	// Order 3: same witness but different chain (bitcoin) — should NOT merge.
	err = log.Record(ctx, "order-3", "bitcoin", "BTC", at.Add(2*time.Minute),
		mustBreakdown(map[string]*big.Int{"aa": big.NewInt(1000)}))
	if err != nil {
		t.Fatalf("Record 3: %v", err)
	}

	records, err := log.CollectEarnings(ctx, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		t.Fatalf("CollectEarnings: %v", err)
	}
	if len(records) != 3 {
		t.Fatalf("got %d grouped records, want 3", len(records))
	}

	if r := findRecord(records, "ethereum", "USDC", "aa"); r == nil || r.Amount.Int64() != 300 {
		t.Errorf("aa@ethereum: got %+v, want amount=300 (100+200)", r)
	}
	if r := findRecord(records, "ethereum", "USDC", "bb"); r == nil || r.Amount.Int64() != 50 {
		t.Errorf("bb@ethereum: got %+v, want amount=50", r)
	}
	if r := findRecord(records, "bitcoin", "BTC", "aa"); r == nil || r.Amount.Int64() != 1000 {
		t.Errorf("aa@bitcoin: got %+v, want amount=1000 (separate chain)", r)
	}
}

func TestEarningLog_Concurrent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	log, err := NewEarningLog(dir)
	if err != nil {
		t.Fatalf("NewEarningLog: %v", err)
	}
	defer log.Close()

	ctx := context.Background()
	base := time.Date(2026, 4, 16, 0, 0, 0, 0, time.UTC)

	const writers = 8
	const recordsPer = 25

	var wg sync.WaitGroup
	// Writers.
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(wIdx int) {
			defer wg.Done()
			for i := 0; i < recordsPer; i++ {
				at := base.Add(time.Duration(wIdx*recordsPer+i) * time.Millisecond)
				err := log.Record(ctx, fmt.Sprintf("order-%d-%d", wIdx, i),
					"ethereum", "USDC", at,
					mustBreakdown(map[string]*big.Int{
						"aa": big.NewInt(1),
					}))
				if err != nil {
					t.Errorf("Record: %v", err)
					return
				}
			}
		}(w)
	}
	// Concurrent readers.
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				_, err := log.CollectEarnings(ctx, base, base.Add(24*time.Hour))
				if err != nil {
					t.Errorf("CollectEarnings: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	records, err := log.CollectEarnings(ctx, base, base.Add(24*time.Hour))
	if err != nil {
		t.Fatalf("final CollectEarnings: %v", err)
	}
	// All writers shared witness "aa", so we expect one group with summed amount.
	if len(records) != 1 {
		t.Fatalf("got %d groups, want 1", len(records))
	}
	want := int64(writers * recordsPer)
	if records[0].Amount.Int64() != want {
		t.Errorf("got amount %d, want %d", records[0].Amount.Int64(), want)
	}
}

func TestEarningLog_PersistenceAcrossRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ctx := context.Background()
	at := time.Date(2026, 4, 16, 10, 0, 0, 0, time.UTC)

	// First session: record two entries and close.
	log1, err := NewEarningLog(dir)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	err = log1.Record(ctx, "order-1", "ethereum", "USDC", at,
		mustBreakdown(map[string]*big.Int{"aa": big.NewInt(100)}))
	if err != nil {
		t.Fatalf("Record 1: %v", err)
	}
	err = log1.Record(ctx, "order-2", "bitcoin", "BTC", at.Add(time.Minute),
		mustBreakdown(map[string]*big.Int{"bb": big.NewInt(500)}))
	if err != nil {
		t.Fatalf("Record 2: %v", err)
	}
	if err := log1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Writing after close is an error.
	if err := log1.Record(ctx, "order-3", "eth", "USDC", at,
		mustBreakdown(map[string]*big.Int{"cc": big.NewInt(1)})); err == nil {
		t.Error("expected Record after Close to error")
	}

	// Second session: open the same directory and add another entry.
	log2, err := NewEarningLog(dir)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	defer log2.Close()

	err = log2.Record(ctx, "order-3", "ethereum", "USDC", at.Add(2*time.Minute),
		mustBreakdown(map[string]*big.Int{"aa": big.NewInt(50)}))
	if err != nil {
		t.Fatalf("Record after restart: %v", err)
	}

	records, err := log2.CollectEarnings(ctx, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		t.Fatalf("CollectEarnings: %v", err)
	}
	// After grouping, we expect 2 groups: (eth,USDC,aa) and (bitcoin,BTC,bb).
	// The (eth,USDC,aa) group spans the restart: 100 from session 1 + 50 from
	// session 2 = 150 total.
	if len(records) != 2 {
		t.Fatalf("got %d grouped records, want 2", len(records))
	}
	if r := findRecord(records, "ethereum", "USDC", "aa"); r == nil || r.Amount.Int64() != 150 {
		t.Errorf("aa@ethereum: got %+v, want amount=150 (100+50 across restart)", r)
	}
	if r := findRecord(records, "bitcoin", "BTC", "bb"); r == nil || r.Amount.Int64() != 500 {
		t.Errorf("bb@bitcoin: got %+v, want amount=500", r)
	}
}

func TestEarningLog_EmptyWitnessFeesIsNoop(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	log, err := NewEarningLog(dir)
	if err != nil {
		t.Fatalf("NewEarningLog: %v", err)
	}
	defer log.Close()

	ctx := context.Background()
	at := time.Now().UTC()

	// Empty WitnessFees: Record should be a no-op (not an error).
	if err := log.Record(ctx, "order-x", "ethereum", "USDC", at, adapter.FeeBreakdown{}); err != nil {
		t.Fatalf("Record with empty WitnessFees: %v", err)
	}
	records, err := log.CollectEarnings(ctx, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		t.Fatalf("CollectEarnings: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("got %d records, want 0", len(records))
	}
}

func TestEarningLog_ImplementsAttestationSource(t *testing.T) {
	// Compile-time assertion that *EarningLog satisfies AttestationSource.
	var _ AttestationSource = (*EarningLog)(nil)
}

// Also verify BigInt precision is preserved across JSON round-trip.
func TestEarningLog_LargeAmountPrecision(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	log, err := NewEarningLog(dir)
	if err != nil {
		t.Fatalf("NewEarningLog: %v", err)
	}
	defer log.Close()

	ctx := context.Background()
	at := time.Now().UTC()

	// Value that overflows int64 (1 ETH = 1e18 wei, 10 ETH = 1e19 > int64 max).
	huge, _ := new(big.Int).SetString("12345678901234567890123456789", 10)
	if err := log.Record(ctx, "order-big", "ethereum", "USDC", at,
		mustBreakdown(map[string]*big.Int{"aa": huge})); err != nil {
		t.Fatalf("Record: %v", err)
	}

	records, err := log.CollectEarnings(ctx, at.Add(-time.Hour), at.Add(time.Hour))
	if err != nil {
		t.Fatalf("CollectEarnings: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if records[0].Amount.Cmp(huge) != 0 {
		t.Errorf("amount round-trip: got %s, want %s", records[0].Amount.String(), huge.String())
	}
}
