/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package arbitrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// stubScorer provides fixed reputation data.
type stubScorer struct {
	rate   map[string]float64
	trades map[string]int
}

func (s *stubScorer) PositiveRate(pk []byte) float64 {
	return s.rate[string(pk)]
}
func (s *stubScorer) TotalTrades(pk []byte) int {
	return s.trades[string(pk)]
}

func freshProfile(t *testing.T, feeBPS uint32, chainID, category string) (ArbitratorProfile, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	p := ArbitratorProfile{
		PubKey:       pub,
		ChainAddrs:   map[string]string{chainID: "0xaaaa"},
		FeeBPS:       feeBPS,
		Categories:   []string{category},
		Availability: true,
		RegisteredAt: time.Now(),
	}
	if err := SignProfile(&p, priv); err != nil {
		t.Fatal(err)
	}
	return p, priv
}

func TestSignAndVerifyProfile(t *testing.T) {
	t.Parallel()
	p, _ := freshProfile(t, 100, "ethereum", "digital-goods")
	if !VerifyProfile(&p) {
		t.Error("fresh profile should verify")
	}
	p.FeeBPS = 999
	if VerifyProfile(&p) {
		t.Error("tampered profile should not verify")
	}
}

func TestVerifyProfile_BadSizes(t *testing.T) {
	t.Parallel()
	p := &ArbitratorProfile{PubKey: []byte{1}}
	if VerifyProfile(p) {
		t.Error("short pubkey must not verify")
	}
	p.PubKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	p.Signature = []byte{1}
	if VerifyProfile(p) {
		t.Error("short signature must not verify")
	}
}

// buildInMemoryRegistry creates a registry that bypasses the whisper engine
// by directly populating the entries map. This lets us test FindBest without
// instantiating a whisper/ledger stack.
func buildInMemoryRegistry(profiles ...ArbitratorProfile) *ArbitratorRegistry {
	r := &ArbitratorRegistry{
		entries: make(map[string]*ArbitratorProfile),
	}
	for i := range profiles {
		p := profiles[i]
		r.entries[string(p.PubKey)] = &p
	}
	return r
}

func TestFindBest_FiltersByCategoryAndChain(t *testing.T) {
	t.Parallel()
	p1, _ := freshProfile(t, 100, "ethereum", "digital-goods")
	p2, _ := freshProfile(t, 200, "polygon", "services")
	p3, _ := freshProfile(t, 150, "ethereum", "services")

	reg := buildInMemoryRegistry(p1, p2, p3)

	// Ethereum + services should only match p3.
	results := FindBest(reg, nil, SelectionCriteria{Category: "services", ChainID: "ethereum"})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if string(results[0].Profile.PubKey) != string(p3.PubKey) {
		t.Error("wrong candidate selected")
	}
}

func TestFindBest_AppliesMaxFee(t *testing.T) {
	t.Parallel()
	lowFee, _ := freshProfile(t, 50, "ethereum", "digital-goods")
	highFee, _ := freshProfile(t, 290, "ethereum", "digital-goods")
	reg := buildInMemoryRegistry(lowFee, highFee)

	results := FindBest(reg, nil, SelectionCriteria{
		Category: "digital-goods",
		ChainID:  "ethereum",
		MaxFee:   100,
	})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if string(results[0].Profile.PubKey) != string(lowFee.PubKey) {
		t.Error("max-fee filter should exclude high-fee candidate")
	}
}

func TestFindBest_LimitApplied(t *testing.T) {
	t.Parallel()
	p1, _ := freshProfile(t, 100, "ethereum", "digital-goods")
	p2, _ := freshProfile(t, 110, "ethereum", "digital-goods")
	p3, _ := freshProfile(t, 120, "ethereum", "digital-goods")
	reg := buildInMemoryRegistry(p1, p2, p3)

	results := FindBest(reg, nil, SelectionCriteria{
		Category: "digital-goods",
		ChainID:  "ethereum",
		Limit:    2,
	})
	if len(results) != 2 {
		t.Errorf("expected 2 results, got %d", len(results))
	}
}

func TestFindBest_RankingFavorsLowerFee(t *testing.T) {
	t.Parallel()
	lowFee, _ := freshProfile(t, 50, "ethereum", "digital-goods")
	highFee, _ := freshProfile(t, 290, "ethereum", "digital-goods")
	reg := buildInMemoryRegistry(lowFee, highFee)

	results := FindBest(reg, nil, SelectionCriteria{
		Category: "digital-goods",
		ChainID:  "ethereum",
	})
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// First should be the lower-fee arbitrator.
	if string(results[0].Profile.PubKey) != string(lowFee.PubKey) {
		t.Error("lower fee should rank higher")
	}
	if results[0].Score < results[1].Score {
		t.Error("results not sorted descending by score")
	}
}

func TestFindBest_NoMatches(t *testing.T) {
	t.Parallel()
	reg := buildInMemoryRegistry()
	if r := FindBest(reg, nil, SelectionCriteria{Category: "x", ChainID: "y"}); len(r) != 0 {
		t.Error("empty registry should yield no results")
	}
}

func TestFindBest_UnavailableExcluded(t *testing.T) {
	t.Parallel()
	p, _ := freshProfile(t, 100, "ethereum", "digital-goods")
	p.Availability = false
	// re-sign after mutation
	_ = SignProfile(&p, ed25519.NewKeyFromSeed(make([]byte, 32))) // dummy — not used for verify here
	reg := buildInMemoryRegistry(p)
	results := FindBest(reg, nil, SelectionCriteria{Category: "digital-goods", ChainID: "ethereum"})
	if len(results) != 0 {
		t.Error("unavailable arbitrator should be excluded")
	}
}

func TestComputeScore_UsesReputation(t *testing.T) {
	t.Parallel()
	pub := make(ed25519.PublicKey, 32)
	for i := range pub {
		pub[i] = 0x42
	}
	prof := ArbitratorProfile{
		PubKey:       pub,
		FeeBPS:       100,
		Availability: true,
	}
	scorer := &stubScorer{
		rate:   map[string]float64{string(pub): 0.95},
		trades: map[string]int{string(pub): 500},
	}
	withRep := computeScore(prof, scorer)

	emptyScorer := &stubScorer{}
	withoutRep := computeScore(prof, emptyScorer)

	if withRep <= withoutRep {
		t.Errorf("high reputation should beat no reputation (%f <= %f)", withRep, withoutRep)
	}
}

func TestLog2Approx(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in      float64
		wantMin float64
		wantMax float64
	}{
		{0, 0, 0.001},
		{1, 0, 0.001},
		{2, 1, 1.001},
		{4, 2, 2.001},
	}
	for _, tc := range cases {
		got := log2Approx(tc.in)
		if got < tc.wantMin || got > tc.wantMax {
			t.Errorf("log2Approx(%v) = %v, want in [%v, %v]", tc.in, got, tc.wantMin, tc.wantMax)
		}
	}
}
