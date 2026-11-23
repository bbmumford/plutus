/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import "sync"

// CollusionPair identifies two witnesses with suspiciously high agreement
// correlation, suggesting they may be colluding (same operator, shared data
// source, or coordinated false attestations).
type CollusionPair struct {
	WitnessA   string
	WitnessB   string
	Agreements int
	Rate       float64 // agreement rate as fraction of total attestations
}

// CollusionDetector tracks pairwise agreement rates between witnesses. When
// two witnesses agree on attestations more than a threshold fraction of the
// time, they are flagged as potentially colluding.
//
// The detector also maintains per-witness total attestation counts so that
// agreement rates can be computed as a fraction of the witness with fewer
// total attestations (avoiding false positives for prolific witnesses).
type CollusionDetector struct {
	mu           sync.RWMutex
	correlations map[string]map[string]int // witnessA -> witnessB -> agreement count
	totals       map[string]int            // witness -> total attestation count
}

// NewCollusionDetector creates a detector with empty state.
func NewCollusionDetector() *CollusionDetector {
	return &CollusionDetector{
		correlations: make(map[string]map[string]int),
		totals:       make(map[string]int),
	}
}

// RecordAgreement records that witnessA and witnessB agreed on an attestation.
// Both sides of the pair are updated (A->B and B->A) and both witnesses'
// total attestation counts are incremented.
func (d *CollusionDetector) RecordAgreement(witnessA, witnessB string) {
	if witnessA == witnessB {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.totals[witnessA]++
	d.totals[witnessB]++

	if d.correlations[witnessA] == nil {
		d.correlations[witnessA] = make(map[string]int)
	}
	d.correlations[witnessA][witnessB]++

	if d.correlations[witnessB] == nil {
		d.correlations[witnessB] = make(map[string]int)
	}
	d.correlations[witnessB][witnessA]++
}

// DetectCollusion returns all pairs whose agreement rate exceeds the given
// threshold (0.0 to 1.0). The rate is computed as agreements / min(totalA, totalB),
// requiring at least 10 mutual attestations to avoid noise from small samples.
func (d *CollusionDetector) DetectCollusion(threshold float64) []CollusionPair {
	d.mu.RLock()
	defer d.mu.RUnlock()

	const minSample = 10

	// Deduplicate pairs (only emit A<B lexicographically)
	seen := make(map[[2]string]bool)
	var pairs []CollusionPair

	for a, peers := range d.correlations {
		for b, count := range peers {
			key := [2]string{a, b}
			if a > b {
				key = [2]string{b, a}
			}
			if seen[key] {
				continue
			}
			seen[key] = true

			if count < minSample {
				continue
			}

			minTotal := d.totals[a]
			if d.totals[b] < minTotal {
				minTotal = d.totals[b]
			}
			if minTotal == 0 {
				continue
			}

			rate := float64(count) / float64(minTotal)
			if rate >= threshold {
				pairs = append(pairs, CollusionPair{
					WitnessA:   key[0],
					WitnessB:   key[1],
					Agreements: count,
					Rate:       rate,
				})
			}
		}
	}
	return pairs
}

// IsSuspicious returns true if the given witness appears in any collusion pair
// at the default threshold of 0.95 (95% agreement rate). This is a convenience
// method for quick checks during attestation collection.
func (d *CollusionDetector) IsSuspicious(witness string) bool {
	pairs := d.DetectCollusion(0.95)
	for _, p := range pairs {
		if p.WitnessA == witness || p.WitnessB == witness {
			return true
		}
	}
	return false
}
