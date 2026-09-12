/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package witness

import "testing"

func TestCollusionDetector_EmptyState(t *testing.T) {
	t.Parallel()
	d := NewCollusionDetector()
	if pairs := d.DetectCollusion(0.5); len(pairs) != 0 {
		t.Errorf("expected no pairs in empty detector, got %d", len(pairs))
	}
	if d.IsSuspicious("A") {
		t.Error("empty detector should not flag anyone suspicious")
	}
}

func TestCollusionDetector_SelfAgreementIgnored(t *testing.T) {
	t.Parallel()
	d := NewCollusionDetector()
	for range 100 {
		d.RecordAgreement("A", "A")
	}
	if pairs := d.DetectCollusion(0.0); len(pairs) != 0 {
		t.Errorf("self-agreements should be ignored, got %d pairs", len(pairs))
	}
}

func TestCollusionDetector_BelowMinSample(t *testing.T) {
	t.Parallel()
	d := NewCollusionDetector()
	// 9 agreements (minSample is 10) -> should not flag.
	for range 9 {
		d.RecordAgreement("A", "B")
	}
	if pairs := d.DetectCollusion(0.5); len(pairs) != 0 {
		t.Error("below minSample should not flag collusion")
	}
}

func TestCollusionDetector_HighRate(t *testing.T) {
	t.Parallel()
	d := NewCollusionDetector()
	// 20 agreements between A and B, always together => 100% rate.
	for range 20 {
		d.RecordAgreement("A", "B")
	}
	pairs := d.DetectCollusion(0.9)
	if len(pairs) != 1 {
		t.Fatalf("expected 1 collusion pair, got %d", len(pairs))
	}
	if pairs[0].Rate < 0.99 {
		t.Errorf("expected ~1.0 rate, got %f", pairs[0].Rate)
	}
	if !d.IsSuspicious("A") || !d.IsSuspicious("B") {
		t.Error("both witnesses should be flagged")
	}
}

func TestCollusionDetector_DeduplicatedPairs(t *testing.T) {
	t.Parallel()
	d := NewCollusionDetector()
	for range 20 {
		d.RecordAgreement("A", "B")
	}
	for range 20 {
		d.RecordAgreement("C", "A")
	}
	pairs := d.DetectCollusion(0.1)
	// Ensure no (A,B) and (B,A) duplicate
	seen := map[string]int{}
	for _, p := range pairs {
		key := p.WitnessA + "|" + p.WitnessB
		seen[key]++
	}
	for k, c := range seen {
		if c > 1 {
			t.Errorf("duplicate pair: %s x%d", k, c)
		}
	}
}
