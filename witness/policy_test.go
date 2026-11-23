/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"testing"
	"time"
)

func TestPolicyForValue_Tiers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name              string
		usd               float64
		wantMinWitnesses  int
		wantMinAgreement  int
		wantMaxTimeout    time.Duration
		wantRequireMerkle bool
	}{
		{"quick-low", 1, 1, 1, 2 * time.Second, false},
		{"quick-boundary", 9.99, 1, 1, 2 * time.Second, false},
		{"standard-low", 10, 3, 2, 5 * time.Second, false},
		{"standard-mid", 50, 3, 2, 5 * time.Second, false},
		{"high", 500, 5, 4, 10 * time.Second, true},
		{"maximum", 5000, 7, 6, 15 * time.Second, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			p := PolicyForValue(tc.usd)
			if p.MinWitnesses != tc.wantMinWitnesses {
				t.Errorf("MinWitnesses: got %d, want %d", p.MinWitnesses, tc.wantMinWitnesses)
			}
			if p.MinAgreement != tc.wantMinAgreement {
				t.Errorf("MinAgreement: got %d, want %d", p.MinAgreement, tc.wantMinAgreement)
			}
			if p.Timeout != tc.wantMaxTimeout {
				t.Errorf("Timeout: got %v, want %v", p.Timeout, tc.wantMaxTimeout)
			}
			if p.RequireMerkleProof != tc.wantRequireMerkle {
				t.Errorf("RequireMerkleProof: got %v, want %v", p.RequireMerkleProof, tc.wantRequireMerkle)
			}
		})
	}
}

func TestPolicyForValue_Monotonic(t *testing.T) {
	t.Parallel()
	// As value increases, witness count should not decrease.
	values := []float64{1, 50, 500, 5000, 1_000_000}
	last := 0
	for _, v := range values {
		p := PolicyForValue(v)
		if p.MinWitnesses < last {
			t.Errorf("policy non-monotonic at value=%v: %d < prev %d", v, p.MinWitnesses, last)
		}
		last = p.MinWitnesses
	}
}
