/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package settle

import (
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/bbmumford/plutus/adapter"
)

func TestFeeCalculator_BasicBPSMath(t *testing.T) {
	t.Parallel()
	calc := NewFeeCalculator()

	type row struct {
		name           string
		amount         int64
		opts           adapter.FeeOptions
		wantMaint      int64
		wantWitness    int64
		wantService    int64
		wantArbitrator int64
		wantSeller     int64
	}
	rows := []row{
		{"1%-maintainer-only-1000", 1000, adapter.FeeOptions{MaintainerBPS: 100}, 10, 0, 0, 0, 990},
		{"5%-maintainer-at-cap", 10000, adapter.FeeOptions{MaintainerBPS: 500}, 500, 0, 0, 0, 9500},
		{"combined-fees", 10000, adapter.FeeOptions{
			MaintainerBPS:      100,
			HasServiceProvider: true, ServiceProviderBPS: 200,
			HasDispute: true, ArbitratorBPS: 300,
			HasWitness: true, WitnessBPS: 100,
		}, 100, 100, 200, 300, 9300},
		{"truncation-rounds-down", 99, adapter.FeeOptions{MaintainerBPS: 100}, 0, 0, 0, 0, 99},
	}

	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			t.Parallel()
			amt := big.NewInt(r.amount)
			fb, err := calc.Calculate(amt, r.opts)
			if err != nil {
				t.Fatalf("Calculate: %v", err)
			}
			if fb.MaintainerFee.Int64() != r.wantMaint {
				t.Errorf("MaintainerFee = %d, want %d", fb.MaintainerFee.Int64(), r.wantMaint)
			}
			if fb.WitnessFee.Int64() != r.wantWitness {
				t.Errorf("WitnessFee = %d, want %d", fb.WitnessFee.Int64(), r.wantWitness)
			}
			if fb.ServiceProviderFee.Int64() != r.wantService {
				t.Errorf("ServiceProviderFee = %d, want %d", fb.ServiceProviderFee.Int64(), r.wantService)
			}
			if fb.ArbitratorFee.Int64() != r.wantArbitrator {
				t.Errorf("ArbitratorFee = %d, want %d", fb.ArbitratorFee.Int64(), r.wantArbitrator)
			}
			if fb.SellerProceeds.Int64() != r.wantSeller {
				t.Errorf("SellerProceeds = %d, want %d", fb.SellerProceeds.Int64(), r.wantSeller)
			}
			// Sanity: all parts add up to total.
			sum := new(big.Int)
			sum.Add(sum, fb.MaintainerFee)
			sum.Add(sum, fb.WitnessFee)
			sum.Add(sum, fb.ServiceProviderFee)
			sum.Add(sum, fb.ArbitratorFee)
			sum.Add(sum, fb.SellerProceeds)
			if sum.Cmp(fb.Total) != 0 {
				t.Errorf("components sum %s != total %s", sum, fb.Total)
			}
		})
	}
}

func TestFeeCalculator_HardCaps(t *testing.T) {
	t.Parallel()
	calc := NewFeeCalculator()

	cases := []struct {
		name string
		opts adapter.FeeOptions
		want string // substring of expected error
	}{
		{"maintainer-over-cap", adapter.FeeOptions{MaintainerBPS: 501}, "maintainer BPS 501"},
		{"witness-over-cap", adapter.FeeOptions{MaintainerBPS: 100, HasWitness: true, WitnessBPS: 101}, "witness BPS 101"},
		{"service-over-cap", adapter.FeeOptions{MaintainerBPS: 100, HasServiceProvider: true, ServiceProviderBPS: 201}, "service provider BPS 201"},
		{"arbitrator-over-cap", adapter.FeeOptions{MaintainerBPS: 100, HasDispute: true, ArbitratorBPS: 301}, "arbitrator BPS 301"},
		{"combined-over-cap", adapter.FeeOptions{
			MaintainerBPS:      500,
			HasServiceProvider: true, ServiceProviderBPS: 200,
			HasDispute: true, ArbitratorBPS: 300,
			HasWitness: true, WitnessBPS: 100,
			// combined = 1100 > 1000 cap
		}, "combined BPS 1100"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := calc.Calculate(big.NewInt(10_000), tc.opts)
			if err == nil {
				t.Fatal("expected cap violation error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestFeeCalculator_AmountEdgeCases(t *testing.T) {
	t.Parallel()
	calc := NewFeeCalculator()

	if _, err := calc.Calculate(big.NewInt(0), adapter.FeeOptions{MaintainerBPS: 100}); err == nil {
		t.Error("expected error for amount=0")
	}
	if _, err := calc.Calculate(nil, adapter.FeeOptions{MaintainerBPS: 100}); err == nil {
		t.Error("expected error for nil amount")
	}
	if _, err := calc.Calculate(big.NewInt(-1), adapter.FeeOptions{MaintainerBPS: 100}); err == nil {
		t.Error("expected error for negative amount")
	}

	// amount=1: fees all truncate to 0, seller gets 1.
	fb, err := calc.Calculate(big.NewInt(1), adapter.FeeOptions{MaintainerBPS: 100})
	if err != nil {
		t.Fatalf("amount=1: %v", err)
	}
	if fb.SellerProceeds.Int64() != 1 {
		t.Errorf("SellerProceeds for amt=1: got %d, want 1", fb.SellerProceeds.Int64())
	}

	// max uint64 should still work (no overflow with big.Int).
	maxU := new(big.Int).SetUint64(math.MaxUint64)
	fb, err = calc.Calculate(maxU, adapter.FeeOptions{MaintainerBPS: 100})
	if err != nil {
		t.Fatalf("max uint64: %v", err)
	}
	sum := new(big.Int).Add(fb.MaintainerFee, fb.SellerProceeds)
	if sum.Cmp(maxU) != 0 {
		t.Errorf("max uint64 sum mismatch: %s vs %s", sum, maxU)
	}
}

func TestFeeCalculator_Verify(t *testing.T) {
	t.Parallel()
	calc := NewFeeCalculator()
	fb, err := calc.Calculate(big.NewInt(1000), adapter.FeeOptions{MaintainerBPS: 100})
	if err != nil {
		t.Fatalf("Calculate: %v", err)
	}
	tx := &adapter.UnsignedTx{Amount: big.NewInt(1000)}
	if err := calc.Verify(tx, fb); err != nil {
		t.Errorf("Verify happy path: %v", err)
	}
	// Tamper: change seller proceeds
	fb.SellerProceeds = big.NewInt(500)
	if err := calc.Verify(tx, fb); err == nil {
		t.Error("expected verify failure after tampering")
	}
}

func TestBPSMul(t *testing.T) {
	t.Parallel()
	bps := big.NewInt(BPSBase)
	if bpsMul(big.NewInt(10_000), 0, bps).Int64() != 0 {
		t.Error("0 BPS should yield 0")
	}
	if bpsMul(big.NewInt(10_000), 100, bps).Int64() != 100 {
		t.Error("1% of 10000 should be 100")
	}
}

// The breakdown's witness split is the same on every node whatever order the
// attester lookup returned the attesters in: the remainder goes to the
// attester whose name sorts first.
func TestCalculateWitnessSplitIsTheSameInEveryOrder(t *testing.T) {
	want := map[string]int64{"a": 4, "b": 3, "c": 3}
	for _, order := range [][]string{{"a", "b", "c"}, {"b", "c", "a"}, {"c", "a", "b"}, {"c", "b", "a"}} {
		got := splitWitnessFeeEqual(big.NewInt(10), order)
		if len(got) != len(want) {
			t.Fatalf("order %v: %d recipients, want %d", order, len(got), len(want))
		}
		for k, v := range want {
			if got[k] == nil || got[k].Int64() != v {
				t.Errorf("order %v: %s gets %v, want %d", order, k, got[k], v)
			}
		}
	}
}
