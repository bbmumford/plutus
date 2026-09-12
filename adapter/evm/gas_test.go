/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package evm

import (
	"math/big"
	"testing"
)

func TestGasSuggestion_TotalCostWei(t *testing.T) {
	t.Parallel()
	s := &GasSuggestion{
		MaxFeePerGas: big.NewInt(100_000_000_000), // 100 gwei
		GasLimit:     21000,
	}
	total := s.TotalCostWei()
	want := new(big.Int).Mul(big.NewInt(100_000_000_000), big.NewInt(21000))
	if total.Cmp(want) != 0 {
		t.Errorf("TotalCostWei: got %s, want %s", total, want)
	}
}

func TestGasSuggestion_TotalCostWei_FallbackToGasPrice(t *testing.T) {
	t.Parallel()
	s := &GasSuggestion{
		GasPrice: big.NewInt(50_000_000_000),
		GasLimit: 30000,
	}
	total := s.TotalCostWei()
	want := new(big.Int).Mul(big.NewInt(50_000_000_000), big.NewInt(30000))
	if total.Cmp(want) != 0 {
		t.Errorf("legacy total: got %s, want %s", total, want)
	}
}

func TestGasSuggestion_TotalCostWei_NilPrice(t *testing.T) {
	t.Parallel()
	s := &GasSuggestion{GasLimit: 21000}
	if s.TotalCostWei().Sign() != 0 {
		t.Error("nil gas price should yield 0 total")
	}
}

func TestNewGasEstimator_NilClient(t *testing.T) {
	t.Parallel()
	if _, err := NewGasEstimator(nil); err == nil {
		t.Error("expected error for nil client")
	}
}

// TestEIP1559_MaxFeeComputation verifies the maxFee math outside of RPC:
// maxFee = baseFee * 2 + priorityFee.
func TestEIP1559_MaxFeeComputation(t *testing.T) {
	t.Parallel()
	baseFee := big.NewInt(20_000_000_000) // 20 gwei
	priority := big.NewInt(1_500_000_000) // 1.5 gwei

	maxFee := new(big.Int).Mul(baseFee, big.NewInt(2))
	maxFee.Add(maxFee, priority)

	want := big.NewInt(41_500_000_000) // 2*20 + 1.5 = 41.5 gwei
	if maxFee.Cmp(want) != 0 {
		t.Errorf("maxFee: got %s, want %s", maxFee, want)
	}
}
