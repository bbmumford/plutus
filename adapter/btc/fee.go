/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package btc

import (
	"context"
	"fmt"
	"math/big"
)

// FeeLevel represents the urgency of a transaction.
type FeeLevel int

const (
	// FeeLow targets confirmation within ~6 blocks (~60 minutes).
	FeeLow FeeLevel = iota
	// FeeMedium targets confirmation within ~3 blocks (~30 minutes).
	FeeMedium
	// FeeHigh targets confirmation within the next block (~10 minutes).
	FeeHigh
)

// FeeEstimate contains a fee rate recommendation.
type FeeEstimate struct {
	// SatPerVByte is the recommended fee rate in satoshis per virtual byte.
	SatPerVByte float64
	// ConfTarget is the target number of blocks for confirmation.
	ConfTarget uint32
	// Level is the fee urgency level.
	Level FeeLevel
}

// BTCFeeEstimator estimates Bitcoin transaction fees by querying the network
// via the witness mesh.
type BTCFeeEstimator struct {
	client *BTCClient

	// MinFeeRate is the absolute minimum fee rate in sat/vbyte.
	// Default: 1.0 (Bitcoin's relay minimum).
	MinFeeRate float64

	// MaxFeeRate is the maximum fee rate cap in sat/vbyte.
	// Default: 500 sat/vbyte.
	MaxFeeRate float64
}

// NewBTCFeeEstimator creates a new fee estimator.
func NewBTCFeeEstimator(client *BTCClient) (*BTCFeeEstimator, error) {
	if client == nil {
		return nil, fmt.Errorf("btc/fee: client is nil")
	}
	return &BTCFeeEstimator{
		client:     client,
		MinFeeRate: 1.0,
		MaxFeeRate: 500.0,
	}, nil
}

// Estimate returns the recommended fee rate for the given urgency level.
func (e *BTCFeeEstimator) Estimate(ctx context.Context, level FeeLevel) (*FeeEstimate, error) {
	confTarget := levelToConfTarget(level)

	satPerVByte, err := e.client.EstimateSmartFee(ctx, confTarget)
	if err != nil {
		return nil, fmt.Errorf("btc/fee: estimate: %w", err)
	}

	// Clamp to bounds.
	satPerVByte = e.clamp(satPerVByte)

	return &FeeEstimate{
		SatPerVByte: satPerVByte,
		ConfTarget:  confTarget,
		Level:       level,
	}, nil
}

// EstimateAll returns fee estimates for all urgency levels.
func (e *BTCFeeEstimator) EstimateAll(ctx context.Context) (map[FeeLevel]*FeeEstimate, error) {
	result := make(map[FeeLevel]*FeeEstimate)

	for _, level := range []FeeLevel{FeeLow, FeeMedium, FeeHigh} {
		est, err := e.Estimate(ctx, level)
		if err != nil {
			return nil, err
		}
		result[level] = est
	}

	return result, nil
}

// EstimateTxFee estimates the total fee for a transaction with known
// input/output counts at the given fee level.
func (e *BTCFeeEstimator) EstimateTxFee(ctx context.Context, numInputs, numOutputs int, level FeeLevel) (*big.Int, error) {
	est, err := e.Estimate(ctx, level)
	if err != nil {
		return nil, err
	}

	vsize := EstimateTxVSize(numInputs, numOutputs)
	feeSat := int64(float64(vsize) * est.SatPerVByte)

	return big.NewInt(feeSat), nil
}

// EstimateTxVSize estimates the virtual size of a transaction.
// Assumes P2WSH inputs and P2WPKH outputs.
func EstimateTxVSize(numInputs, numOutputs int) int {
	const (
		txOverhead   = 11  // version + locktime + segwit marker + counts
		p2wshInput   = 41  // outpoint + sequence + witness discount
		p2wpkhOutput = 31  // value + scriptPubKey
	)
	return txOverhead + numInputs*p2wshInput + numOutputs*p2wpkhOutput
}

// clamp ensures the fee rate is within configured bounds.
func (e *BTCFeeEstimator) clamp(rate float64) float64 {
	if rate < e.MinFeeRate {
		return e.MinFeeRate
	}
	if rate > e.MaxFeeRate {
		return e.MaxFeeRate
	}
	return rate
}

// levelToConfTarget maps a FeeLevel to a Bitcoin confirmation block target.
func levelToConfTarget(level FeeLevel) uint32 {
	switch level {
	case FeeHigh:
		return 1
	case FeeMedium:
		return 3
	case FeeLow:
		return 6
	default:
		return 6
	}
}
