/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package evm

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
)

// GasEstimator handles EIP-1559 gas price estimation and gas limit calculation.
// It queries the network via the EVMClient (through the witness mesh) to
// determine current base fees and appropriate priority fees.
type GasEstimator struct {
	client *EVMClient

	// Configurable multiplier for gas limit safety margin (1.2 = 20% buffer).
	GasLimitMultiplier float64

	// MaxPriorityFeePerGas default in wei if the network doesn't support
	// eth_maxPriorityFeePerGas.
	DefaultMaxPriorityFee *big.Int

	// Maximum gas price cap (wei) to prevent runaway fees.
	MaxGasPrice *big.Int
}

// GasSuggestion contains the recommended gas parameters for a transaction.
type GasSuggestion struct {
	// EIP-1559 fields.
	BaseFee              *big.Int // current base fee from the latest block
	MaxPriorityFeePerGas *big.Int // suggested priority fee (tip)
	MaxFeePerGas         *big.Int // baseFee * 2 + maxPriorityFee

	// Legacy field (for chains that don't support EIP-1559).
	GasPrice *big.Int

	// Estimated gas limit for the transaction.
	GasLimit uint64

	// Whether this chain supports EIP-1559.
	EIP1559 bool
}

// NewGasEstimator creates a new gas estimator for the given client.
func NewGasEstimator(client *EVMClient) (*GasEstimator, error) {
	if client == nil {
		return nil, fmt.Errorf("evm/gas: client is nil")
	}
	return &GasEstimator{
		client:                client,
		GasLimitMultiplier:    1.2,
		DefaultMaxPriorityFee: big.NewInt(1_500_000_000), // 1.5 gwei default
		MaxGasPrice:           new(big.Int).Mul(big.NewInt(500), big.NewInt(1_000_000_000)), // 500 gwei cap
	}, nil
}

// EstimateGas estimates the gas limit for a transaction with a safety buffer.
func (g *GasEstimator) EstimateGas(ctx context.Context, from, to string, data []byte, value *big.Int) (uint64, error) {
	rawEstimate, err := g.client.EstimateGas(ctx, from, to, data, value)
	if err != nil {
		return 0, fmt.Errorf("evm/gas: estimate failed: %w", err)
	}

	// Apply safety multiplier.
	buffered := float64(rawEstimate) * g.GasLimitMultiplier
	return uint64(buffered), nil
}

// SuggestGasPrice returns recommended gas parameters for a transaction.
// It attempts EIP-1559 pricing first, falling back to legacy gasPrice.
func (g *GasEstimator) SuggestGasPrice(ctx context.Context) (*GasSuggestion, error) {
	suggestion := &GasSuggestion{}

	// Try to get the base fee from the latest block header.
	baseFee, err := g.getBaseFee(ctx)
	if err == nil && baseFee != nil && baseFee.Sign() > 0 {
		// EIP-1559 supported.
		suggestion.EIP1559 = true
		suggestion.BaseFee = baseFee

		// Get priority fee.
		priorityFee, err := g.getMaxPriorityFee(ctx)
		if err != nil || priorityFee == nil || priorityFee.Sign() <= 0 {
			priorityFee = new(big.Int).Set(g.DefaultMaxPriorityFee)
		}
		suggestion.MaxPriorityFeePerGas = priorityFee

		// MaxFeePerGas = baseFee * 2 + maxPriorityFee
		// This allows for one block's worth of base fee increase.
		maxFee := new(big.Int).Mul(baseFee, big.NewInt(2))
		maxFee.Add(maxFee, priorityFee)

		// Cap at maximum.
		if g.MaxGasPrice != nil && maxFee.Cmp(g.MaxGasPrice) > 0 {
			maxFee = new(big.Int).Set(g.MaxGasPrice)
		}

		suggestion.MaxFeePerGas = maxFee
		suggestion.GasPrice = maxFee // fallback for legacy fields
	} else {
		// Legacy gas pricing.
		suggestion.EIP1559 = false

		gasPrice, err := g.getLegacyGasPrice(ctx)
		if err != nil {
			return nil, fmt.Errorf("evm/gas: failed to get gas price: %w", err)
		}

		// Apply a small buffer to legacy gas price (10%).
		buffered := new(big.Int).Mul(gasPrice, big.NewInt(110))
		buffered.Div(buffered, big.NewInt(100))

		// Cap at maximum.
		if g.MaxGasPrice != nil && buffered.Cmp(g.MaxGasPrice) > 0 {
			buffered = new(big.Int).Set(g.MaxGasPrice)
		}

		suggestion.GasPrice = buffered
	}

	return suggestion, nil
}

// SuggestGasPriceWithEstimate combines gas price suggestion with gas limit estimation.
func (g *GasEstimator) SuggestGasPriceWithEstimate(ctx context.Context, from, to string, data []byte, value *big.Int) (*GasSuggestion, error) {
	suggestion, err := g.SuggestGasPrice(ctx)
	if err != nil {
		return nil, err
	}

	gasLimit, err := g.EstimateGas(ctx, from, to, data, value)
	if err != nil {
		return nil, err
	}
	suggestion.GasLimit = gasLimit

	return suggestion, nil
}

// TotalCostWei returns the maximum transaction cost in wei (gasLimit * maxFeePerGas).
func (s *GasSuggestion) TotalCostWei() *big.Int {
	gasPrice := s.MaxFeePerGas
	if gasPrice == nil {
		gasPrice = s.GasPrice
	}
	if gasPrice == nil {
		return big.NewInt(0)
	}
	return new(big.Int).Mul(gasPrice, big.NewInt(int64(s.GasLimit)))
}

// getBaseFee retrieves the base fee from the latest block.
func (g *GasEstimator) getBaseFee(ctx context.Context) (*big.Int, error) {
	result, err := g.client.call(ctx, "eth_getBlockByNumber", "latest", false)
	if err != nil {
		return nil, err
	}

	var block struct {
		BaseFeePerGas string `json:"baseFeePerGas"`
	}
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, fmt.Errorf("evm/gas: decode block: %w", err)
	}

	if block.BaseFeePerGas == "" {
		return nil, fmt.Errorf("evm/gas: block has no baseFeePerGas (pre-EIP-1559 chain)")
	}

	return decodeHexBigInt(mustMarshalString(block.BaseFeePerGas))
}

// getMaxPriorityFee calls eth_maxPriorityFeePerGas.
func (g *GasEstimator) getMaxPriorityFee(ctx context.Context) (*big.Int, error) {
	result, err := g.client.call(ctx, "eth_maxPriorityFeePerGas")
	if err != nil {
		return nil, err
	}

	return decodeHexBigInt(result)
}

// getLegacyGasPrice calls eth_gasPrice for legacy gas pricing.
func (g *GasEstimator) getLegacyGasPrice(ctx context.Context) (*big.Int, error) {
	result, err := g.client.call(ctx, "eth_gasPrice")
	if err != nil {
		return nil, err
	}

	return decodeHexBigInt(result)
}

// mustMarshalString wraps a string as JSON for decoding.
func mustMarshalString(s string) json.RawMessage {
	b, _ := json.Marshal(s)
	return b
}
