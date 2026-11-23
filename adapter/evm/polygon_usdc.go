/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

import (
	"math/big"

	"github.com/bbmumford/plutus/adapter"
)

// PolygonUSDCAdapter is a thin backward-compatible alias for *EVMAdapter
// configured for USDC on Polygon.
type PolygonUSDCAdapter = EVMAdapter

// NewPolygonUSDCAdapter creates a Polygon USDC adapter from chains.json.
func NewPolygonUSDCAdapter(transport MeshTransport, prcAddr string) (*PolygonUSDCAdapter, error) {
	return newAdapterFor(transport, "polygon", "USDC", prcAddr)
}

// calculateFeesCommon is shared by the generic EVMAdapter and any callers
// (tests) that need a chain-agnostic fee breakdown. It lives in this file for
// historical reasons; do not move without updating imports.
func calculateFeesCommon(amount *big.Int, opts adapter.FeeOptions) adapter.FeeBreakdown {
	if amount == nil || amount.Sign() <= 0 {
		return adapter.FeeBreakdown{Total: big.NewInt(0)}
	}

	bpsBase := big.NewInt(10000)
	base := new(big.Int).Set(amount)

	maintainerFee := bpsMul(base, opts.MaintainerBPS, bpsBase)

	var witnessFee *big.Int
	if opts.HasWitness {
		witnessFee = bpsMul(base, opts.WitnessBPS, bpsBase)
	} else {
		witnessFee = new(big.Int)
	}

	var serviceFee *big.Int
	if opts.HasServiceProvider {
		serviceFee = bpsMul(base, opts.ServiceProviderBPS, bpsBase)
	} else {
		serviceFee = new(big.Int)
	}

	var arbitratorFee *big.Int
	if opts.HasDispute {
		arbitratorFee = bpsMul(base, opts.ArbitratorBPS, bpsBase)
	} else {
		arbitratorFee = new(big.Int)
	}

	totalFees := new(big.Int)
	totalFees.Add(totalFees, maintainerFee)
	totalFees.Add(totalFees, witnessFee)
	totalFees.Add(totalFees, serviceFee)
	totalFees.Add(totalFees, arbitratorFee)

	sellerProceeds := new(big.Int).Sub(base, totalFees)
	if sellerProceeds.Sign() < 0 {
		sellerProceeds = new(big.Int)
	}

	return adapter.FeeBreakdown{
		MaintainerFee:      maintainerFee,
		ServiceProviderFee: serviceFee,
		ArbitratorFee:      arbitratorFee,
		WitnessFee:         witnessFee,
		SellerProceeds:     sellerProceeds,
		Total:              new(big.Int).Set(amount),
	}
}

// bpsMul computes floor(amount * bpsVal / bpsBase) using big.Int.
func bpsMul(amount *big.Int, bpsVal uint32, bpsBase *big.Int) *big.Int {
	if bpsVal == 0 {
		return new(big.Int)
	}
	result := new(big.Int).Mul(amount, big.NewInt(int64(bpsVal)))
	result.Div(result, bpsBase)
	return result
}
