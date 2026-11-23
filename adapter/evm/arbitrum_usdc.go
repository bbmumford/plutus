/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

// ArbitrumUSDCAdapter is a thin backward-compatible alias for *EVMAdapter
// configured for USDC on Arbitrum One.
type ArbitrumUSDCAdapter = EVMAdapter

// NewArbitrumUSDCAdapter creates an Arbitrum USDC adapter from chains.json.
func NewArbitrumUSDCAdapter(transport MeshTransport, prcAddr string) (*ArbitrumUSDCAdapter, error) {
	return newAdapterFor(transport, "arbitrum", "USDC", prcAddr)
}
