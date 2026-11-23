/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

// BSCBUSDAdapter is a thin backward-compatible alias for *EVMAdapter
// configured for BUSD on BNB Smart Chain.
type BSCBUSDAdapter = EVMAdapter

// NewBSCBUSDAdapter creates a BSC BUSD adapter from chains.json.
func NewBSCBUSDAdapter(transport MeshTransport, prcAddr string) (*BSCBUSDAdapter, error) {
	return newAdapterFor(transport, "bsc", "BUSD", prcAddr)
}
