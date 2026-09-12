/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package evm

// BSCBUSDAdapter is a thin backward-compatible alias for *EVMAdapter
// configured for BUSD on BNB Smart Chain.
type BSCBUSDAdapter = EVMAdapter

// NewBSCBUSDAdapter creates a BSC BUSD adapter from chains.json.
func NewBSCBUSDAdapter(transport MeshTransport, prcAddr string) (*BSCBUSDAdapter, error) {
	return newAdapterFor(transport, "bsc", "BUSD", prcAddr)
}
