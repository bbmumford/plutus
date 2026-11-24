/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

// PolygonUSDCAdapter is a thin backward-compatible alias for *EVMAdapter
// configured for USDC on Polygon.
type PolygonUSDCAdapter = EVMAdapter

// NewPolygonUSDCAdapter creates a Polygon USDC adapter from chains.json.
func NewPolygonUSDCAdapter(transport MeshTransport, prcAddr string) (*PolygonUSDCAdapter, error) {
	return newAdapterFor(transport, "polygon", "USDC", prcAddr)
}
