/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

import (
	"fmt"
)

// EthereumUSDCAdapter implements CurrencyAdapter for USDC on Ethereum mainnet.
// It is a thin backward-compatible alias for *EVMAdapter, kept so existing
// call sites (NewEthereumUSDCAdapter, type assertions, etc.) continue to
// compile. All real logic lives in EVMAdapter / chains.json.
type EthereumUSDCAdapter = EVMAdapter

// NewEthereumUSDCAdapter creates an Ethereum USDC adapter by loading the
// chain spec from chains.json and delegating to NewEVMAdapterFromSpec.
func NewEthereumUSDCAdapter(transport MeshTransport, prcAddr string) (*EthereumUSDCAdapter, error) {
	return newAdapterFor(transport, "ethereum", "USDC", prcAddr)
}

// newAdapterFor is the shared helper used by every named constructor. It
// loads the embedded chains.json, selects the matching chain+token, and
// builds a generic EVMAdapter. Overlay files are NOT consulted here; call
// sites that need operator overrides should use LoadChains + NewEVMAdapterFromSpec
// directly.
func newAdapterFor(transport MeshTransport, chainName, symbol, prcAddr string) (*EVMAdapter, error) {
	chains, err := LoadChains("")
	if err != nil {
		return nil, err
	}
	spec, ok := ChainByName(chains, chainName)
	if !ok {
		return nil, fmt.Errorf("evm: chain %q not in chains.json", chainName)
	}
	token, ok := spec.Currency(symbol)
	if !ok {
		return nil, fmt.Errorf("evm/%s: currency %q not configured", chainName, symbol)
	}
	return NewEVMAdapterFromSpec(transport, spec, token, prcAddr)
}
