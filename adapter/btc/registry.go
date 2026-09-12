/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package btc

import (
	"fmt"

	"github.com/bbmumford/plutus/adapter"
	"github.com/bbmumford/plutus/canonical"
)

// Compile-time assertion: BTCAdapter satisfies adapter.CurrencyAdapter.
var _ adapter.CurrencyAdapter = (*BTCAdapter)(nil)

// RegisterBitcoinAdapters registers the canonical BTC adapters (mainnet +
// testnet) with the given adapter registry. If a descriptor is supplied for
// a network, it's used verbatim (assumes the caller validated its signature);
// otherwise a local descriptor is synthesized.
//
// This mirrors the pattern used by the EVM adapters via adapter.Registry.
// Unlike EVM, the "PRC address" field is set to the canonical maintainer BTC
// address since Bitcoin has no on-chain registry contract.
func RegisterBitcoinAdapters(
	registry *adapter.Registry,
	transport MeshTransport,
	mainnetDesc, testnetDesc *adapter.AdapterDescriptor,
) error {
	if registry == nil {
		return fmt.Errorf("btc: adapter registry is nil")
	}
	if transport == nil {
		return fmt.Errorf("btc: mesh transport is nil")
	}

	// Mainnet.
	mainnetAdapter, err := NewBTCAdapter(BTCAdapterConfig{
		Transport: transport,
		Network:   "mainnet",
	})
	if err != nil {
		return fmt.Errorf("btc: create mainnet adapter: %w", err)
	}
	desc := mainnetDesc
	if desc == nil {
		d := synthesizeDescriptor("bitcoin", canonical.MaintainerBTCAddress)
		desc = &d
	}
	if err := registry.Register(mainnetAdapter, *desc); err != nil {
		return fmt.Errorf("btc: register mainnet adapter: %w", err)
	}

	// Testnet (only register if caller supplied a descriptor — skip by default).
	if testnetDesc != nil {
		testnetAdapter, err := NewBTCAdapter(BTCAdapterConfig{
			Transport: transport,
			Network:   "testnet",
		})
		if err != nil {
			// Testnet failure is non-fatal; maintainer address might only be
			// set for mainnet. Log via return-error so caller decides.
			return fmt.Errorf("btc: create testnet adapter: %w", err)
		}
		if err := registry.Register(testnetAdapter, *testnetDesc); err != nil {
			return fmt.Errorf("btc: register testnet adapter: %w", err)
		}
	}

	return nil
}

// synthesizeDescriptor builds a local (unsigned) descriptor for an adapter.
// Production deployments must supply a real, Platform-Key-signed descriptor
// via the ceremony pipeline.
func synthesizeDescriptor(chainID, maintainerAddr string) adapter.AdapterDescriptor {
	return adapter.AdapterDescriptor{
		ChainID:    chainID,
		Currency:   "BTC",
		Symbol:     "BTC",
		Version:    "v0.1.0-local",
		PRCAddress: maintainerAddr, // BTC uses the maintainer address here.
	}
}

// RegisterBitcoinPayoutBuilder constructs a BTCPayoutBuilder for `network`
// and registers it on the given adapter registry under (chainID, "BTC").
// Callers supply a PoolUTXOSource (Neutrino/full-node/static) and optional
// fee rate; everything else inherits sane defaults.
//
// The payout builder is a separate facility from the CurrencyAdapter: it is
// only needed on nodes that run the witness fee distributor, so we expose
// registration independently rather than folding it into
// RegisterBitcoinAdapters.
func RegisterBitcoinPayoutBuilder(
	registry *adapter.Registry,
	network string,
	src PoolUTXOSource,
	feeRateSatPerVByte float64,
) error {
	if registry == nil {
		return fmt.Errorf("btc: adapter registry is nil")
	}
	builder, err := NewBTCPayoutBuilder(BTCPayoutBuilderConfig{
		Network:            network,
		UTXOSource:         src,
		FeeRateSatPerVByte: feeRateSatPerVByte,
	})
	if err != nil {
		return fmt.Errorf("btc: create payout builder: %w", err)
	}
	// The builder's ChainID() reflects the configured network so we can
	// distinguish mainnet / testnet / regtest registrations on the same
	// registry.
	return registry.RegisterPayoutBuilder(builder.ChainID(), "BTC", builder)
}
