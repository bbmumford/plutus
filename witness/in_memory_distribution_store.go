/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

// NewInMemoryDistributionStore returns a DistributionStore backed by an
// in-process map. Safe for concurrent use. Intended for tests, WASM, and
// deployments that haven't yet wired the Ledger-backed persistent store.
//
// The underlying implementation is the same one NewWitnessFeeDistributor
// installs by default when cfg.Store is nil — exporting it here lets callers
// pass an explicit store to FeeDistributorConfig.Store (for example, so the
// mercury-node can share a single store across ticker + admin API handlers).
func NewInMemoryDistributionStore() DistributionStore {
	return newMemDistributionStore()
}
