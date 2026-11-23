/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/bbmumford/plutus/witness"
)

// MultiRPCBalanceProvider queries N upstream RPC endpoints in parallel and
// returns a balance snapshot only when at least K of them agree on the exact
// same (balance, block_number) pair.
//
// This is "RPC consensus" — it does not eliminate trust in chain providers but
// it raises the collusion bar: any K-1 providers being wrong or offline is
// tolerated. With 5 endpoints operated by different parties (LlamaRPC, Ankr,
// publicnode, dRPC, the chain's official RPC) and quorum=3, it is economically
// and legally implausible for an attacker to lie to a witness.
//
// See _OTHER/mercury/portal-network-roadmap.md for the future migration path
// to fully trustless proofs via the Ethereum Portal Network.
//
// A MultiRPCBalanceProvider is itself a witness.ChainBalanceProvider — it
// plugs in wherever an EVMBalanceProvider does, and is opt-in via the
// --evm-balance-mode=multi flag on mercury-node.
type MultiRPCBalanceProvider struct {
	providers []*EVMBalanceProvider
	names     []string
	quorum    int
	timeout   time.Duration
	label     string
}

// RPCEndpoint describes one upstream JSON-RPC endpoint. Transport is supplied
// by the caller so that adapter/evm need not import net/http (keeping the
// package WASM-clean); mercury-node wraps each URL in its local
// httpRPCTransport and passes them in.
type RPCEndpoint struct {
	// Name is a short human-readable label (llamarpc, ankr, publicnode...)
	// used purely in diagnostic/error messages. Must be unique within one
	// MultiRPCBalanceProvider.
	Name string

	// Transport is the MeshTransport implementation that will carry JSON-RPC
	// calls for this endpoint. For direct HTTPS RPCs, mercury-node supplies a
	// simple http.Client wrapper; for witness-mesh calls, supply the mesh
	// transport.
	Transport MeshTransport

	// ChainID is passed through to EVMClient (e.g. "polygon", "ethereum").
	// Must match the ChainSpec.Name the verifier registers the provider under.
	ChainID string

	// NativeDecimals is the number of decimals the chain's native asset uses.
	// Zero is treated as 18 (the default for every EVM chain we ship with).
	NativeDecimals uint64
}

// RPCEndpointSpec is a serialisable-ish tuple of the fields that do not
// involve a live transport. It exists so that default-endpoint helpers can
// ship a neutral list of (name, URL) pairs without forcing adapter/evm to
// import a specific HTTP implementation — callers compose these into
// RPCEndpoint values at startup.
type RPCEndpointSpec struct {
	Name    string
	RPCURL  string
	ChainID string // canonical chain name, e.g. "polygon"
}

// NewMultiRPCBalanceProvider builds a cross-checking balance provider over the
// given endpoints. quorum must be in [1, len(endpoints)]; a strict majority
// (ceil(N/2)+1) is recommended — with 5 endpoints choose 3. timeout caps the
// total wall-clock a single QueryBalance call may take before reporting "no
// quorum" to the caller; individual provider calls inherit this context.
//
// The label argument is stamped into error messages for observability so
// multiple MultiRPC instances on one witness (e.g. one per chain) are
// distinguishable in logs.
func NewMultiRPCBalanceProvider(endpoints []RPCEndpoint, quorum int, timeout time.Duration, label string) (*MultiRPCBalanceProvider, error) {
	if len(endpoints) == 0 {
		return nil, errors.New("evm/multi_rpc_balance: no endpoints supplied")
	}
	if quorum < 1 || quorum > len(endpoints) {
		return nil, fmt.Errorf("evm/multi_rpc_balance: invalid quorum %d for %d endpoints", quorum, len(endpoints))
	}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	// Dedup names so error messages stay useful.
	seen := make(map[string]struct{}, len(endpoints))
	providers := make([]*EVMBalanceProvider, len(endpoints))
	names := make([]string, len(endpoints))
	for i, ep := range endpoints {
		if ep.Transport == nil {
			return nil, fmt.Errorf("evm/multi_rpc_balance: endpoint %q has nil transport", ep.Name)
		}
		if ep.ChainID == "" {
			return nil, fmt.Errorf("evm/multi_rpc_balance: endpoint %q has empty chainID", ep.Name)
		}
		if _, dup := seen[ep.Name]; dup {
			return nil, fmt.Errorf("evm/multi_rpc_balance: duplicate endpoint name %q", ep.Name)
		}
		seen[ep.Name] = struct{}{}

		client, err := NewEVMClient(ep.Transport, ep.ChainID)
		if err != nil {
			return nil, fmt.Errorf("evm/multi_rpc_balance: construct client for %q: %w", ep.Name, err)
		}
		p, err := NewEVMBalanceProvider(client, ep.NativeDecimals)
		if err != nil {
			return nil, fmt.Errorf("evm/multi_rpc_balance: construct provider for %q: %w", ep.Name, err)
		}
		providers[i] = p
		names[i] = ep.Name
	}

	return &MultiRPCBalanceProvider{
		providers: providers,
		names:     names,
		quorum:    quorum,
		timeout:   timeout,
		label:     label,
	}, nil
}

// multiRPCResult is one goroutine's contribution to QueryBalance.
type multiRPCResult struct {
	snap witness.BalanceSnapshot
	err  error
	idx  int
}

// QueryBalance fans out the (addr, token) query to every configured provider
// in parallel, buckets responses by (balance_hex, block_number), and returns
// the first bucket to reach quorum. If no bucket reaches quorum before the
// timeout or all goroutines complete, it returns a detailed error including
// per-provider failures and the largest-agreeing bucket count (useful for
// operator alerting — a 2/5 top bucket when you asked for 3 says you had a
// real disagreement, not just downed endpoints).
func (m *MultiRPCBalanceProvider) QueryBalance(ctx context.Context, addr, token string) (witness.BalanceSnapshot, error) {
	if addr == "" {
		return witness.BalanceSnapshot{}, errors.New("evm/multi_rpc_balance: address is empty")
	}

	queryCtx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	results := make(chan multiRPCResult, len(m.providers))
	var wg sync.WaitGroup

	for i, p := range m.providers {
		wg.Add(1)
		go func(i int, p *EVMBalanceProvider) {
			defer wg.Done()
			snap, err := p.QueryBalance(queryCtx, addr, token)
			select {
			case results <- multiRPCResult{snap: snap, err: err, idx: i}:
			case <-queryCtx.Done():
			}
		}(i, p)
	}

	// Close results only once every worker has finished so we don't deadlock
	// the collection loop on a channel closed mid-drain.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Bucket key: exact (balance, block) tuple. Balance is serialised as
	// lowercase hex (no "0x" prefix) to avoid big.Int comparison quirks and
	// match the bucket strategy the witness-side BalanceVerifier uses.
	type bucketKey struct {
		balanceHex string
		block      uint64
	}
	buckets := map[bucketKey]int{}
	var snapshots []witness.BalanceSnapshot
	var errs []error
	responded := 0

	for r := range results {
		if r.err != nil {
			errs = append(errs, fmt.Errorf("provider %s: %w", m.nameFor(r.idx), r.err))
			continue
		}
		bal := r.snap.Balance
		if bal == nil {
			bal = new(big.Int)
		}
		k := bucketKey{balanceHex: bal.Text(16), block: r.snap.BlockNumber}
		buckets[k]++
		snapshots = append(snapshots, r.snap)
		responded++

		if buckets[k] >= m.quorum {
			// Quorum reached — cancel the rest so we don't pay for their
			// latency on the calling path.
			cancel()
			return findMultiRPCSnapshot(snapshots, k.balanceHex, k.block), nil
		}
	}

	// No bucket reached quorum — include the best-effort disagreement report.
	bestCount := 0
	for _, n := range buckets {
		if n > bestCount {
			bestCount = n
		}
	}
	labelPrefix := ""
	if m.label != "" {
		labelPrefix = m.label + ": "
	}
	return witness.BalanceSnapshot{}, fmt.Errorf(
		"%sno quorum: %d of %d providers responded, largest agreeing bucket=%d, need %d; errors=%v",
		labelPrefix, responded, len(m.providers), bestCount, m.quorum, errs,
	)
}

// nameFor returns the configured label for provider index i, or a numeric
// placeholder when the index is out of range (should not happen; defensive).
func (m *MultiRPCBalanceProvider) nameFor(i int) string {
	if i < 0 || i >= len(m.names) {
		return fmt.Sprintf("#%d", i)
	}
	return m.names[i]
}

// Quorum returns the K threshold this provider was constructed with. Exposed
// for metrics/logging; not used on the query path.
func (m *MultiRPCBalanceProvider) Quorum() int { return m.quorum }

// EndpointCount returns the N total configured endpoints. Exposed for
// metrics/logging.
func (m *MultiRPCBalanceProvider) EndpointCount() int { return len(m.providers) }

// findMultiRPCSnapshot returns the first snapshot in snaps whose balance and
// block match the winning bucket key. The snapshot is the one we return to
// the caller — since every snapshot in the bucket is definitionally equal on
// the fields that matter, which one we pick is only relevant for Timestamp
// (we use the earliest observed, which happens to be whatever arrived first).
func findMultiRPCSnapshot(snaps []witness.BalanceSnapshot, balanceHex string, block uint64) witness.BalanceSnapshot {
	for _, s := range snaps {
		bal := s.Balance
		if bal == nil {
			bal = new(big.Int)
		}
		if bal.Text(16) == balanceHex && s.BlockNumber == block {
			return s
		}
	}
	return witness.BalanceSnapshot{}
}

// -----------------------------------------------------------------------------
// Default endpoint lists
//
// These return the public RPC URLs we ship with. Operators are encouraged to
// override via the mercury-node flags or a chains overlay — the defaults are
// the starting set for a zero-config balance witness.
//
// Every URL below is HTTPS, rate-limited by its operator, and free-tier
// accessible. None require API keys. Update with care: changing these changes
// the implicit trust anchors of any MultiRPC witness running the defaults.
// -----------------------------------------------------------------------------

// DefaultPolygonEndpoints returns the stock 5-of-N endpoint list for Polygon
// mainnet. Chain ID is passed through as "polygon" (matches chains.json).
func DefaultPolygonEndpoints() []RPCEndpointSpec {
	return []RPCEndpointSpec{
		{Name: "llamarpc", RPCURL: "https://polygon.llamarpc.com", ChainID: "polygon"},
		{Name: "ankr", RPCURL: "https://rpc.ankr.com/polygon", ChainID: "polygon"},
		{Name: "publicnode", RPCURL: "https://polygon-bor-rpc.publicnode.com", ChainID: "polygon"},
		{Name: "drpc", RPCURL: "https://polygon.drpc.org", ChainID: "polygon"},
		{Name: "official", RPCURL: "https://polygon-rpc.com", ChainID: "polygon"},
	}
}

// DefaultEthereumEndpoints returns the stock endpoint list for Ethereum
// mainnet.
func DefaultEthereumEndpoints() []RPCEndpointSpec {
	return []RPCEndpointSpec{
		{Name: "llamarpc", RPCURL: "https://eth.llamarpc.com", ChainID: "ethereum"},
		{Name: "ankr", RPCURL: "https://rpc.ankr.com/eth", ChainID: "ethereum"},
		{Name: "publicnode", RPCURL: "https://ethereum-rpc.publicnode.com", ChainID: "ethereum"},
		{Name: "drpc", RPCURL: "https://eth.drpc.org", ChainID: "ethereum"},
		{Name: "cloudflare", RPCURL: "https://cloudflare-eth.com", ChainID: "ethereum"},
	}
}

// DefaultArbitrumEndpoints returns the stock endpoint list for Arbitrum One.
func DefaultArbitrumEndpoints() []RPCEndpointSpec {
	return []RPCEndpointSpec{
		{Name: "llamarpc", RPCURL: "https://arbitrum.llamarpc.com", ChainID: "arbitrum"},
		{Name: "ankr", RPCURL: "https://rpc.ankr.com/arbitrum", ChainID: "arbitrum"},
		{Name: "publicnode", RPCURL: "https://arbitrum-one-rpc.publicnode.com", ChainID: "arbitrum"},
		{Name: "drpc", RPCURL: "https://arbitrum.drpc.org", ChainID: "arbitrum"},
		{Name: "official", RPCURL: "https://arb1.arbitrum.io/rpc", ChainID: "arbitrum"},
	}
}

// DefaultBSCEndpoints returns the stock endpoint list for Binance Smart Chain.
func DefaultBSCEndpoints() []RPCEndpointSpec {
	return []RPCEndpointSpec{
		{Name: "llamarpc", RPCURL: "https://binance.llamarpc.com", ChainID: "bsc"},
		{Name: "ankr", RPCURL: "https://rpc.ankr.com/bsc", ChainID: "bsc"},
		{Name: "publicnode", RPCURL: "https://bsc-rpc.publicnode.com", ChainID: "bsc"},
		{Name: "drpc", RPCURL: "https://bsc.drpc.org", ChainID: "bsc"},
		{Name: "official", RPCURL: "https://bsc-dataseed.bnbchain.org", ChainID: "bsc"},
	}
}

// DefaultEndpointsFor returns the stock endpoint list for the named chain, or
// nil if the chain has no defaults bundled. Chain names are lowercase, matching
// ChainSpec.Name in chains.json.
func DefaultEndpointsFor(chainID string) []RPCEndpointSpec {
	switch chainID {
	case "polygon":
		return DefaultPolygonEndpoints()
	case "ethereum":
		return DefaultEthereumEndpoints()
	case "arbitrum":
		return DefaultArbitrumEndpoints()
	case "bsc":
		return DefaultBSCEndpoints()
	default:
		return nil
	}
}
