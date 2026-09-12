/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

//go:build !js

// Package btc — NeutrinoBalanceProvider is a pure-Go BIP157/158 compact-block-
// filter SPV implementation of witness.ChainBalanceProvider. It lets a witness
// serve BTC balance queries without any sidecar: no Esplora HTTP indexer, no
// bitcoind JSON-RPC, no Electrum server. The witness embeds a P2P Bitcoin
// light client, downloads block headers + compact filters, and fetches only
// the small subset of blocks that match the queried address.
//
// Relative to EsploraBalanceProvider (balance.go) the trade-offs are:
//
//   - Trust model:   Neutrino trusts the heaviest-PoW chain from connected
//                    P2P peers (BIP157 filter-header checkpoints). Esplora
//                    trusts the indexer operator. Neutrino is strictly
//                    stronger.
//   - Footprint:     Neutrino uses ~3-5 GB disk (headers + filters; blocks
//                    are fetched on demand and pruned), ~200-300 MB RAM.
//                    Esplora uses 0 local resources.
//   - Initial sync:  1-6 hours on mainnet before Neutrino can answer any
//                    query. Esplora answers immediately.
//   - Query latency: Neutrino walks filters from birthHeight to tip; for a
//                    narrow window (maintainer-sponsored addresses created
//                    after birthHeight) this is seconds. Esplora is one
//                    HTTP round-trip.
//   - Availability:  Neutrino depends only on the Bitcoin P2P network.
//                    Esplora depends on one HTTP provider.
//
// This file is build-tagged !js because walletdb/bdb (bbolt) and the P2P
// stack do not compile under js/wasm. WASM witnesses fall back to the
// EsploraBalanceProvider in balance.go.
package btc

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/gcs/builder"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/walletdb"
	// Register the bdb (bbolt) walletdb driver.
	_ "github.com/btcsuite/btcwallet/walletdb/bdb"
	"github.com/lightninglabs/neutrino"

	"github.com/bbmumford/plutus/witness"
)

// neutrinoBtcDecimals mirrors btcDecimals from balance.go but is redeclared
// locally under a different name to keep this file fully additive and avoid
// any risk of collision if the original constant is moved.
const neutrinoBtcDecimals uint64 = 8

// neutrinoDBTimeout is the bbolt lock-acquisition timeout used when opening
// the header/filter database.
const neutrinoDBTimeout = 30 * time.Second

// NeutrinoBalanceProvider implements witness.ChainBalanceProvider using an
// embedded BIP157/158 compact-block-filter SPV client. Connects directly to
// Bitcoin P2P peers; no RPC, no HTTP, no sidecar.
//
// Disk: ~3-5 GB steady-state (headers + compact filters; blocks pruned).
// RAM:  ~200-300 MB.
// Initial sync: 1-6 hours on mainnet.
type NeutrinoBalanceProvider struct {
	cs          *neutrino.ChainService
	db          walletdb.DB
	netParams   *chaincfg.Params
	dataDir     string
	birthHeight int32 // earliest block to scan (skip ancient history)

	startMu sync.Mutex
	started bool
}

// NewNeutrinoBalanceProvider initializes the SPV client, opens the header
// database in dataDir/neutrino.db, and prepares a ChainService bound to the
// given network. Call Start(ctx) to begin P2P sync. QueryBalance() will
// return results against whatever chain tip Neutrino has reached — callers
// that need tip-freshness guarantees should gate queries on IsCaughtUp().
//
// Supported network identifiers:
//   - "bitcoin" / "mainnet"  → chaincfg.MainNetParams
//   - "testnet" / "testnet3" → chaincfg.TestNet3Params
//   - "regtest"              → chaincfg.RegressionNetParams
//   - "signet"               → chaincfg.SigNetParams
//
// If peers is empty, Neutrino uses the DNS seeds baked into ChainParams.
func NewNeutrinoBalanceProvider(dataDir, network string, peers []string, birthHeight int32) (*NeutrinoBalanceProvider, error) {
	if dataDir == "" {
		return nil, errors.New("btc/neutrino: dataDir required")
	}

	params, err := neutrinoNetParams(network)
	if err != nil {
		return nil, err
	}

	dbPath := filepath.Join(dataDir, "neutrino.db")
	db, err := openOrCreateNeutrinoDB(dbPath)
	if err != nil {
		return nil, err
	}

	cfg := neutrino.Config{
		DataDir:     dataDir,
		Database:    db,
		ChainParams: *params,
		// Empty ConnectPeers means: use DNS seeds from ChainParams.
		ConnectPeers: peers,
	}

	cs, err := neutrino.NewChainService(cfg)
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("btc/neutrino: create chain service: %w", err)
	}

	return &NeutrinoBalanceProvider{
		cs:          cs,
		db:          db,
		netParams:   params,
		dataDir:     dataDir,
		birthHeight: birthHeight,
	}, nil
}

// neutrinoNetParams resolves a human-friendly network identifier to
// chaincfg.Params. Extracted so tests can exercise it without spinning up a
// ChainService.
func neutrinoNetParams(network string) (*chaincfg.Params, error) {
	switch network {
	case "bitcoin", "mainnet":
		return &chaincfg.MainNetParams, nil
	case "testnet", "testnet3":
		return &chaincfg.TestNet3Params, nil
	case "regtest":
		return &chaincfg.RegressionNetParams, nil
	case "signet":
		return &chaincfg.SigNetParams, nil
	default:
		return nil, fmt.Errorf("btc/neutrino: unsupported network %q", network)
	}
}

// openOrCreateNeutrinoDB opens the bdb-backed walletdb at dbPath, creating it
// if it doesn't yet exist. The bdb driver signature is
// (dbPath, noFreelistSync, timeout). The first flag set to true speeds up
// filter-batch writes; the timeout bounds the blocking bbolt lock.
func openOrCreateNeutrinoDB(dbPath string) (walletdb.DB, error) {
	// Try Create first — returns ErrDbExists if it's already there, in which
	// case Open. This matches the pattern used by LND, btcwallet, and the
	// driver_test.go reference.
	db, err := walletdb.Create("bdb", dbPath, true, neutrinoDBTimeout)
	if err == nil {
		return db, nil
	}
	if !errors.Is(err, walletdb.ErrDbExists) {
		return nil, fmt.Errorf("btc/neutrino: create db %q: %w", dbPath, err)
	}
	db, err = walletdb.Open("bdb", dbPath, true, neutrinoDBTimeout)
	if err != nil {
		return nil, fmt.Errorf("btc/neutrino: open db %q: %w", dbPath, err)
	}
	return db, nil
}

// Start begins P2P sync. Safe to call multiple times; second and subsequent
// calls are no-ops. ctx is passed to ChainService.Start per the Neutrino
// v0.16+ API.
func (p *NeutrinoBalanceProvider) Start(ctx context.Context) error {
	p.startMu.Lock()
	defer p.startMu.Unlock()
	if p.started {
		return nil
	}
	if err := p.cs.Start(ctx); err != nil {
		return fmt.Errorf("btc/neutrino: start chain service: %w", err)
	}
	p.started = true
	return nil
}

// Stop halts the ChainService and closes the header database. Best-effort;
// returns the first non-nil error encountered.
func (p *NeutrinoBalanceProvider) Stop() error {
	p.startMu.Lock()
	defer p.startMu.Unlock()
	var firstErr error
	if p.started {
		if err := p.cs.Stop(); err != nil {
			firstErr = fmt.Errorf("btc/neutrino: stop chain service: %w", err)
		}
		p.started = false
	}
	if p.db != nil {
		if err := p.db.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("btc/neutrino: close db: %w", err)
		}
		p.db = nil
	}
	return firstErr
}

// IsCaughtUp reports whether Neutrino's filter-header tip is within two
// blocks of its block-header tip. Callers that require strict tip freshness
// should gate QueryBalance on this predicate.
func (p *NeutrinoBalanceProvider) IsCaughtUp() bool {
	if p.cs == nil {
		return false
	}
	return p.cs.IsCurrent()
}

// QueryBalance scans the compact filters for blocks >= birthHeight for any
// output paying `addr`, fetches those blocks on demand, and sums unspent
// outputs. Returns a BalanceSnapshot keyed to the current chain tip.
//
// token must be empty or "BTC" — Bitcoin L1 has no ERC-20-style tokens.
func (p *NeutrinoBalanceProvider) QueryBalance(ctx context.Context, addr, token string) (witness.BalanceSnapshot, error) {
	if addr == "" {
		return witness.BalanceSnapshot{}, errors.New("btc/neutrino: address required")
	}
	if token != "" && token != "BTC" {
		return witness.BalanceSnapshot{}, fmt.Errorf("btc/neutrino: tokens not supported on bitcoin (got %q)", token)
	}

	btcAddr, err := btcutil.DecodeAddress(addr, p.netParams)
	if err != nil {
		return witness.BalanceSnapshot{}, fmt.Errorf("btc/neutrino: decode address %q: %w", addr, err)
	}
	if !btcAddr.IsForNet(p.netParams) {
		return witness.BalanceSnapshot{}, fmt.Errorf("btc/neutrino: address %q not valid for network %q", addr, p.netParams.Name)
	}

	pkScript, err := txscript.PayToAddrScript(btcAddr)
	if err != nil {
		return witness.BalanceSnapshot{}, fmt.Errorf("btc/neutrino: build pkScript: %w", err)
	}

	tip, err := p.cs.BestBlock()
	if err != nil {
		return witness.BalanceSnapshot{}, fmt.Errorf("btc/neutrino: get tip: %w", err)
	}

	startHeight := p.birthHeight
	if startHeight < 0 {
		startHeight = 0
	}

	// utxos tracks currently-unspent outputs paying this address:
	// key "txid:vout" → satoshi value. When we later see an input spending
	// one of these outpoints we delete it.
	type outpointKey struct {
		txid string
		vout uint32
	}
	utxos := make(map[outpointKey]int64)

	for h := startHeight; h <= tip.Height; h++ {
		if err := ctx.Err(); err != nil {
			return witness.BalanceSnapshot{}, err
		}

		blockHash, err := p.cs.GetBlockHash(int64(h))
		if err != nil {
			return witness.BalanceSnapshot{}, fmt.Errorf("btc/neutrino: get block hash at %d: %w", h, err)
		}

		filter, err := p.cs.GetCFilter(*blockHash, wire.GCSFilterRegular)
		if err != nil {
			return witness.BalanceSnapshot{}, fmt.Errorf("btc/neutrino: get cfilter for %d: %w", h, err)
		}
		if filter == nil {
			continue
		}

		// BIP158 filter key is derived from the block hash.
		key := builder.DeriveKey(blockHash)
		matched, err := filter.Match(key, pkScript)
		if err != nil {
			// Corrupt filter for this block; skip rather than abort the
			// whole scan. Neutrino will re-fetch on retry.
			continue
		}
		if !matched {
			continue
		}

		// Filter matched — fetch the full block and walk tx I/O.
		block, err := p.cs.GetBlock(*blockHash)
		if err != nil {
			return witness.BalanceSnapshot{}, fmt.Errorf("btc/neutrino: get block %d: %w", h, err)
		}
		if block == nil {
			continue
		}

		for _, tx := range block.MsgBlock().Transactions {
			// Inputs — each may spend one of our tracked UTXOs.
			for _, in := range tx.TxIn {
				prev := outpointKey{
					txid: in.PreviousOutPoint.Hash.String(),
					vout: in.PreviousOutPoint.Index,
				}
				delete(utxos, prev)
			}
			// Outputs — credit any that pay our pkScript.
			txHash := tx.TxHash().String()
			for vout, out := range tx.TxOut {
				if !pkScriptEqual(out.PkScript, pkScript) {
					continue
				}
				utxos[outpointKey{txid: txHash, vout: uint32(vout)}] = out.Value
			}
		}
	}

	balance := big.NewInt(0)
	for _, v := range utxos {
		balance.Add(balance, big.NewInt(v))
	}

	return witness.BalanceSnapshot{
		Balance:     balance,
		Decimals:    neutrinoBtcDecimals,
		BlockHash:   tip.Hash.String(),
		BlockNumber: uint64(tip.Height),
		Timestamp:   time.Now().UTC(),
	}, nil
}

// pkScriptEqual does a byte-for-byte compare. Split out so tests can drive
// it independently of DecodeAddress/PayToAddrScript round-trips.
func pkScriptEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
