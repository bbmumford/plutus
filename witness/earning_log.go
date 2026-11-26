/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/bbmumford/plutus/adapter"
)

// EarningLog is a durable record of witness fee earnings per settled order. It
// satisfies AttestationSource so it can be plugged directly into
// WitnessFeeDistributor as the read side of per-order settlement fees.
//
// Its rows live in the witness journal store, the SQLite file
// <dir>/witness.db stamped as a billing witness journal (see openJournal),
// which a PersistentDistributionStore on the same directory shares. Each
// EarningLogEntry is one row (big.Int amounts as decimal strings, so values
// past int64 keep their precision); a Record's rows commit in one
// transaction, and CollectEarnings reads only its window, through the
// settledAt index.
type EarningLog struct {
	dir string

	mu      sync.Mutex
	journal *journalDB // nil once the log is closed
}

// EarningLogEntry is the stored form of a single EarningRecord. Amount is kept
// as a decimal string so we don't lose precision for values that overflow
// int64 (common on EVM chains where fees are denominated in wei). Its JSON
// form is the line format of the earnings.log journals NewEarningLog takes in.
type EarningLogEntry struct {
	OrderID       string    `json:"orderId"`
	ChainID       string    `json:"chainId"`
	Currency      string    `json:"currency"`
	WitnessPubKey string    `json:"witnessPubkey"`
	Amount        string    `json:"amount"` // decimal string
	AttestationID []byte    `json:"attestationId,omitempty"`
	SettledAt     time.Time `json:"settledAt"`
}

// earningsJournal is the JSON-lines journal an EarningLog kept in its
// directory before the journal store; NewEarningLog takes it in once.
const earningsJournal = "earnings.log"

// NewEarningLog opens (or creates) the earning log in dir. The directory is
// created if it does not exist, and reopening keeps every record written
// before. An earnings.log journal already in dir is taken into the store once
// and left on disk.
func NewEarningLog(dir string) (*EarningLog, error) {
	return openEarningLog(dir, earningsJournal)
}

// OpenJournals opens dir's witness journal store once and returns the
// earning log and the distribution store kept in it. The JSON-lines journals
// a node kept under dir before the store (earnings/earnings.log and
// distributions/distribution.log) are taken in once and left on disk. Close
// both; the file closes with the second.
func OpenJournals(dir string) (*EarningLog, *PersistentDistributionStore, error) {
	el, err := openEarningLog(dir, filepath.Join("earnings", earningsJournal))
	if err != nil {
		return nil, nil, err
	}
	ds, err := openDistributionStore(dir, filepath.Join("distributions", distributionJournal))
	if err != nil {
		_ = el.Close() // the distribution store's error is the one returned
		return nil, nil, err
	}
	return el, ds, nil
}

// openEarningLog opens the earning log in dir and takes in the earnings.log
// journal at dir/legacy (legacy is relative to dir).
func openEarningLog(dir, legacy string) (*EarningLog, error) {
	if dir == "" {
		return nil, errors.New("witness/earning_log: dir is empty")
	}
	ctx := context.Background()
	j, err := openJournal(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("witness/earning_log: %w", err)
	}
	if err := j.importEarningsJournal(ctx, legacy, filepath.Join(dir, legacy)); err != nil {
		_ = j.release() // the import's error is the one returned
		return nil, fmt.Errorf("witness/earning_log: take in %s: %w", legacy, err)
	}
	return &EarningLog{dir: dir, journal: j}, nil
}

// Record flattens a FeeBreakdown for a single order into one EarningLogEntry
// per witness (keyed by hex pubkey in breakdown.WitnessFees) and stores them
// in one transaction. If breakdown.WitnessFees is empty or nil, Record is a
// no-op — the aggregate WitnessFee is payable to a single tx witness and there
// is nothing to distribute pro-rata.
//
// chainID and currency scope the record to a (chain, asset) pair so the
// distributor can group correctly downstream. They are not present on
// FeeBreakdown itself, so callers (typically settle.Executor) must supply
// them alongside the breakdown.
//
// The AttestationID on every entry is derived from the FeeBreakdown's
// deterministic serialisation (see feeBreakdownAttestationID): the
// distributor uses AttestationIDs to build the window-level Merkle root
// threaded into UnsignedBatch.AttestationLogRoot, and this ID keeps that root
// non-zero for every recorded settlement.
func (l *EarningLog) Record(
	ctx context.Context,
	orderID string,
	chainID string,
	currency string,
	at time.Time,
	breakdown adapter.FeeBreakdown,
) error {
	if l == nil {
		return errors.New("witness/earning_log: nil log")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if orderID == "" {
		return errors.New("witness/earning_log: order id is empty")
	}
	if chainID == "" {
		return errors.New("witness/earning_log: chain id is empty")
	}
	if len(breakdown.WitnessFees) == 0 {
		// Nothing to distribute pro-rata.
		return nil
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}

	// Entries go in sorted by hex key, so a settlement's rows are stored in
	// one deterministic order.
	keys := make([]string, 0, len(breakdown.WitnessFees))
	for k := range breakdown.WitnessFees {
		keys = append(keys, k)
	}
	sortStrings(keys)

	attestationID := feeBreakdownAttestationID(orderID, chainID, currency, breakdown)

	entries := make([]EarningLogEntry, 0, len(keys))
	for _, witHex := range keys {
		amt := breakdown.WitnessFees[witHex]
		if amt == nil || amt.Sign() <= 0 {
			continue
		}
		entries = append(entries, EarningLogEntry{
			OrderID:       orderID,
			ChainID:       chainID,
			Currency:      currency,
			WitnessPubKey: witHex,
			Amount:        amt.String(),
			AttestationID: attestationID,
			SettledAt:     at.UTC(),
		})
	}
	if len(entries) == 0 {
		return nil
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.journal == nil {
		return errors.New("witness/earning_log: log is closed")
	}
	if err := l.journal.insertEarnings(ctx, entries); err != nil {
		return fmt.Errorf("witness/earning_log: write: %w", err)
	}
	return nil
}

// CollectEarnings implements AttestationSource. It reads the records settled
// in [start, end) and groups them by (chainID, currency, hex(pubkey)),
// summing Amount.
//
// AttestationID is the earliest-settled matching entry's (may be empty). OrderID and
// SettledAt on the returned record reference the most recent contributing
// entry, which is sufficient for audit since the individual per-order entries
// stay in the store.
func (l *EarningLog) CollectEarnings(
	ctx context.Context,
	start, end time.Time,
) ([]EarningRecord, error) {
	if l == nil {
		return nil, errors.New("witness/earning_log: nil log")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if end.Before(start) {
		return nil, fmt.Errorf("witness/earning_log: end %s before start %s", end, start)
	}

	l.mu.Lock()
	j := l.journal
	l.mu.Unlock()
	if j == nil {
		return nil, errors.New("witness/earning_log: log is closed")
	}
	entries, err := j.earningsIn(ctx, start, end)
	if err != nil {
		return nil, fmt.Errorf("witness/earning_log: read: %w", err)
	}

	type groupKey struct {
		chainID  string
		currency string
		witHex   string
	}
	type groupVal struct {
		amount        *big.Int
		attestations  [][]byte
		lastOrderID   string
		lastSettledAt time.Time
	}
	groups := make(map[groupKey]*groupVal)
	for _, entry := range entries {
		amt, ok := new(big.Int).SetString(entry.Amount, 10)
		if !ok {
			return nil, fmt.Errorf("witness/earning_log: invalid amount %q", entry.Amount)
		}
		gk := groupKey{
			chainID:  entry.ChainID,
			currency: entry.Currency,
			witHex:   entry.WitnessPubKey,
		}
		g, ok := groups[gk]
		if !ok {
			g = &groupVal{amount: new(big.Int)}
			groups[gk] = g
		}
		g.amount.Add(g.amount, amt)
		if len(entry.AttestationID) > 0 {
			g.attestations = append(g.attestations, entry.AttestationID)
		}
		if entry.SettledAt.After(g.lastSettledAt) {
			g.lastSettledAt = entry.SettledAt
			g.lastOrderID = entry.OrderID
		}
	}

	out := make([]EarningRecord, 0, len(groups))
	for gk, g := range groups {
		// Flatten per-entry attestations into a single audit handle. Keeping
		// only the first one matches the EarningRecord schema (one []byte);
		// the full list stays in the store.
		var att []byte
		if len(g.attestations) > 0 {
			att = g.attestations[0]
		}
		out = append(out, EarningRecord{
			OrderID:       g.lastOrderID,
			ChainID:       gk.chainID,
			Currency:      gk.currency,
			WitnessPubKey: gk.witHex,
			Amount:        g.amount,
			AttestationID: att,
			SettledAt:     g.lastSettledAt,
		})
	}
	return out, nil
}

// Close releases the log's hold on the journal store (the store closes when
// its last holder does). Subsequent Record calls return an error. Safe to
// call multiple times.
func (l *EarningLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.journal == nil {
		return nil
	}
	err := l.journal.release()
	l.journal = nil
	return err
}

// sortStrings is a tiny local shim that delegates to sort.Strings. Kept as a
// named helper so Record's call site reads as a domain operation and future
// callers can swap in a specialised sort if the hot path grows teeth.
func sortStrings(s []string) { sort.Strings(s) }

// BuildMerkleRoot returns the keccak256 Merkle root of the AttestationIDs on
// records, using the OpenZeppelin sorted-pair convention so the root is
// compatible with libraries/MerkleProof.sol on-chain verification.
//
// Algorithm (the root lets an attester the distribution left out prove its
// attestation was logged, through the PRC's disputeDistribution gate):
//
//  1. Collect records with non-empty AttestationID, dedup by ID bytes, and
//     hash each ID to a 32-byte leaf via keccak256(AttestationID).
//  2. Sort leaves byte-lexicographically so the root is deterministic across
//     witnesses (map-iteration order and record-collection order must not
//     perturb the output).
//  3. Fold the tree with sorted-pair hashing: parent = keccak256(min || max).
//     Odd tails are promoted unchanged to the next level, matching OpenZeppelin
//     standard-tree semantics.
//
// Returns the zero [32]byte when no leaves are available, which the
// distributor uses as a sentinel for "no attestations this window".
//
// Callers that want to build a proof over the same tree should hash their
// target AttestationID with keccak256 and sort sibling pairs lexicographically
// at each level (the PRC contract's MerkleProof.verify does the sort
// symmetrically, so the proof shape matches OpenZeppelin's JavaScript
// standard-tree helpers without modification).
func BuildMerkleRoot(records []EarningRecord) [32]byte {
	return attestationMerkleRoot(records)
}

// feeBreakdownAttestationID derives a deterministic []byte ID from a
// (orderID, chainID, currency, breakdown) tuple. Callers that do not yet
// surface a canonical attestation ID (the attestation-signature chain wiring
// is a later phase) use this so every earning record carries a non-empty
// AttestationID. The distributor feeds these IDs into the Merkle root
// embedded in UnsignedBatch.AttestationLogRoot; a stable fallback means the
// root is never zero in the common path.
//
// Determinism: we canonicalise the WitnessFees map by sorting its keys
// and encoding as parallel slices so Go map iteration order cannot perturb
// the output.
func feeBreakdownAttestationID(orderID, chainID, currency string, breakdown adapter.FeeBreakdown) []byte {
	// Build a canonical signing payload. We re-use the orderID/chainID/
	// currency that scope the earning log entry plus a sorted slice-form of
	// the WitnessFees map so the same (breakdown, context) always hashes to
	// the same bytes.
	keys := make([]string, 0, len(breakdown.WitnessFees))
	for k := range breakdown.WitnessFees {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	amounts := make([]string, 0, len(keys))
	for _, k := range keys {
		v := breakdown.WitnessFees[k]
		if v == nil {
			amounts = append(amounts, "0")
			continue
		}
		amounts = append(amounts, v.String())
	}
	doc := struct {
		Domain         string   `json:"domain"`
		OrderID        string   `json:"orderId"`
		ChainID        string   `json:"chainId"`
		Currency       string   `json:"currency"`
		WitnessPubs    []string `json:"witnessPubs"`
		WitnessAmounts []string `json:"witnessAmounts"`
	}{
		Domain:         "plutus.witness.earning.fallback.v1",
		OrderID:        orderID,
		ChainID:        chainID,
		Currency:       currency,
		WitnessPubs:    keys,
		WitnessAmounts: amounts,
	}
	b, _ := json.Marshal(&doc)
	h := sha256.Sum256(b)
	return h[:]
}
