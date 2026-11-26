/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/bbmumford/plutus/adapter"
)

// EarningLog is a durable append-only record of witness fee earnings per
// settled order. It satisfies AttestationSource so it can be plugged directly
// into WitnessFeeDistributor as the read side of per-order settlement fees.
//
// Layout on disk is a single JSON-lines file (earnings.log) inside the given
// directory. Each line is one EarningLogEntry (the wire representation of an
// EarningRecord — big.Int is serialised as a decimal string to preserve
// arbitrary precision). Writes fsync on every Record to survive crashes; the
// file is opened O_APPEND so concurrent writes from a single process are
// atomic at OS granularity for typical line sizes (<4KB) on all supported
// filesystems.
//
// CollectEarnings scans the entire file on each call. That is O(N) in the
// number of records ever written, which is acceptable for the current scale
// (one record per settled order per witness per currency — low hundreds per
// day on a busy node). A future optimisation can add a time-indexed sidecar.
type EarningLog struct {
	dir  string
	path string

	mu   sync.Mutex
	file *os.File
	w    *bufio.Writer
}

// EarningLogEntry is the serialised form of a single EarningRecord. Amount is
// kept as a decimal string so the JSON is portable across languages and we
// don't lose precision for values that overflow int64 (common on EVM chains
// where fees are denominated in wei).
type EarningLogEntry struct {
	OrderID       string    `json:"orderId"`
	ChainID       string    `json:"chainId"`
	Currency      string    `json:"currency"`
	WitnessPubKey string    `json:"witnessPubkey"`
	Amount        string    `json:"amount"` // decimal string
	AttestationID []byte    `json:"attestationId,omitempty"`
	SettledAt     time.Time `json:"settledAt"`
}

// NewEarningLog opens (or creates) an EarningLog backed by <dir>/earnings.log.
// The directory is created if it does not exist. The log is opened in append
// mode so re-opening preserves prior records.
func NewEarningLog(dir string) (*EarningLog, error) {
	if dir == "" {
		return nil, errors.New("witness/earning_log: dir is empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("witness/earning_log: mkdir %q: %w", dir, err)
	}
	path := filepath.Join(dir, "earnings.log")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("witness/earning_log: open %q: %w", path, err)
	}
	return &EarningLog{
		dir:  dir,
		path: path,
		file: f,
		w:    bufio.NewWriter(f),
	}, nil
}

// Record flattens a FeeBreakdown for a single order into one EarningLogEntry
// per witness (keyed by hex pubkey in breakdown.WitnessFees) and appends them
// atomically. If breakdown.WitnessFees is empty or nil, Record is a no-op —
// the aggregate WitnessFee is payable to a single tx witness and there is
// nothing to distribute pro-rata.
//
// chainID and currency scope the record to a (chain, asset) pair so the
// distributor can group correctly downstream. They are not present on
// FeeBreakdown itself, so callers (typically settle.Executor) must supply
// them alongside the breakdown.
//
// The AttestationID on every written EarningLogEntry is derived from the
// FeeBreakdown's deterministic serialisation (see feeBreakdownAttestationID)
// when no canonical attestation ID has surfaced through the settle flow
// yet. This is a documented fallback: the distributor uses AttestationIDs
// to build the window-level Merkle root threaded into UnsignedBatch.
// AttestationLogRoot, and the fallback keeps that root non-zero for the
// common case while the attestation-signature chain is still being wired.
// Once settle.Executor passes a real canonical ID through the recorder
// interface, we'll flip to using that instead.
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

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return errors.New("witness/earning_log: log is closed")
	}

	// Encode each witness's entry and append. Write order is deterministic by
	// sorted hex key — not strictly required for correctness (CollectEarnings
	// re-groups) but makes the file diff-friendly for audit.
	keys := make([]string, 0, len(breakdown.WitnessFees))
	for k := range breakdown.WitnessFees {
		keys = append(keys, k)
	}
	sortStrings(keys)

	// Derive a deterministic attestation ID fallback from the breakdown
	// bytes. A caller that holds a canonical attestation ID uses
	// RecordWithAttestationID instead; settle's executor records through
	// Record, and this ID keeps the distributor's AttestationLogRoot
	// non-zero on that path.
	attestationID := feeBreakdownAttestationID(orderID, chainID, currency, breakdown)

	for _, witHex := range keys {
		amt := breakdown.WitnessFees[witHex]
		if amt == nil || amt.Sign() <= 0 {
			continue
		}
		entry := EarningLogEntry{
			OrderID:       orderID,
			ChainID:       chainID,
			Currency:      currency,
			WitnessPubKey: witHex,
			Amount:        amt.String(),
			AttestationID: attestationID,
			SettledAt:     at.UTC(),
		}
		buf, err := json.Marshal(&entry)
		if err != nil {
			return fmt.Errorf("witness/earning_log: marshal: %w", err)
		}
		if _, err := l.w.Write(buf); err != nil {
			return fmt.Errorf("witness/earning_log: write: %w", err)
		}
		if err := l.w.WriteByte('\n'); err != nil {
			return fmt.Errorf("witness/earning_log: write newline: %w", err)
		}
	}
	if err := l.w.Flush(); err != nil {
		return fmt.Errorf("witness/earning_log: flush: %w", err)
	}
	if err := l.file.Sync(); err != nil {
		return fmt.Errorf("witness/earning_log: fsync: %w", err)
	}
	return nil
}

// CollectEarnings implements AttestationSource. It reads the full log, filters
// to records in [start, end) by SettledAt, and groups matching entries by
// (chainID, currency, hex(pubkey)), summing Amount.
//
// AttestationID is accumulated from all matching raw entries (may be empty).
// OrderID and SettledAt on the returned record reference the most recent
// contributing entry, which is sufficient for audit since the individual
// per-order entries remain on disk.
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

	// Serialise against writers so we see a consistent on-disk snapshot.
	l.mu.Lock()
	if l.file == nil {
		l.mu.Unlock()
		return nil, errors.New("witness/earning_log: log is closed")
	}
	// Flush any buffered writer output before reading.
	if err := l.w.Flush(); err != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("witness/earning_log: pre-read flush: %w", err)
	}
	path := l.path
	l.mu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("witness/earning_log: open for read: %w", err)
	}
	defer f.Close()

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

	scanner := bufio.NewScanner(f)
	// Allow long JSON lines (default is 64KB; entries are <1KB but be defensive).
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry EarningLogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return nil, fmt.Errorf("witness/earning_log: unmarshal: %w", err)
		}
		// Time window: [start, end) — inclusive start, exclusive end.
		if entry.SettledAt.Before(start) {
			continue
		}
		if !entry.SettledAt.Before(end) {
			continue
		}
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
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("witness/earning_log: scan: %w", err)
	}

	out := make([]EarningRecord, 0, len(groups))
	for gk, g := range groups {
		// Flatten per-entry attestations into a single audit handle. Keeping
		// only the first one matches the EarningRecord schema (one []byte);
		// the full list stays on disk in the raw log.
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

// Close flushes and closes the underlying file. Subsequent Record calls
// return an error. Safe to call multiple times.
func (l *EarningLog) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	var firstErr error
	if l.w != nil {
		if err := l.w.Flush(); err != nil {
			firstErr = err
		}
	}
	if err := l.file.Sync(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := l.file.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	l.file = nil
	l.w = nil
	return firstErr
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
