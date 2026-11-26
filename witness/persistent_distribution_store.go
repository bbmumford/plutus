/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// PersistentDistributionStore is a crash-recoverable DistributionStore backed
// by a JSON-lines append log on disk. Each SaveRound appends one line; on
// process start the full file is replayed into an in-memory index so LoadRound
// is O(1) and matches the in-memory store's latency.
//
// Layout: <dir>/distribution.log — each line is a JSON-encoded
// distributionLogEntry. The file is opened O_APPEND so concurrent writers
// within one process see line-atomic semantics on all supported filesystems
// for entries under ~4KB. fsync is called after every append so a crash
// between SaveRound calls never loses an already-returned write.
//
// This mirrors witness.EarningLog's durability pattern — the two logs are
// sized and paced identically (one write per round per chain, low hundreds
// per year at 24h windows) so the same on-disk strategy applies.
//
// The writer holds a mutex serialising SaveRound; LoadRound is lock-free for
// reads (sync.RWMutex read side). The in-memory index is authoritative for
// LoadRound once the file has been replayed; the file is the authoritative
// source across restarts.
type PersistentDistributionStore struct {
	dir  string
	path string
	// backend is the durable primitive this store delegates I/O to. The
	// default backend is a file-backed appendLog; tests can inject a fake
	// backend to induce error paths without touching the filesystem.
	backend distributionBackend

	mu     sync.RWMutex
	rounds map[string]*DistributionRoundResult
}

// distributionBackend abstracts the durable I/O the store needs. Kept narrow
// so a fake backend in tests can surface errors at the boundary without
// touching the filesystem. The default file-backed implementation is
// fileDistributionBackend below.
type distributionBackend interface {
	// Replay invokes fn for every previously-persisted entry in order. fn
	// returning an error aborts replay.
	Replay(fn func(entry distributionLogEntry) error) error
	// Append writes one entry and fsyncs before returning. Errors surface
	// to the caller of SaveRound.
	Append(entry distributionLogEntry) error
	// Close releases any underlying handles. Safe to call multiple times.
	Close() error
}

// distributionLogEntry is the on-disk form of one persisted round. Keeping it
// tagged and distinct from DistributionRoundResult lets us evolve the audit
// schema independently of the public API — e.g. add a schemaVersion field or
// separate per-receipt records — without breaking existing logs.
type distributionLogEntry struct {
	SchemaVersion int                `json:"v"`
	RoundID       string             `json:"roundId"`
	WindowStart   time.Time          `json:"windowStart"`
	WindowEnd     time.Time          `json:"windowEnd"`
	StartedAt     time.Time          `json:"startedAt"`
	CompletedAt   time.Time          `json:"completedAt"`
	Receipts      []persistedReceipt `json:"receipts,omitempty"`
	Skipped       []persistedSkipped `json:"skipped,omitempty"`
	Residuals     map[string]string  `json:"residuals,omitempty"` // group-key → decimal amount
}

type persistedReceipt struct {
	ChainID       string            `json:"chainId"`
	Currency      string            `json:"currency"`
	TxHash        string            `json:"txHash"`
	BroadcastedAt time.Time         `json:"broadcastedAt"`
	Payouts       []persistedPayout `json:"payouts,omitempty"`
}

type persistedPayout struct {
	WitnessPubKey  string   `json:"pubkey"` // hex
	WitnessAddr    string   `json:"addr"`
	ChainID        string   `json:"chainId"`
	Currency       string   `json:"currency"`
	Amount         string   `json:"amount"`                   // decimal string
	AttestationIDs []string `json:"attestationIds,omitempty"` // hex-encoded
}

type persistedSkipped struct {
	WitnessPubKey string `json:"pubkey"`
	ChainID       string `json:"chainId"`
	Currency      string `json:"currency"`
	Amount        string `json:"amount"`
	Reason        string `json:"reason"`
}

const distributionLogSchemaVersion = 1

// NewPersistentDistributionStore opens (or creates) a persistent store backed
// by <dir>/distribution.log. The directory is created if it does not exist.
// On open the log is replayed into an in-memory index so LoadRound matches
// the in-memory implementation's latency.
//
// Production deployments should co-locate this directory with the SDK's
// Config.DataDir — the SDK's NewFeeDistributor helper does this automatically
// when no explicit Store is supplied.
func NewPersistentDistributionStore(dir string) (*PersistentDistributionStore, error) {
	if dir == "" {
		return nil, errors.New("witness/persistent_distribution_store: dir is empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("witness/persistent_distribution_store: mkdir %q: %w", dir, err)
	}
	path := filepath.Join(dir, "distribution.log")
	backend, err := newFileDistributionBackend(path)
	if err != nil {
		return nil, err
	}
	return newPersistentDistributionStoreWithBackend(dir, path, backend)
}

// newPersistentDistributionStoreWithBackend is the test seam. Production
// callers always go through NewPersistentDistributionStore.
func newPersistentDistributionStoreWithBackend(dir, path string, backend distributionBackend) (*PersistentDistributionStore, error) {
	s := &PersistentDistributionStore{
		dir:     dir,
		path:    path,
		backend: backend,
		rounds:  make(map[string]*DistributionRoundResult),
	}
	if err := backend.Replay(func(entry distributionLogEntry) error {
		round, err := entryToRound(entry)
		if err != nil {
			return err
		}
		// Last-write-wins on duplicate RoundIDs. In practice SaveRound rejects
		// duplicates, so this only fires when an operator has manually edited
		// the log to replay a stuck round — honour their intent.
		s.rounds[round.RoundID] = round
		return nil
	}); err != nil {
		_ = backend.Close()
		return nil, fmt.Errorf("witness/persistent_distribution_store: replay: %w", err)
	}
	return s, nil
}

// LoadRound satisfies DistributionStore. Returns (nil, nil) when the round is
// not known.
func (s *PersistentDistributionStore) LoadRound(_ context.Context, roundID string) (*DistributionRoundResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.rounds[roundID]
	if !ok {
		return nil, nil
	}
	return r, nil
}

// SaveRound satisfies DistributionStore. The round is first appended to the
// durable log (fsynced) and then installed in the in-memory index so a crash
// between the two is never visible to LoadRound — on restart the replay
// rebuilds the index from the log.
func (s *PersistentDistributionStore) SaveRound(_ context.Context, round *DistributionRoundResult) error {
	if round == nil {
		return errors.New("witness/persistent_distribution_store: save nil round")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.rounds[round.RoundID]; exists {
		return fmt.Errorf("%w: %s", ErrRoundAlreadyProcessed, round.RoundID)
	}
	entry, err := roundToEntry(round)
	if err != nil {
		return fmt.Errorf("witness/persistent_distribution_store: encode: %w", err)
	}
	if err := s.backend.Append(entry); err != nil {
		return fmt.Errorf("witness/persistent_distribution_store: append: %w", err)
	}
	s.rounds[round.RoundID] = round
	return nil
}

// Close releases the underlying backend. Safe to call multiple times.
func (s *PersistentDistributionStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.backend == nil {
		return nil
	}
	err := s.backend.Close()
	s.backend = nil
	return err
}

// --- file-backed backend ---------------------------------------------------

// fileDistributionBackend is the production backend: a JSON-lines append log
// with fsync-on-append. One open file handle is shared by all Append calls
// inside the owning store's serialising mutex.
type fileDistributionBackend struct {
	path string
	mu   sync.Mutex
	file *os.File
	w    *bufio.Writer
}

func newFileDistributionBackend(path string) (*fileDistributionBackend, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("witness/persistent_distribution_store: open %q: %w", path, err)
	}
	return &fileDistributionBackend{
		path: path,
		file: f,
		w:    bufio.NewWriter(f),
	}, nil
}

// Replay reads the file front-to-back, invoking fn once per line. Blank lines
// are skipped. A decode error aborts replay so an operator notices schema
// drift before the store starts serving traffic.
func (b *fileDistributionBackend) Replay(fn func(entry distributionLogEntry) error) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.file == nil {
		return errors.New("witness/persistent_distribution_store: backend closed")
	}
	// Flush any buffered writes before replaying so the caller observes all
	// prior Appends even if some happened before Replay was invoked.
	if b.w != nil {
		if err := b.w.Flush(); err != nil {
			return fmt.Errorf("pre-replay flush: %w", err)
		}
	}
	// Use a fresh reader at offset 0; don't disturb the writer's append
	// position.
	f, err := os.Open(b.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("open for replay: %w", err)
	}
	// Opened only for reading: a close has nothing to flush.
	defer func() { _ = f.Close() }()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry distributionLogEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return fmt.Errorf("unmarshal entry: %w", err)
		}
		if err := fn(entry); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("scan: %w", err)
	}
	return nil
}

func (b *fileDistributionBackend) Append(entry distributionLogEntry) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.file == nil {
		return errors.New("witness/persistent_distribution_store: backend closed")
	}
	buf, err := json.Marshal(&entry)
	if err != nil {
		return fmt.Errorf("marshal entry: %w", err)
	}
	if _, err := b.w.Write(buf); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	if err := b.w.WriteByte('\n'); err != nil {
		return fmt.Errorf("write newline: %w", err)
	}
	if err := b.w.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	if err := b.file.Sync(); err != nil {
		return fmt.Errorf("fsync: %w", err)
	}
	return nil
}

func (b *fileDistributionBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.file == nil {
		return nil
	}
	var firstErr error
	if b.w != nil {
		if err := b.w.Flush(); err != nil {
			firstErr = err
		}
	}
	if err := b.file.Sync(); err != nil && firstErr == nil {
		firstErr = err
	}
	if err := b.file.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	b.file = nil
	b.w = nil
	return firstErr
}

// --- encoding / decoding ---------------------------------------------------

func roundToEntry(round *DistributionRoundResult) (distributionLogEntry, error) {
	entry := distributionLogEntry{
		SchemaVersion: distributionLogSchemaVersion,
		RoundID:       round.RoundID,
		WindowStart:   round.WindowStart,
		WindowEnd:     round.WindowEnd,
		StartedAt:     round.StartedAt,
		CompletedAt:   round.CompletedAt,
	}
	if len(round.Receipts) > 0 {
		entry.Receipts = make([]persistedReceipt, 0, len(round.Receipts))
		for _, r := range round.Receipts {
			pr := persistedReceipt{
				ChainID:       r.ChainID,
				Currency:      r.Currency,
				TxHash:        r.TxHash,
				BroadcastedAt: r.BroadcastedAt,
			}
			if len(r.Payouts) > 0 {
				pr.Payouts = make([]persistedPayout, 0, len(r.Payouts))
				for _, p := range r.Payouts {
					pp := persistedPayout{
						WitnessPubKey: hex.EncodeToString(p.WitnessPubKey),
						WitnessAddr:   p.WitnessAddr,
						ChainID:       p.ChainID,
						Currency:      p.Currency,
						Amount:        bigIntString(p.Amount),
					}
					if len(p.AttestationIDs) > 0 {
						pp.AttestationIDs = make([]string, 0, len(p.AttestationIDs))
						for _, a := range p.AttestationIDs {
							pp.AttestationIDs = append(pp.AttestationIDs, hex.EncodeToString(a))
						}
					}
					pr.Payouts = append(pr.Payouts, pp)
				}
			}
			entry.Receipts = append(entry.Receipts, pr)
		}
	}
	if len(round.Skipped) > 0 {
		entry.Skipped = make([]persistedSkipped, 0, len(round.Skipped))
		for _, s := range round.Skipped {
			entry.Skipped = append(entry.Skipped, persistedSkipped{
				WitnessPubKey: s.WitnessPubKey,
				ChainID:       s.ChainID,
				Currency:      s.Currency,
				Amount:        bigIntString(s.Amount),
				Reason:        s.Reason,
			})
		}
	}
	if len(round.ResidualByGroup) > 0 {
		entry.Residuals = make(map[string]string, len(round.ResidualByGroup))
		for k, v := range round.ResidualByGroup {
			entry.Residuals[k] = bigIntString(v)
		}
	}
	return entry, nil
}

func entryToRound(entry distributionLogEntry) (*DistributionRoundResult, error) {
	round := &DistributionRoundResult{
		RoundID:         entry.RoundID,
		WindowStart:     entry.WindowStart,
		WindowEnd:       entry.WindowEnd,
		StartedAt:       entry.StartedAt,
		CompletedAt:     entry.CompletedAt,
		ResidualByGroup: make(map[string]*big.Int),
	}
	if len(entry.Receipts) > 0 {
		round.Receipts = make([]DistributionReceipt, 0, len(entry.Receipts))
		for _, pr := range entry.Receipts {
			r := DistributionReceipt{
				ChainID:       pr.ChainID,
				Currency:      pr.Currency,
				TxHash:        pr.TxHash,
				BroadcastedAt: pr.BroadcastedAt,
			}
			if len(pr.Payouts) > 0 {
				r.Payouts = make([]Payout, 0, len(pr.Payouts))
				for _, pp := range pr.Payouts {
					pk, err := hex.DecodeString(pp.WitnessPubKey)
					if err != nil {
						return nil, fmt.Errorf("decode pubkey %q: %w", pp.WitnessPubKey, err)
					}
					amt, err := parseBigInt(pp.Amount)
					if err != nil {
						return nil, fmt.Errorf("decode payout amount %q: %w", pp.Amount, err)
					}
					p := Payout{
						WitnessPubKey: pk,
						WitnessAddr:   pp.WitnessAddr,
						ChainID:       pp.ChainID,
						Currency:      pp.Currency,
						Amount:        amt,
					}
					if len(pp.AttestationIDs) > 0 {
						p.AttestationIDs = make([][]byte, 0, len(pp.AttestationIDs))
						for _, a := range pp.AttestationIDs {
							b, err := hex.DecodeString(a)
							if err != nil {
								return nil, fmt.Errorf("decode attestation id %q: %w", a, err)
							}
							p.AttestationIDs = append(p.AttestationIDs, b)
						}
					}
					r.Payouts = append(r.Payouts, p)
				}
			}
			round.Receipts = append(round.Receipts, r)
		}
	}
	if len(entry.Skipped) > 0 {
		round.Skipped = make([]SkippedPayout, 0, len(entry.Skipped))
		for _, ps := range entry.Skipped {
			amt, err := parseBigInt(ps.Amount)
			if err != nil {
				return nil, fmt.Errorf("decode skipped amount %q: %w", ps.Amount, err)
			}
			round.Skipped = append(round.Skipped, SkippedPayout{
				WitnessPubKey: ps.WitnessPubKey,
				ChainID:       ps.ChainID,
				Currency:      ps.Currency,
				Amount:        amt,
				Reason:        ps.Reason,
			})
		}
	}
	for k, v := range entry.Residuals {
		amt, err := parseBigInt(v)
		if err != nil {
			return nil, fmt.Errorf("decode residual %q: %w", v, err)
		}
		round.ResidualByGroup[k] = amt
	}
	return round, nil
}

func bigIntString(v *big.Int) string {
	if v == nil {
		return "0"
	}
	return v.String()
}

func parseBigInt(s string) (*big.Int, error) {
	if s == "" {
		return new(big.Int), nil
	}
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("invalid decimal big.Int %q", s)
	}
	return v, nil
}
