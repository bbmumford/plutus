/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"time"
)

// PersistentDistributionStore is a crash-recoverable DistributionStore backed
// by the witness journal store: the SQLite file <dir>/witness.db stamped as a
// billing witness journal (see openJournal), which an EarningLog on the same
// directory shares. Each SaveRound inserts one row, committed before it
// returns; on open the rows are replayed into an in-memory index so LoadRound
// is O(1) and matches the in-memory store's latency.
//
// The writer holds a mutex serialising SaveRound; LoadRound is lock-free for
// reads (sync.RWMutex read side). The in-memory index is authoritative for
// LoadRound once the rows have been replayed; the store is the authoritative
// source across restarts.
type PersistentDistributionStore struct {
	dir  string
	path string
	// backend is the durable primitive this store delegates I/O to. The
	// default backend is the journal store's rounds table; tests can inject
	// a fake backend to induce error paths without touching the filesystem.
	backend distributionBackend

	mu     sync.RWMutex
	rounds map[string]*DistributionRoundResult
}

// distributionBackend abstracts the durable I/O the store needs. Kept narrow
// so a fake backend in tests can surface errors at the boundary without
// touching the filesystem. The default implementation is
// journalDistributionBackend below.
type distributionBackend interface {
	// Replay invokes fn for every previously-persisted entry in order. fn
	// returning an error aborts replay.
	Replay(fn func(entry distributionLogEntry) error) error
	// Append writes one entry durably before returning. Errors surface to
	// the caller of SaveRound.
	Append(entry distributionLogEntry) error
	// Close releases any underlying handles. Safe to call multiple times.
	Close() error
}

// distributionLogEntry is the stored form of one persisted round (a row's
// entry, and a line of the distribution.log journals the store takes in). Keeping it
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

// distributionJournal is the JSON-lines journal a PersistentDistributionStore
// kept in its directory before the journal store; it is taken in once.
const distributionJournal = "distribution.log"

// NewPersistentDistributionStore opens (or creates) a persistent store in
// dir. The directory is created if it does not exist. On open the stored
// rounds are replayed into an in-memory index so LoadRound matches the
// in-memory implementation's latency. A distribution.log journal already in
// dir is taken into the store once and left on disk.
//
// Production deployments should co-locate this directory with the SDK's
// Config.DataDir — the SDK opens it there (OpenJournals) when DataDir is set.
func NewPersistentDistributionStore(dir string) (*PersistentDistributionStore, error) {
	return openDistributionStore(dir, distributionJournal)
}

// openDistributionStore opens the store in dir and takes in the
// distribution.log journal at dir/legacy (legacy is relative to dir).
func openDistributionStore(dir, legacy string) (*PersistentDistributionStore, error) {
	if dir == "" {
		return nil, errors.New("witness/persistent_distribution_store: dir is empty")
	}
	ctx := context.Background()
	j, err := openJournal(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("witness/persistent_distribution_store: %w", err)
	}
	if err := j.importDistributionJournal(ctx, legacy, filepath.Join(dir, legacy)); err != nil {
		_ = j.release() // the import's error is the one returned
		return nil, fmt.Errorf("witness/persistent_distribution_store: take in %s: %w", legacy, err)
	}
	return newPersistentDistributionStoreWithBackend(dir, filepath.Join(dir, journalFile), journalDistributionBackend{j: j})
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

// --- journal-store backend ------------------------------------------------

// journalDistributionBackend is the production backend: the rounds table of
// the witness journal store. The store's own primary key refuses a round ID
// twice, behind SaveRound's in-memory check.
type journalDistributionBackend struct {
	j *journalDB
}

func (b journalDistributionBackend) Replay(fn func(entry distributionLogEntry) error) error {
	return b.j.distributionEntries(context.Background(), fn)
}

func (b journalDistributionBackend) Append(entry distributionLogEntry) error {
	return b.j.insertDistribution(context.Background(), entry)
}

func (b journalDistributionBackend) Close() error {
	return b.j.release()
}

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
