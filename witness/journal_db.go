//go:build !js

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package witness

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bbmumford/filekind"
	_ "turso.tech/database/tursogo" // registers the "turso" database/sql driver
)

// journalFile is the witness journal store's file name inside its directory.
const journalFile = "witness.db"

// journalGeneration is the store's schema generation, stamped with
// filekind.BillingWitness in the file's header (user_version).
const journalGeneration = 1

// journalSchema is the store's schema, made once by filekind.Create with the
// stamp. earnings holds one row per witness per settled order
// (EarningLog.Record), indexed by settledAt for CollectEarnings' window reads;
// distributionRounds holds one row per distribution round
// (PersistentDistributionStore), keyed by its round ID; journalImports names
// each JSON-lines journal the store has taken in, so none is taken in twice.
var journalSchema = []string{
	`CREATE TABLE earnings (
		id INTEGER PRIMARY KEY,
		orderId TEXT NOT NULL,
		chainId TEXT NOT NULL,
		currency TEXT NOT NULL,
		witnessPubKey TEXT NOT NULL,
		amount TEXT NOT NULL,
		attestationId BLOB,
		settledAt INTEGER NOT NULL
	)`,
	`CREATE INDEX earningsBySettledAt ON earnings (settledAt)`,
	`CREATE TABLE distributionRounds (
		roundId TEXT PRIMARY KEY,
		entry TEXT NOT NULL
	)`,
	`CREATE TABLE journalImports (
		source TEXT PRIMARY KEY,
		entries INTEGER NOT NULL
	)`,
}

// earningsInWindow is CollectEarnings' read: the earnings settled in
// [start, end), in settlement order, through earningsBySettledAt. It orders
// by the indexed column first: ordered by id alone, the engine scans the
// table instead of the index.
const earningsInWindow = `SELECT orderId, chainId, currency, witnessPubKey, amount, attestationId, settledAt
	FROM earnings WHERE settledAt >= ? AND settledAt < ? ORDER BY settledAt, id`

// journalDB is one open witness journal store. Every EarningLog and
// PersistentDistributionStore opened on the same directory in a process shares
// it (openJournals), and it holds one connection, so the file has a single
// writer and no two transactions ever race on it.
type journalDB struct {
	db   *sql.DB
	path string
	refs int // views open on it; the last Close closes the file
}

var (
	openJournalsMu sync.Mutex
	openJournals   = map[string]*journalDB{}
)

// openJournal opens (or creates) the witness journal store in dir, or returns
// the one this process already has open there. A new file is made a
// filekind.BillingWitness file at journalGeneration with journalSchema; an
// existing file must already be one, at exactly that generation (filekind
// refuses any other kind, an unstamped file with a schema of its own, and a
// newer generation).
func openJournal(ctx context.Context, dir string) (*journalDB, error) {
	if dir == "" {
		return nil, errors.New("witness/journal: dir is empty")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("witness/journal: mkdir %q: %w", dir, err)
	}
	path, err := filepath.Abs(filepath.Join(dir, journalFile))
	if err != nil {
		return nil, fmt.Errorf("witness/journal: %w", err)
	}
	openJournalsMu.Lock()
	defer openJournalsMu.Unlock()
	if j, ok := openJournals[path]; ok {
		j.refs++
		return j, nil
	}
	db, err := sql.Open("turso", path)
	if err != nil {
		return nil, fmt.Errorf("witness/journal: open %q: %w", path, err)
	}
	db.SetMaxOpenConns(1)
	if err := stampJournal(ctx, db); err != nil {
		_ = db.Close() // the open already failed; its error is the one returned
		return nil, fmt.Errorf("witness/journal: %q: %w", path, err)
	}
	j := &journalDB{db: db, path: path, refs: 1}
	openJournals[path] = j
	return j, nil
}

func stampJournal(ctx context.Context, db *sql.DB) error {
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	_, err = filekind.Create(ctx, conn, filekind.BillingWitness, journalGeneration, journalSchema)
	if cerr := conn.Close(); err == nil {
		err = cerr
	}
	return err
}

// release closes this view's hold on the store; the last view to release it
// closes the file.
func (j *journalDB) release() error {
	openJournalsMu.Lock()
	defer openJournalsMu.Unlock()
	j.refs--
	if j.refs > 0 {
		return nil
	}
	delete(openJournals, j.path)
	return j.db.Close()
}

// unixNanos is t in Unix nanoseconds, saturated at the int64 range so a zero
// or far-future window bound still compares correctly.
func unixNanos(t time.Time) int64 {
	if t.Before(time.Unix(0, math.MinInt64)) {
		return math.MinInt64
	}
	if t.After(time.Unix(0, math.MaxInt64)) {
		return math.MaxInt64
	}
	return t.UnixNano()
}

// inTx runs fn inside one transaction and commits it, or rolls it back when
// fn or the commit fails.
func (j *journalDB) inTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := j.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		// The transaction's own error is the one returned; a failed rollback
		// leaves nothing committed either way.
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

const insertEarning = `INSERT INTO earnings (orderId, chainId, currency, witnessPubKey, amount, attestationId, settledAt)
	VALUES (?, ?, ?, ?, ?, ?, ?)`

// insertEarnings writes every entry in one transaction: a settlement's
// per-witness entries are all stored or none are.
func (j *journalDB) insertEarnings(ctx context.Context, entries []EarningLogEntry) error {
	return j.inTx(ctx, func(tx *sql.Tx) error {
		for _, e := range entries {
			if _, err := tx.ExecContext(ctx, insertEarning, e.OrderID, e.ChainID, e.Currency, e.WitnessPubKey,
				e.Amount, e.AttestationID, unixNanos(e.SettledAt)); err != nil {
				return err
			}
		}
		return nil
	})
}

// earningsIn returns the entries settled in [start, end), in settlement
// order (ties in the order they were written).
func (j *journalDB) earningsIn(ctx context.Context, start, end time.Time) ([]EarningLogEntry, error) {
	rows, err := j.db.QueryContext(ctx, earningsInWindow, unixNanos(start), unixNanos(end))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }() // rows.Err below reports a failed read
	var out []EarningLogEntry
	for rows.Next() {
		var e EarningLogEntry
		var at int64
		if err := rows.Scan(&e.OrderID, &e.ChainID, &e.Currency, &e.WitnessPubKey, &e.Amount, &e.AttestationID, &at); err != nil {
			return nil, err
		}
		e.SettledAt = time.Unix(0, at).UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// distributionEntries calls fn with every stored round, in the order they were
// written.
func (j *journalDB) distributionEntries(ctx context.Context, fn func(distributionLogEntry) error) error {
	rows, err := j.db.QueryContext(ctx, `SELECT entry FROM distributionRounds ORDER BY rowid`)
	if err != nil {
		return err
	}
	var entries []distributionLogEntry
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			_ = rows.Close() // the scan error is the one returned
			return err
		}
		var e distributionLogEntry
		if err := json.Unmarshal([]byte(raw), &e); err != nil {
			_ = rows.Close() // the decode error is the one returned
			return fmt.Errorf("round entry: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close() // the read error is the one returned
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	// fn runs after the read so it may write to the store: its one connection
	// is free again.
	for _, e := range entries {
		if err := fn(e); err != nil {
			return err
		}
	}
	return nil
}

// insertDistribution stores one round; a round ID already stored is refused by
// the primary key.
func (j *journalDB) insertDistribution(ctx context.Context, entry distributionLogEntry) error {
	raw, err := json.Marshal(&entry)
	if err != nil {
		return err
	}
	_, err = j.db.ExecContext(ctx, `INSERT INTO distributionRounds (roundId, entry) VALUES (?, ?)`, entry.RoundID, string(raw))
	return err
}

// importJSONLines takes the JSON-lines journal at path (one JSON value per
// line, as EarningLog and PersistentDistributionStore wrote before this store
// existed) into the store once: put is called for every line inside one
// transaction that also records source in journalImports, so a crash leaves
// either every line or none, and a source already recorded is skipped. A
// missing file is nothing to take in. The file itself is left where it is.
func (j *journalDB) importJSONLines(ctx context.Context, source, path string, put func(tx *sql.Tx, line []byte) error) error {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	// Opened only for reading: a close has nothing to flush.
	defer func() { _ = f.Close() }()
	return j.inTx(ctx, func(tx *sql.Tx) error {
		var seen int
		if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM journalImports WHERE source = ?`, source).Scan(&seen); err != nil {
			return err
		}
		if seen > 0 {
			return nil
		}
		n := 0
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}
			if err := put(tx, line); err != nil {
				return fmt.Errorf("%s line %d: %w", path, n+1, err)
			}
			n++
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("read %q: %w", path, err)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO journalImports (source, entries) VALUES (?, ?)`, source, n)
		return err
	})
}

// importEarningsJournal takes in an earnings.log JSON-lines journal.
func (j *journalDB) importEarningsJournal(ctx context.Context, source, path string) error {
	return j.importJSONLines(ctx, source, path, func(tx *sql.Tx, line []byte) error {
		var e EarningLogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, insertEarning, e.OrderID, e.ChainID, e.Currency, e.WitnessPubKey,
			e.Amount, e.AttestationID, unixNanos(e.SettledAt))
		return err
	})
}

// importDistributionJournal takes in a distribution.log JSON-lines journal. A
// round ID the journal holds twice keeps its last line, as the journal's own
// replay did.
func (j *journalDB) importDistributionJournal(ctx context.Context, source, path string) error {
	return j.importJSONLines(ctx, source, path, func(tx *sql.Tx, line []byte) error {
		var e distributionLogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			return err
		}
		raw, err := json.Marshal(&e)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT OR REPLACE INTO distributionRounds (roundId, entry) VALUES (?, ?)`, e.RoundID, string(raw))
		return err
	})
}
