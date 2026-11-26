//go:build !js

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package witness

import (
	"context"
	"database/sql"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bbmumford/filekind"
)

// OpenJournals keeps both journals in one file, takes in the JSON-lines
// journals already under the data directory, and takes each in only once.
func TestOpenJournalsTakesInTheJSONLinesJournalsOnce(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	writeLines(t, filepath.Join(dir, "earnings", "earnings.log"),
		`{"orderId":"o-1","chainId":"bitcoin","currency":"BTC","witnessPubkey":"aa","amount":"7","settledAt":"2026-11-01T12:00:00Z"}`,
		`{"orderId":"o-2","chainId":"bitcoin","currency":"BTC","witnessPubkey":"aa","amount":"123456789012345678901234567890","settledAt":"2026-11-01T12:00:00Z"}`)
	writeLines(t, filepath.Join(dir, "distributions", "distribution.log"),
		`{"v":1,"roundId":"old-round","windowStart":"2026-10-31T00:00:00Z","windowEnd":"2026-11-01T00:00:00Z","startedAt":"2026-11-01T00:00:00Z","completedAt":"2026-11-01T00:01:00Z"}`)

	want, _ := new(big.Int).SetString("123456789012345678901234567897", 10)
	for open := 1; open <= 2; open++ {
		el, ds, err := OpenJournals(dir)
		if err != nil {
			t.Fatalf("open %d: OpenJournals: %v", open, err)
		}
		recs, err := el.CollectEarnings(context.Background(), at.Add(-time.Hour), at.Add(time.Hour))
		if err != nil {
			t.Fatalf("open %d: CollectEarnings: %v", open, err)
		}
		if len(recs) != 1 || recs[0].Amount.Cmp(want) != 0 {
			t.Fatalf("open %d: collected %+v, want one record of %s", open, recs, want)
		}
		round, err := ds.LoadRound(context.Background(), "old-round")
		if err != nil || round == nil {
			t.Fatalf("open %d: LoadRound(old-round) = %v, %v; want the journal's round", open, round, err)
		}
		if err := el.Close(); err != nil {
			t.Fatalf("open %d: close earning log: %v", open, err)
		}
		if err := ds.Close(); err != nil {
			t.Fatalf("open %d: close distribution store: %v", open, err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "earnings", "earnings.log")); err != nil {
		t.Fatalf("the taken-in journal is gone: %v", err)
	}
}

// CollectEarnings reads its window through the settledAt index, not a scan
// of every row.
func TestCollectEarningsReadsThroughTheSettledAtIndex(t *testing.T) {
	l, err := NewEarningLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewEarningLog: %v", err)
	}
	defer func() {
		if err := l.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	rows, err := l.journal.db.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+earningsInWindow, int64(0), int64(1))
	if err != nil {
		t.Fatalf("query plan: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var plan []string
	cols, _ := rows.Columns()
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		if s, ok := vals[len(vals)-1].(string); ok {
			plan = append(plan, s)
		}
	}
	if !strings.Contains(strings.ToLower(strings.Join(plan, " | ")), "using index earningsbysettledat") {
		t.Fatalf("the window read does not use earningsBySettledAt: plan %q", plan)
	}
}

// A SQLite file of another kind where the journal belongs is refused, not
// written into.
func TestNewEarningLogRefusesAFileOfAnotherKind(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("turso", filepath.Join(dir, "witness.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := filekind.Stamp(context.Background(), db, filekind.TursoraftLocal, 1); err != nil {
		t.Fatalf("stamp another kind: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	l, err := NewEarningLog(dir)
	if err == nil {
		_ = l.Close()
		t.Fatal("NewEarningLog opened a file stamped as another kind")
	}
	if !errors.Is(err, filekind.ErrWrongKind) {
		t.Fatalf("NewEarningLog: %v, want filekind.ErrWrongKind", err)
	}
}

func writeLines(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
