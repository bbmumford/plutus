//go:build !js

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package witness

import (
	"context"
	"encoding/binary"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bbmumford/plutus/adapter"
)

// journalHeader reads a closed journal file's identity from its header bytes:
// application_id at offset 68 and user_version at offset 60.
func journalHeader(t *testing.T, dir string) (applicationID, userVersion uint32) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "witness.db"))
	if err != nil {
		t.Fatalf("read the journal file: %v", err)
	}
	if len(b) < 100 || string(b[:16]) != "SQLite format 3\x00" {
		t.Fatalf("witness.db is not a SQLite file (%d bytes)", len(b))
	}
	return binary.BigEndian.Uint32(b[68:72]), binary.BigEndian.Uint32(b[60:64])
}

// billingWitnessID is 'ORB' followed by the billing witness kind byte 0x50.
const billingWitnessID = 0x4F524250

// The earning log keeps its rows in witness.db, a SQLite file stamped as a
// billing witness journal at generation 1.
func TestEarningLogKeepsItsRecordsInAStampedWitnessJournal(t *testing.T) {
	dir := t.TempDir()
	l, err := NewEarningLog(dir)
	if err != nil {
		t.Fatalf("NewEarningLog: %v", err)
	}
	if err := l.Record(context.Background(), "order-1", "bitcoin", "BTC", time.Now(), adapter.FeeBreakdown{
		WitnessFees: map[string]*big.Int{"aa": big.NewInt(5)},
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if id, gen := journalHeader(t, dir); id != billingWitnessID || gen != 1 {
		t.Fatalf("witness.db header: application_id %#x, user_version %d; want %#x, 1", id, gen, billingWitnessID)
	}
}

// The distribution store keeps its rounds in the same stamped file.
func TestDistributionStoreKeepsItsRoundsInAStampedWitnessJournal(t *testing.T) {
	dir := t.TempDir()
	s, err := NewPersistentDistributionStore(dir)
	if err != nil {
		t.Fatalf("NewPersistentDistributionStore: %v", err)
	}
	if err := s.SaveRound(context.Background(), sampleRound("R1")); err != nil {
		t.Fatalf("SaveRound: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if id, gen := journalHeader(t, dir); id != billingWitnessID || gen != 1 {
		t.Fatalf("witness.db header: application_id %#x, user_version %d; want %#x, 1", id, gen, billingWitnessID)
	}
}
