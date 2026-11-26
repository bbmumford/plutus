//go:build js

/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package witness

import (
	"context"
	"errors"
	"time"
)

// errNoJournalInBrowser is every journal operation's answer in the js build:
// the store's SQLite engine (tursogo) loads a native library, which a browser
// cannot, so the earning log and the distribution store are native-only. The
// browser bridge never opens them.
var errNoJournalInBrowser = errors.New("witness/journal: the witness journal store is not available in the browser build")

// journalFile is the native store's file name inside its directory.
const journalFile = "witness.db"

// journalDB stands in for the native store so the witness package builds for
// js; it is never made.
type journalDB struct{}

func openJournal(context.Context, string) (*journalDB, error) { return nil, errNoJournalInBrowser }

func (*journalDB) release() error { return errNoJournalInBrowser }

func (*journalDB) insertEarnings(context.Context, []EarningLogEntry) error {
	return errNoJournalInBrowser
}

func (*journalDB) earningsIn(context.Context, time.Time, time.Time) ([]EarningLogEntry, error) {
	return nil, errNoJournalInBrowser
}

func (*journalDB) distributionEntries(context.Context, func(distributionLogEntry) error) error {
	return errNoJournalInBrowser
}

func (*journalDB) insertDistribution(context.Context, distributionLogEntry) error {
	return errNoJournalInBrowser
}

func (*journalDB) importEarningsJournal(context.Context, string, string) error {
	return errNoJournalInBrowser
}

func (*journalDB) importDistributionJournal(context.Context, string, string) error {
	return errNoJournalInBrowser
}
