/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package gossipstate computes the record-set fingerprint that the
// arbitrator, reputation and witness whisper state stores report from
// Fingerprint, so the three topics derive it the same way.
package gossipstate

import "hash/fnv"

// Fingerprint returns an order-independent summary of records: the XOR of
// each record's FNV-1a hash. whisper's G2 digest takes equal non-zero
// fingerprints on two peers as agreement on every record and skips the G1
// exchange, so the value is derived from the record bytes rather than a
// local mutation count, which two peers holding different records can
// share. An empty set yields 0, which the digest never counts as a match.
func Fingerprint(records [][]byte) uint64 {
	var fp uint64
	for _, rec := range records {
		h := fnv.New64a()
		_, _ = h.Write(rec)
		fp ^= h.Sum64()
	}
	return fp
}
