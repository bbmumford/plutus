/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package reputation

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func newRecord(t *testing.T, subject, recorder ed25519.PublicKey, typ RepType, score int32) *ReputationRecord {
	t.Helper()
	return &ReputationRecord{
		SubjectPubKey:  subject,
		RecorderPubKey: recorder,
		Type:           typ,
		Score:          score,
		AppID:          "test-app",
		TxHash:         "0xtx",
		Timestamp:      time.Now().UTC(),
	}
}

func TestSignAndVerifyRecord(t *testing.T) {
	t.Parallel()
	subject, _, _ := ed25519.GenerateKey(rand.Reader)
	recorder, recorderPriv, _ := ed25519.GenerateKey(rand.Reader)
	rec := newRecord(t, subject, recorder, TradeComplete, 1)
	if err := SignRecord(rec, recorderPriv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if !VerifyRecord(rec) {
		t.Error("fresh record should verify")
	}
	rec.Score = 0
	if VerifyRecord(rec) {
		t.Error("tampered record should not verify")
	}
}

func TestVerifyRecord_BadKey(t *testing.T) {
	t.Parallel()
	rec := &ReputationRecord{
		RecorderPubKey: []byte{1, 2, 3},
		Signature:      make([]byte, ed25519.SignatureSize),
	}
	if VerifyRecord(rec) {
		t.Error("short recorder pubkey should not verify")
	}
}

func TestRepTypeString(t *testing.T) {
	t.Parallel()
	cases := map[RepType]string{
		TradeComplete: "TradeComplete",
		Dispute:       "Dispute",
		Review:        "Review",
	}
	for k, v := range cases {
		if k.String() != v {
			t.Errorf("RepType(%d).String() = %q, want %q", k, k.String(), v)
		}
	}
}

func TestValidateRecord_InvalidScore(t *testing.T) {
	t.Parallel()
	subject, _, _ := ed25519.GenerateKey(rand.Reader)
	recorder, recorderPriv, _ := ed25519.GenerateKey(rand.Reader)
	rec := newRecord(t, subject, recorder, TradeComplete, 99) // invalid
	_ = SignRecord(rec, recorderPriv)
	if err := validateRecord(rec); err == nil {
		t.Error("expected score-range error")
	}
}

func TestValidateRecord_ShortSubjectPubKey(t *testing.T) {
	t.Parallel()
	rec := &ReputationRecord{
		SubjectPubKey:  []byte{1, 2, 3},
		RecorderPubKey: make([]byte, ed25519.PublicKeySize),
		Timestamp:      time.Now(),
	}
	if err := validateRecord(rec); err == nil {
		t.Error("expected subject-key error")
	}
}
