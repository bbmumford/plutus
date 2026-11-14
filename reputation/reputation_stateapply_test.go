/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package reputation

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/bbmumford/whisper"
)

// State sync admits a record only under the rule gossip applies: a record whose
// signature does not verify, or whose score is outside [-1, 1], is refused by
// Apply as OnBroadcast drops it, so no peer can move a subject's score by sync.
func TestStateApplyRefusesWhatGossipRefuses(t *testing.T) {
	svc := NewReputationService(whisper.NewEngine(), nil)
	store := &reputationStateStore{service: svc, topic: topicRepTrades}
	subject, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	recorder, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rec := ReputationRecord{SubjectPubKey: subject, RecorderPubKey: recorder, Score: -1,
		TxHash: "0xT1", Timestamp: time.Now()}
	if err := SignRecord(&rec, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	b, _ := json.Marshal(rec)
	if err := store.Apply(b); err != nil {
		t.Fatalf("Apply refused a signed record: %v", err)
	}

	forged := rec
	forged.TxHash = "0xT2"
	forged.Score = 1
	b, _ = json.Marshal(forged)
	if err := store.Apply(b); err == nil {
		t.Fatal("Apply admitted a record whose signature does not verify")
	}

	wild := ReputationRecord{SubjectPubKey: subject, RecorderPubKey: recorder, Score: 7,
		TxHash: "0xT3", Timestamp: time.Now()}
	if err := SignRecord(&wild, priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	b, _ = json.Marshal(wild)
	if err := store.Apply(b); err == nil {
		t.Fatal("Apply admitted a score outside [-1, 1]")
	}

	svc.mu.RLock()
	n := len(svc.records[hex.EncodeToString(subject)])
	svc.mu.RUnlock()
	if n != 1 {
		t.Fatalf("subject holds %d records, want only the signed one", n)
	}
}
