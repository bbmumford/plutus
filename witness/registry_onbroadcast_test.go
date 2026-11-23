/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/bbmumford/whisper"
)

// TestOnBroadcast_RejectsForgedPayoutAddressChange checks that a peer which
// has already received a validly-signed WitnessRegistration CANNOT be tricked
// into accepting a second, newer-timestamped gossip frame whose
// PayoutAddresses map has been mutated and whose signature no longer
// verifies. This is the registry.go:286-306 security regression: before the
// fix, OnBroadcast blindly merged by timestamp and would overwrite the
// honest payout map with the attacker's.
func TestOnBroadcast_RejectsForgedPayoutAddressChange(t *testing.T) {
	t.Parallel()

	engine := whisper.NewEngine()
	reg := NewWitnessRegistry(engine, nil)

	// Seed a signed honest registration.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	honest := WitnessRegistration{
		PubKey:       pub,
		ChainIDs:     []string{"ethereum"},
		Capabilities: []string{"balance"},
		Reputation:   0.5,
		RegisteredAt: time.Now(),
		PayoutAddresses: map[string]string{
			"ethereum": "0xHONEST",
		},
	}
	if err := honest.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := reg.Register(honest); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Craft a forged wire frame: copy the honest signature bytes but mutate
	// PayoutAddresses and advance RegisteredAt so the naive timestamp-merge
	// would accept it. Verify() will fail against the mutated canonical
	// bytes, which is exactly what OnBroadcast must now check.
	forgedWire := witnessRegistrationWire{
		PubKey:       []byte(honest.PubKey),
		ChainIDs:     honest.ChainIDs,
		Capabilities: honest.Capabilities,
		Reputation:   honest.Reputation,
		RegisteredAt: time.Now().Add(time.Hour).UnixNano(), // newer
		PayoutAddresses: map[string]string{
			"ethereum": "0xATTACKER", // hijack
		},
		Signature: honest.Signature,
	}
	payload, err := json.Marshal(forgedWire)
	if err != nil {
		t.Fatalf("marshal forged: %v", err)
	}
	reg.OnBroadcast(topicWitnesses, "peer-attacker", payload)

	// The registry must still report the honest payout address.
	got := reg.Get(pub)
	if got == nil {
		t.Fatalf("entry disappeared")
	}
	if got.PayoutAddresses["ethereum"] != "0xHONEST" {
		t.Fatalf("PayoutAddresses[ethereum]=%q, want 0xHONEST (forged gossip must be rejected)",
			got.PayoutAddresses["ethereum"])
	}
}

// TestOnBroadcast_AcceptsUnsignedReputationUpdate verifies the CRDT path:
// UpdateReputation re-gossips the record with a mutated Reputation/
// RegisteredAt and a stale signature. OnBroadcast MUST still accept it so
// reputation converges across peers — the sig-verify gate only fires when
// the PayoutAddresses map actually changes.
func TestOnBroadcast_AcceptsUnsignedReputationUpdate(t *testing.T) {
	t.Parallel()

	engine := whisper.NewEngine()
	reg := NewWitnessRegistry(engine, nil)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	honest := WitnessRegistration{
		PubKey:       pub,
		ChainIDs:     []string{"ethereum"},
		Capabilities: []string{"balance"},
		Reputation:   0.5,
		RegisteredAt: time.Now(),
		PayoutAddresses: map[string]string{
			"ethereum": "0xHONEST",
		},
	}
	if err := honest.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := reg.Register(honest); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Bump reputation on the original record, keep the same PayoutAddresses,
	// do NOT re-sign. This mimics UpdateReputation's gossip frame.
	bumped := witnessRegistrationWire{
		PubKey:       []byte(honest.PubKey),
		ChainIDs:     honest.ChainIDs,
		Capabilities: honest.Capabilities,
		Reputation:   0.9,                               // mutated
		RegisteredAt: time.Now().Add(time.Hour).UnixNano(),
		PayoutAddresses: map[string]string{
			"ethereum": "0xHONEST", // unchanged
		},
		Signature: honest.Signature, // stale
	}
	payload, err := json.Marshal(bumped)
	if err != nil {
		t.Fatalf("marshal bumped: %v", err)
	}
	reg.OnBroadcast(topicWitnesses, "peer-peer", payload)

	got := reg.Get(pub)
	if got == nil {
		t.Fatalf("entry disappeared")
	}
	if got.Reputation != 0.9 {
		t.Errorf("Reputation=%v, want 0.9 (reputation-only CRDT update must be accepted)", got.Reputation)
	}
	if got.PayoutAddresses["ethereum"] != "0xHONEST" {
		t.Errorf("PayoutAddresses hijacked: %q", got.PayoutAddresses["ethereum"])
	}
}

// TestOnBroadcast_RejectsUnsignedFirstContact asserts that a peer which has
// NEVER seen a witness cannot be fed an unsigned frame as first contact — we
// require Verify() to pass on new entries so an attacker cannot preempt the
// honest witness's first broadcast with a forged PayoutAddresses map.
func TestOnBroadcast_RejectsUnsignedFirstContact(t *testing.T) {
	t.Parallel()

	engine := whisper.NewEngine()
	reg := NewWitnessRegistry(engine, nil)

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	forged := witnessRegistrationWire{
		PubKey:       []byte(pub),
		ChainIDs:     []string{"ethereum"},
		Capabilities: []string{"balance"},
		Reputation:   0.5,
		RegisteredAt: time.Now().UnixNano(),
		PayoutAddresses: map[string]string{
			"ethereum": "0xATTACKER",
		},
		Signature: make([]byte, ed25519.SignatureSize), // garbage sig
	}
	payload, err := json.Marshal(forged)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	reg.OnBroadcast(topicWitnesses, "peer-attacker", payload)

	if got := reg.Get(pub); got != nil {
		t.Fatalf("forged first-contact accepted: %+v", got)
	}
	// Sanity: at least confirm hex.EncodeToString works (used by registry
	// key path); otherwise the Get(nil) above could hide a different bug.
	if _, err := hex.DecodeString(hex.EncodeToString(pub)); err != nil {
		t.Fatalf("hex roundtrip: %v", err)
	}
}
