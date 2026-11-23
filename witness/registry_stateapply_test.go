/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/bbmumford/whisper"
)

// stateApplyFixture is a registry holding one signed registration, the state
// store whisper's StatefulMerge sync hands a peer's records to, and the key
// the registration was signed with.
func stateApplyFixture(t *testing.T) (*WitnessRegistry, *witnessStateStore, WitnessRegistration) {
	t.Helper()
	reg := NewWitnessRegistry(whisper.NewEngine(), nil)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	honest := WitnessRegistration{
		PubKey:          pub,
		ChainIDs:        []string{"ethereum"},
		Capabilities:    []string{"balance"},
		Reputation:      0.5,
		RegisteredAt:    time.Now(),
		PayoutAddresses: map[string]string{"ethereum": "0xHONEST"},
	}
	if err := honest.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := reg.Register(honest); err != nil {
		t.Fatalf("Register: %v", err)
	}
	return reg, &witnessStateStore{registry: reg}, honest
}

func wireOf(t *testing.T, r WitnessRegistration) []byte {
	t.Helper()
	b, err := json.Marshal(witnessRegistrationWire{
		PubKey: []byte(r.PubKey), ChainIDs: r.ChainIDs, Capabilities: r.Capabilities,
		Reputation: r.Reputation, RegisteredAt: r.RegisteredAt.UnixNano(),
		PayoutAddresses: r.PayoutAddresses, Signature: r.Signature,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

// State sync admits what gossip admits and refuses what gossip refuses: a
// peer cannot redirect a witness's fee payouts by sending through Apply the
// record OnBroadcast drops.
func TestStateApplyRefusesAnUnsignedPayoutAddressChange(t *testing.T) {
	reg, store, honest := stateApplyFixture(t)
	forged := honest
	forged.RegisteredAt = honest.RegisteredAt.Add(time.Hour)
	forged.PayoutAddresses = map[string]string{"ethereum": "0xATTACKER"}

	if err := store.Apply(wireOf(t, forged)); err == nil {
		t.Fatal("Apply admitted a payout change whose signature does not verify")
	}
	if got := reg.Get(honest.PubKey).PayoutAddresses["ethereum"]; got != "0xHONEST" {
		t.Fatalf("PayoutAddresses[ethereum] = %q, want 0xHONEST", got)
	}
}

func TestStateApplyRefusesAnUnsignedChainOrCapabilityChange(t *testing.T) {
	reg, store, honest := stateApplyFixture(t)
	for _, mutate := range []func(*WitnessRegistration){
		func(r *WitnessRegistration) { r.ChainIDs = []string{"ethereum", "bitcoin"} },
		func(r *WitnessRegistration) { r.Capabilities = []string{"balance", "escrow-state"} },
	} {
		forged := honest
		forged.RegisteredAt = honest.RegisteredAt.Add(time.Hour)
		mutate(&forged)
		if err := store.Apply(wireOf(t, forged)); err == nil {
			t.Fatalf("Apply admitted an unsigned change: chains %v, capabilities %v", forged.ChainIDs, forged.Capabilities)
		}
	}
	got := reg.Get(honest.PubKey)
	if len(got.ChainIDs) != 1 || len(got.Capabilities) != 1 {
		t.Fatalf("held entry changed: chains %v, capabilities %v", got.ChainIDs, got.Capabilities)
	}
}

func TestStateApplyRefusesAnUnsignedFirstContact(t *testing.T) {
	reg, store, _ := stateApplyFixture(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	stranger := WitnessRegistration{
		PubKey: pub, ChainIDs: []string{"ethereum"}, RegisteredAt: time.Now(),
		PayoutAddresses: map[string]string{"ethereum": "0xATTACKER"},
		Signature:       make([]byte, ed25519.SignatureSize),
	}
	if err := store.Apply(wireOf(t, stranger)); err == nil {
		t.Fatal("Apply admitted a new witness whose signature does not verify")
	}
	if reg.Get(pub) != nil {
		t.Fatal("the unsigned witness is held")
	}
}

// The reputation update UpdateReputation re-publishes keeps the original
// signature over fields it did not change; state sync must admit it, as gossip
// does, or reputation never converges.
func TestStateApplyAdmitsAReputationOnlyUpdate(t *testing.T) {
	reg, store, honest := stateApplyFixture(t)
	bumped := honest
	bumped.Reputation = 0.9
	bumped.RegisteredAt = honest.RegisteredAt.Add(time.Minute)

	if err := store.Apply(wireOf(t, bumped)); err != nil {
		t.Fatalf("Apply refused a reputation-only update: %v", err)
	}
	if got := reg.Get(honest.PubKey).Reputation; got != 0.9 {
		t.Fatalf("Reputation = %v, want 0.9", got)
	}
}

func TestStateApplyKeepsTheNewerEntry(t *testing.T) {
	reg, store, honest := stateApplyFixture(t)
	older := honest
	older.Reputation = 0.1
	older.RegisteredAt = honest.RegisteredAt.Add(-time.Hour)
	if err := store.Apply(wireOf(t, older)); err != nil {
		t.Fatalf("Apply of an older record: %v", err)
	}
	if got := reg.Get(honest.PubKey).Reputation; got != 0.5 {
		t.Fatalf("an older record replaced the entry: Reputation = %v", got)
	}
}
