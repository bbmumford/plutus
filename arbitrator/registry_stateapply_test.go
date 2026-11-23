/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package arbitrator

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
	"time"

	"github.com/bbmumford/whisper"
)

// State sync admits a profile only under the rule gossip applies: a profile
// whose signature does not verify, or whose fee is above the ceiling, is
// refused by Apply as OnBroadcast drops it.
func TestStateApplyRefusesWhatGossipRefuses(t *testing.T) {
	reg := NewArbitratorRegistry(whisper.NewEngine(), nil)
	store := &arbitratorStateStore{registry: reg}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	honest := ArbitratorProfile{PubKey: pub, ChainAddrs: map[string]string{"ethereum": "0xHONEST"},
		FeeBPS: 100, RegisteredAt: time.Now()}
	if err := SignProfile(&honest, priv); err != nil {
		t.Fatalf("SignProfile: %v", err)
	}
	b, _ := json.Marshal(honest)
	if err := store.Apply(b); err != nil {
		t.Fatalf("Apply refused a signed profile: %v", err)
	}

	forged := honest
	forged.ChainAddrs = map[string]string{"ethereum": "0xATTACKER"}
	forged.RegisteredAt = honest.RegisteredAt.Add(time.Hour)
	b, _ = json.Marshal(forged)
	if err := store.Apply(b); err == nil {
		t.Fatal("Apply admitted a profile whose signature does not verify")
	}
	if got, _ := reg.Get(pub); got.ChainAddrs["ethereum"] != "0xHONEST" {
		t.Fatalf("ChainAddrs[ethereum] = %q, want 0xHONEST", got.ChainAddrs["ethereum"])
	}

	greedy := honest
	greedy.FeeBPS = maxFeeBPS + 1
	greedy.RegisteredAt = honest.RegisteredAt.Add(2 * time.Hour)
	if err := SignProfile(&greedy, priv); err != nil {
		t.Fatalf("SignProfile: %v", err)
	}
	b, _ = json.Marshal(greedy)
	if err := store.Apply(b); err == nil {
		t.Fatal("Apply admitted a fee above the ceiling")
	}
}
