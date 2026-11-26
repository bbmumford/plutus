/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

// fixedRegistration returns a fully-populated registration seeded so the
// canonical byte encoding is deterministic across test runs. Callers that
// want to test sensitivity to a specific field mutate the returned copy.
func fixedRegistration(t *testing.T) (WitnessRegistration, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return WitnessRegistration{
		PubKey:       pub,
		ChainIDs:     []string{"polygon", "ethereum"}, // intentionally unsorted
		Capabilities: []string{"tx-confirm", "balance"},
		Reputation:   0.75,
		RegisteredAt: time.Unix(1_700_000_000, 42_000_000).UTC(),
		PayoutAddresses: map[string]string{
			"polygon":  "0xPAYPoly",
			"ethereum": "0xPAYEth",
			"bitcoin":  "bc1qsomething",
		},
	}, priv
}

// TestCanonicalBytes_Deterministic verifies that canonicalBytes() is stable
// across repeated calls AND across shuffled inputs (slice order, map
// iteration order). Two registrations that are logically equivalent must
// produce byte-identical canonical forms so any peer hashing the same
// registration sees the same bytes.
func TestCanonicalBytes_Deterministic(t *testing.T) {
	t.Parallel()
	r1, _ := fixedRegistration(t)

	// Same struct twice — must be byte-identical.
	b1a, err := r1.canonicalBytes()
	if err != nil {
		t.Fatalf("canonicalBytes a: %v", err)
	}
	b1b, err := r1.canonicalBytes()
	if err != nil {
		t.Fatalf("canonicalBytes b: %v", err)
	}
	if !bytes.Equal(b1a, b1b) {
		t.Fatalf("canonicalBytes not deterministic: %q vs %q", b1a, b1b)
	}

	// Same logical content, shuffled slice order — must still be identical.
	r2 := r1
	r2.ChainIDs = []string{"ethereum", "polygon"}       // reverse order
	r2.Capabilities = []string{"balance", "tx-confirm"} // reverse order
	// Rebuild the payout map with different insertion order (not observable,
	// but exercises that the map-key sorting is what produces determinism).
	r2.PayoutAddresses = map[string]string{
		"bitcoin":  "bc1qsomething",
		"ethereum": "0xPAYEth",
		"polygon":  "0xPAYPoly",
	}
	b2, err := r2.canonicalBytes()
	if err != nil {
		t.Fatalf("canonicalBytes r2: %v", err)
	}
	if !bytes.Equal(b1a, b2) {
		t.Fatalf("canonicalBytes differs between equivalent registrations:\n  r1: %s\n  r2: %s", b1a, b2)
	}
}

// TestCanonicalBytes_Sensitivity checks that ANY meaningful change to the
// registration produces different canonical bytes. If a field is missed by
// canonicalBytes, a signature forged over one value could be reused over a
// different value.
func TestCanonicalBytes_Sensitivity(t *testing.T) {
	t.Parallel()
	base, _ := fixedRegistration(t)
	baseBytes, err := base.canonicalBytes()
	if err != nil {
		t.Fatalf("base canonicalBytes: %v", err)
	}

	mustDiffer := func(name string, mutate func(r *WitnessRegistration)) {
		t.Helper()
		r := base
		// Deep-copy slice/map fields we might mutate so the base is untouched.
		r.ChainIDs = append([]string(nil), base.ChainIDs...)
		r.Capabilities = append([]string(nil), base.Capabilities...)
		r.PayoutAddresses = map[string]string{}
		for k, v := range base.PayoutAddresses {
			r.PayoutAddresses[k] = v
		}
		r.PubKey = append(ed25519.PublicKey(nil), base.PubKey...)
		mutate(&r)
		got, err := r.canonicalBytes()
		if err != nil {
			t.Fatalf("%s canonicalBytes: %v", name, err)
		}
		if bytes.Equal(got, baseBytes) {
			t.Errorf("mutation %q did not change canonical bytes", name)
		}
	}

	mustDiffer("pubkey", func(r *WitnessRegistration) { r.PubKey[0] ^= 0xff })
	mustDiffer("chain add", func(r *WitnessRegistration) {
		r.ChainIDs = append(r.ChainIDs, "arbitrum")
	})
	mustDiffer("capability add", func(r *WitnessRegistration) {
		r.Capabilities = append(r.Capabilities, "escrow-state")
	})
	mustDiffer("reputation", func(r *WitnessRegistration) { r.Reputation = 0.76 })
	mustDiffer("registeredAt", func(r *WitnessRegistration) {
		r.RegisteredAt = r.RegisteredAt.Add(time.Nanosecond)
	})
	mustDiffer("payout add chain", func(r *WitnessRegistration) {
		r.PayoutAddresses["arbitrum"] = "0xArbPay"
	})
	mustDiffer("payout change addr", func(r *WitnessRegistration) {
		r.PayoutAddresses["polygon"] = "0xDIFFERENT"
	})
}

// TestCanonicalBytes_IncludesDomainSeparator asserts the documented domain
// string is present in the canonical payload. A registration signature must
// not be replayable as a signature over any other Plutus-domain document.
func TestCanonicalBytes_IncludesDomainSeparator(t *testing.T) {
	t.Parallel()
	r, _ := fixedRegistration(t)
	b, err := r.canonicalBytes()
	if err != nil {
		t.Fatalf("canonicalBytes: %v", err)
	}
	if !bytes.Contains(b, []byte(witnessRegistrationDomain)) {
		t.Errorf("canonical bytes missing domain separator %q: %s", witnessRegistrationDomain, b)
	}
}

// TestSignVerify_RoundTrip verifies the happy path: Sign produces a
// signature that Verify accepts.
func TestSignVerify_RoundTrip(t *testing.T) {
	t.Parallel()
	r, priv := fixedRegistration(t)
	if err := r.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(r.Signature) != ed25519.SignatureSize {
		t.Fatalf("Sign produced %d-byte signature, want %d", len(r.Signature), ed25519.SignatureSize)
	}
	if err := r.Verify(); err != nil {
		t.Fatalf("Verify after Sign: %v", err)
	}
}

// TestSign_RejectsMismatchedKeys verifies Sign refuses to produce a
// signature when the provided private key does not correspond to r.PubKey,
// which would otherwise yield an unverifiable signature.
func TestSign_RejectsMismatchedKeys(t *testing.T) {
	t.Parallel()
	r, _ := fixedRegistration(t)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := r.Sign(otherPriv); err == nil {
		t.Fatalf("Sign with mismatched key should error")
	}
}

// TestVerify_DetectsMutation asserts Verify catches any post-sign field
// mutation. This is the whole point of having a signature — if Verify does
// not reject a mutation, the signature provides no integrity guarantee.
func TestVerify_DetectsMutation(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(r *WitnessRegistration)
	}{
		{"reputation", func(r *WitnessRegistration) { r.Reputation = 1.0 }},
		{"chain add", func(r *WitnessRegistration) { r.ChainIDs = append(r.ChainIDs, "arbitrum") }},
		{"capability add", func(r *WitnessRegistration) { r.Capabilities = append(r.Capabilities, "bogus") }},
		{"registeredAt shift", func(r *WitnessRegistration) { r.RegisteredAt = r.RegisteredAt.Add(time.Second) }},
		{"payout add", func(r *WitnessRegistration) {
			if r.PayoutAddresses == nil {
				r.PayoutAddresses = map[string]string{}
			}
			r.PayoutAddresses["arbitrum"] = "0xForged"
		}},
		{"payout change", func(r *WitnessRegistration) { r.PayoutAddresses["polygon"] = "0xForged" }},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, priv := fixedRegistration(t)
			if err := r.Sign(priv); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			tc.mutate(&r)
			if err := r.Verify(); err == nil {
				t.Fatalf("Verify accepted mutated registration (%s)", tc.name)
			}
		})
	}
}

// TestVerify_RejectsMissing checks the obvious no-signature / short-signature
// paths so Verify cannot be silently bypassed by setting r.Signature to nil.
func TestVerify_RejectsMissing(t *testing.T) {
	t.Parallel()
	r, _ := fixedRegistration(t)
	if err := r.Verify(); err == nil {
		t.Error("Verify on unsigned registration should error")
	}
	r.Signature = []byte{1, 2, 3}
	if err := r.Verify(); err == nil {
		t.Error("Verify on short signature should error")
	}
}
