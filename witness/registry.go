/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/bbmumford/plutus/canonical"
	"github.com/bbmumford/plutus/internal/gossipstate"

	ledger "github.com/bbmumford/ledger"
	"github.com/bbmumford/ledger/cache"
	"github.com/bbmumford/whisper"
)

// witnessRegistrationDomain is the domain separator mixed into the canonical
// signing bytes so that a signature over a WitnessRegistration cannot be
// replayed as a signature over any other Plutus-domain payload.
const witnessRegistrationDomain = "plutus.witness.registration.v1"

// topicWitnesses is resolved at init time from the protocol fingerprint so
// that forked deployments with a different trust chain use different topics.
var topicWitnesses string

func init() {
	topicWitnesses = canonical.WitnessTopic()
}

// witnessRegistrationWire is the JSON wire format for gossip serialization.
type witnessRegistrationWire struct {
	PubKey          []byte            `json:"pubKey"`
	ChainIDs        []string          `json:"chainIds"`
	Capabilities    []string          `json:"capabilities"`
	Reputation      float64           `json:"reputation"`
	RegisteredAt    int64             `json:"registeredAt"` // unix nanos
	PayoutAddresses map[string]string `json:"payoutAddresses,omitempty"`
	Signature       []byte            `json:"signature"`
}

// WitnessRegistration describes a node that is willing to attest chain state.
// Registrations are gossiped via the plutus.witnesses BroadcastOnly topic and
// cached locally for quick lookup by chain ID.
//
// A registration is authenticated by an Ed25519 signature over a canonical
// byte encoding of all other fields. Producers MUST call Sign with the
// private key that corresponds to PubKey before handing the registration to
// Registry.Register; consumers MUST call Verify before acting on a
// registration received over the wire.
type WitnessRegistration struct {
	PubKey       ed25519.PublicKey
	ChainIDs     []string
	Capabilities []string // e.g. "tx-confirm", "balance", "escrow-state", "broadcast"
	Reputation   float64
	RegisteredAt time.Time

	// PayoutAddresses maps chainID -> on-chain address where this witness wants
	// its share of fee distributions delivered. Format is chain-specific
	// (0x-hex for EVM, bech32 for BTC, etc.). Callers are expected to populate
	// at least one entry per chain in ChainIDs; the fee distributor will skip
	// any (witness, chain) pair that has no configured address.
	PayoutAddresses map[string]string

	// Signature is the Ed25519 signature produced by Sign() over the canonical
	// bytes of the registration (all other fields, domain-separated). Zero or
	// nil until Sign() has been called. Registry.Register rejects registrations
	// whose signature does not verify.
	Signature []byte
}

// canonicalRegistration is the deterministic, signed-over shape of a
// WitnessRegistration. JSON key ordering follows the struct field
// declaration order (stdlib encoding/json guarantees), slice elements are
// pre-sorted, and the map is materialised as a sorted key/value slice pair
// so that different peers hashing the same logical registration produce
// byte-identical output.
type canonicalRegistration struct {
	Domain           string   `json:"domain"`
	PubKey           []byte   `json:"pubKey"`
	ChainIDs         []string `json:"chainIds"`
	Capabilities     []string `json:"capabilities"`
	Reputation       float64  `json:"reputation"`
	RegisteredAtUnix int64    `json:"registeredAtUnixNano"`
	RegisteredAtRFC  string   `json:"registeredAt"` // RFC3339Nano, redundant with unix for human audit
	PayoutChainIDs   []string `json:"payoutChainIds"`
	PayoutAddresses  []string `json:"payoutAddresses"`
}

// canonicalBytes returns the deterministic byte encoding that Sign signs and
// that Verify re-hashes. The format is a domain-separated JSON document with
// stable field ordering (declaration order), pre-sorted slice elements, and a
// sorted parallel-slice encoding of PayoutAddresses so that Go map iteration
// order cannot perturb the output.
//
// Signature is intentionally excluded: the signature is computed over these
// bytes, so including it would create a chicken-and-egg loop.
func (r *WitnessRegistration) canonicalBytes() ([]byte, error) {
	if r == nil {
		return nil, errors.New("witness: canonicalBytes on nil registration")
	}

	// Normalise repeated string fields: copy (so we don't mutate the caller's
	// slice) then sort ascending. nil is preserved as nil (JSON encodes as null),
	// but an empty non-nil slice is preserved as [].
	var chains []string
	if r.ChainIDs != nil {
		chains = append([]string(nil), r.ChainIDs...)
		sort.Strings(chains)
	}
	var caps []string
	if r.Capabilities != nil {
		caps = append([]string(nil), r.Capabilities...)
		sort.Strings(caps)
	}

	// Materialise PayoutAddresses as two parallel sorted slices so the
	// canonical form is map-iteration-order-independent.
	keys := make([]string, 0, len(r.PayoutAddresses))
	for k := range r.PayoutAddresses {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	vals := make([]string, 0, len(keys))
	for _, k := range keys {
		vals = append(vals, r.PayoutAddresses[k])
	}

	// RegisteredAt: we include BOTH the UnixNano int and the RFC3339Nano
	// string. UnixNano is the authoritative field for hashing (drops monotonic
	// clock readings and zone info); the RFC3339Nano string is redundant but
	// human-readable on audit. We normalise the time to UTC before formatting
	// so a registration created in different zones produces the same bytes.
	t := r.RegisteredAt.UTC()

	doc := canonicalRegistration{
		Domain:           witnessRegistrationDomain,
		PubKey:           []byte(r.PubKey),
		ChainIDs:         chains,
		Capabilities:     caps,
		Reputation:       r.Reputation,
		RegisteredAtUnix: t.UnixNano(),
		RegisteredAtRFC:  t.Format(time.RFC3339Nano),
		PayoutChainIDs:   keys,
		PayoutAddresses:  vals,
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, fmt.Errorf("witness: canonical encode: %w", err)
	}
	// json.Encoder.Encode appends a trailing '\n'; strip it so the byte
	// sequence is exactly the encoded document (no trailing whitespace).
	out := buf.Bytes()
	if n := len(out); n > 0 && out[n-1] == '\n' {
		out = out[:n-1]
	}
	return out, nil
}

// Sign fills r.Signature with an Ed25519 signature over r.canonicalBytes().
// priv MUST be the private key corresponding to r.PubKey; mismatched keys
// are rejected rather than allowed to produce an unverifiable signature.
// Any existing value in r.Signature is overwritten.
func (r *WitnessRegistration) Sign(priv ed25519.PrivateKey) error {
	if r == nil {
		return errors.New("witness: Sign on nil registration")
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("witness: invalid private key size %d", len(priv))
	}
	if len(r.PubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("witness: invalid public key size %d", len(r.PubKey))
	}
	// Guard against ed25519.Sign segfaulting / producing garbage on a
	// priv/pub mismatch by checking the derived public key up front.
	derivedPub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("witness: private key does not yield ed25519 public key")
	}
	if !bytes.Equal(derivedPub, r.PubKey) {
		return errors.New("witness: private key does not match registration public key")
	}
	payload, err := r.canonicalBytes()
	if err != nil {
		return err
	}
	r.Signature = ed25519.Sign(priv, payload)
	return nil
}

// Verify checks r.Signature against r.canonicalBytes() using r.PubKey.
// Returns a non-nil error if the public key is malformed, the signature is
// missing, or the signature does not verify.
func (r *WitnessRegistration) Verify() error {
	if r == nil {
		return errors.New("witness: Verify on nil registration")
	}
	if len(r.PubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("witness: invalid public key size %d", len(r.PubKey))
	}
	if len(r.Signature) == 0 {
		return errors.New("witness: registration has no signature")
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("witness: invalid signature size %d", len(r.Signature))
	}
	payload, err := r.canonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(r.PubKey, payload, r.Signature) {
		return errors.New("witness: signature does not verify")
	}
	return nil
}

// WitnessRegistry tracks which nodes are registered as witnesses and what
// chains they can attest. Backed by Whisper gossip and Ledger storage.
type WitnessRegistry struct {
	engine  *whisper.Engine
	cache   *cache.DirectoryCache
	mu      sync.RWMutex
	entries map[string]*WitnessRegistration // hex(pubkey) -> registration
}

// NewWitnessRegistry creates a registry wired to Whisper for gossip
// propagation and Ledger for persistent storage. It registers the
// plutus.witnesses topic as StatefulMerge (with delta-sync) and
// subscribes to receive remote registrations.
func NewWitnessRegistry(engine *whisper.Engine, c *cache.DirectoryCache) *WitnessRegistry {
	r := &WitnessRegistry{
		engine:  engine,
		cache:   c,
		entries: make(map[string]*WitnessRegistration),
	}

	// Register as StatefulMerge so witness registrations are durably stored
	// and delta-synced between peers, not just fire-and-forget broadcast.
	_ = engine.RegisterTopic(topicWitnesses, whisper.TopicConfig{
		Mode:  whisper.StatefulMerge,
		Store: &witnessStateStore{cache: c, registry: r},
	})

	// Subscribe to receive remote witness registrations via gossip.
	engine.Subscribe(topicWitnesses, r)

	return r
}

// OnBroadcast implements whisper.Subscriber. It receives witness registrations
// gossiped by remote peers and merges them into the local registry.
func (r *WitnessRegistry) OnBroadcast(topic string, from string, payload []byte) {
	if topic != topicWitnesses {
		return
	}

	var wire witnessRegistrationWire
	if err := json.Unmarshal(payload, &wire); err != nil {
		return
	}

	reg := WitnessRegistration{
		PubKey:          ed25519.PublicKey(wire.PubKey),
		ChainIDs:        wire.ChainIDs,
		Capabilities:    wire.Capabilities,
		Reputation:      wire.Reputation,
		RegisteredAt:    time.Unix(0, wire.RegisteredAt),
		PayoutAddresses: wire.PayoutAddresses,
		Signature:       wire.Signature,
	}

	// Silently drop a refused record: gossip frames are best-effort, and a log
	// line per forged drop would give an attacker an oracle.
	_ = r.merge(&reg)
}

// merge admits one registration a peer sent, by gossip (OnBroadcast) or by
// state sync (witnessStateStore.Apply), under one rule, decided and applied
// under one hold of r.mu so the entry it judged against is the entry it
// replaces:
//
//   - A record whose signature verifies is admitted when it is newer than the
//     entry held, or when no entry is held.
//   - A record whose signature does not verify is admitted only as a
//     reputation update of a held entry: everything but Reputation and
//     RegisteredAt equal to the held entry, the signature included, and
//     RegisteredAt later. UpdateReputation re-publishes a record that way,
//     keeping the original signature over fields it did not change, because
//     reputation is a local observation and not an attester-signed claim.
//   - Anything else is refused: an unsigned new witness, or an unsigned change
//     to its chains, capabilities or PayoutAddresses, which would let any peer
//     redirect a witness's fee payouts.
func (r *WitnessRegistry) merge(reg *WitnessRegistration) error {
	if len(reg.PubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("witness: invalid public key in registration")
	}
	key := hex.EncodeToString(reg.PubKey)

	r.mu.Lock()
	defer r.mu.Unlock()

	existing, haveExisting := r.entries[key]
	if haveExisting && !reg.RegisteredAt.After(existing.RegisteredAt) {
		return nil
	}
	if !(haveExisting && reputationOnlyUpdate(existing, reg)) {
		if err := reg.Verify(); err != nil {
			return fmt.Errorf("witness: the registration's signature does not verify: %w", err)
		}
	}
	r.entries[key] = reg
	return nil
}

// reputationOnlyUpdate reports whether next differs from held in Reputation and
// RegisteredAt alone, the only fields UpdateReputation changes without
// re-signing.
func reputationOnlyUpdate(held, next *WitnessRegistration) bool {
	return bytes.Equal(held.Signature, next.Signature) &&
		stringsEqual(held.ChainIDs, next.ChainIDs) &&
		stringsEqual(held.Capabilities, next.Capabilities) &&
		payoutAddressesEqual(held.PayoutAddresses, next.PayoutAddresses)
}

func stringsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// payoutAddressesEqual reports whether two payout-address maps describe
// byte-identical on-chain payout targets. A nil map and an empty map are
// treated as equal. Used by OnBroadcast to decide whether a gossiped
// registration requires signature verification: any change to the payout
// address map is a security-sensitive mutation and MUST carry a valid sig.
func payoutAddressesEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok || va != vb {
			return false
		}
	}
	return true
}

// Register adds or updates a witness registration. The registration must have
// a valid public key. After updating the local map, the registration is
// serialized and published on the plutus.witnesses gossip topic for
// propagation to remote peers, and written to the Ledger cache for persistence.
func (r *WitnessRegistry) Register(reg WitnessRegistration) error {
	if len(reg.PubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("witness: invalid public key size %d", len(reg.PubKey))
	}
	if len(reg.ChainIDs) == 0 {
		return fmt.Errorf("witness: registration must include at least one chain ID")
	}
	if reg.RegisteredAt.IsZero() {
		// RegisteredAt is part of the signed canonical bytes, so we cannot
		// mutate it after the caller has signed. Reject here rather than
		// silently break signature verification.
		return fmt.Errorf("witness: registration must set RegisteredAt before signing")
	}

	// A registration is only trustworthy if it carries a valid Ed25519
	// signature over its canonical bytes. We verify BEFORE storing so that a
	// forged record cannot even be cached locally; callers must Sign() the
	// registration with the witness private key before handing it here.
	if err := reg.Verify(); err != nil {
		return fmt.Errorf("witness: registration signature invalid: %w", err)
	}

	key := hex.EncodeToString(reg.PubKey)

	r.mu.Lock()
	r.entries[key] = &reg
	r.mu.Unlock()

	// Serialize for gossip propagation.
	wire := witnessRegistrationWire{
		PubKey:          []byte(reg.PubKey),
		ChainIDs:        reg.ChainIDs,
		Capabilities:    reg.Capabilities,
		Reputation:      reg.Reputation,
		RegisteredAt:    reg.RegisteredAt.UnixNano(),
		PayoutAddresses: reg.PayoutAddresses,
		Signature:       reg.Signature,
	}
	data, err := json.Marshal(wire)
	if err != nil {
		return fmt.Errorf("witness: marshal registration: %w", err)
	}

	// Publish to Whisper gossip for remote peers.
	if err := r.engine.Publish(topicWitnesses, data); err != nil {
		// Log but do not fail the registration -- local state is already updated.
		_ = err
	}

	// Persist to Ledger cache for durability across restarts.
	if r.cache != nil {
		rec := ledger.Record{
			Topic:     ledger.Topic(topicWitnesses),
			NodeID:    key,
			Body:      data,
			Timestamp: reg.RegisteredAt,
		}
		_ = r.cache.Apply(rec)
	}

	return nil
}

// Unregister removes a witness from the registry.
func (r *WitnessRegistry) Unregister(pubkey ed25519.PublicKey) error {
	if len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("witness: invalid public key size %d", len(pubkey))
	}
	key := hex.EncodeToString(pubkey)

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.entries[key]; !ok {
		return fmt.Errorf("witness: no registration found for %s", key[:16])
	}
	delete(r.entries, key)
	return nil
}

// FindForChain returns all registered witnesses that support the given chain.
// Results are sorted by reputation (highest first).
func (r *WitnessRegistry) FindForChain(chainID string) []WitnessRegistration {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []WitnessRegistration
	for _, reg := range r.entries {
		for _, cid := range reg.ChainIDs {
			if cid == chainID {
				results = append(results, *reg)
				break
			}
		}
	}

	// Sort by reputation descending (simple insertion sort — registries are small)
	for i := 1; i < len(results); i++ {
		for j := i; j > 0 && results[j].Reputation > results[j-1].Reputation; j-- {
			results[j], results[j-1] = results[j-1], results[j]
		}
	}

	return results
}

// UpdateReputation adjusts a witness's reputation score by delta. The score
// is clamped to [0.0, 1.0]. The change is encoded in the registration record
// and gossiped via the StatefulMerge witness topic so all peers converge on
// the same reputation state (CRDT-synced via Ledger).
func (r *WitnessRegistry) UpdateReputation(pubkey ed25519.PublicKey, delta float64) {
	key := hex.EncodeToString(pubkey)

	r.mu.Lock()
	reg, ok := r.entries[key]
	if !ok {
		r.mu.Unlock()
		return
	}
	reg.Reputation += delta
	if reg.Reputation > 1.0 {
		reg.Reputation = 1.0
	}
	if reg.Reputation < 0.0 {
		reg.Reputation = 0.0
	}
	// Bump timestamp so the updated record wins during merge.
	reg.RegisteredAt = time.Now()
	regCopy := *reg
	r.mu.Unlock()

	// Gossip the updated registration with new reputation via StatefulMerge.
	// This ensures all peers converge on the same reputation value.
	wire := witnessRegistrationWire{
		PubKey:          []byte(regCopy.PubKey),
		ChainIDs:        regCopy.ChainIDs,
		Capabilities:    regCopy.Capabilities,
		Reputation:      regCopy.Reputation,
		RegisteredAt:    regCopy.RegisteredAt.UnixNano(),
		PayoutAddresses: regCopy.PayoutAddresses,
		Signature:       regCopy.Signature,
	}
	data, err := json.Marshal(wire)
	if err != nil {
		return
	}

	// Publish to gossip so remote peers receive the reputation update.
	_ = r.engine.Publish(topicWitnesses, data)

	// Persist to Ledger cache as a StatefulMerge record.
	if r.cache != nil {
		rec := ledger.Record{
			Topic:     ledger.Topic(topicWitnesses),
			NodeID:    key,
			Body:      data,
			Timestamp: regCopy.RegisteredAt,
		}
		_ = r.cache.Apply(rec)
	}
}

// Get returns the registration for a specific public key, or nil if not found.
func (r *WitnessRegistry) Get(pubkey ed25519.PublicKey) *WitnessRegistration {
	key := hex.EncodeToString(pubkey)
	r.mu.RLock()
	defer r.mu.RUnlock()
	reg, ok := r.entries[key]
	if !ok {
		return nil
	}
	cp := *reg
	return &cp
}

// Count returns the number of registered witnesses.
func (r *WitnessRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// witnessStateStore implements whisper.StateStore for the witness
// StatefulMerge topic. Same pattern as arbitratorStateStore.
type witnessStateStore struct {
	cache    *cache.DirectoryCache
	registry *WitnessRegistry
}

// Fingerprint summarises every witness record for whisper's G2 digest.
func (s *witnessStateStore) Fingerprint() uint64 {
	return gossipstate.Fingerprint(s.Snapshot())
}

// Snapshot returns every witness registration in its wire form; a
// registration that fails to marshal is left out so it does not block
// the rest.
func (s *witnessStateStore) Snapshot() [][]byte {
	s.registry.mu.RLock()
	defer s.registry.mu.RUnlock()

	records := make([][]byte, 0, len(s.registry.entries))
	for _, reg := range s.registry.entries {
		wire := witnessRegistrationWire{
			PubKey:          []byte(reg.PubKey),
			ChainIDs:        reg.ChainIDs,
			Capabilities:    reg.Capabilities,
			Reputation:      reg.Reputation,
			RegisteredAt:    reg.RegisteredAt.UnixNano(),
			PayoutAddresses: reg.PayoutAddresses,
			Signature:       reg.Signature,
		}
		data, err := json.Marshal(wire)
		if err != nil {
			continue
		}
		records = append(records, data)
	}
	return records
}

// Delta returns the full snapshot: a registration's RegisteredAt is
// stamped by its author, not by the local Apply, so filtering on it would
// drop a registration that reached this node after the peer's watermark.
func (s *witnessStateStore) Delta(_ time.Time) [][]byte {
	return s.Snapshot()
}

// Apply stores an incoming witness record, merging by timestamp.
func (s *witnessStateStore) Apply(data []byte) error {
	var wire witnessRegistrationWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("witness: unmarshal state record: %w", err)
	}

	if len(wire.PubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("witness: invalid public key in state record")
	}

	reg := &WitnessRegistration{
		PubKey:          ed25519.PublicKey(wire.PubKey),
		ChainIDs:        wire.ChainIDs,
		Capabilities:    wire.Capabilities,
		Reputation:      wire.Reputation,
		RegisteredAt:    time.Unix(0, wire.RegisteredAt),
		PayoutAddresses: wire.PayoutAddresses,
		Signature:       wire.Signature,
	}
	return s.registry.merge(reg)
}
