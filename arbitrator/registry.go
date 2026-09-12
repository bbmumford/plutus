/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package arbitrator

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/bbmumford/plutus/canonical"

	"github.com/bbmumford/ledger/cache"
	"github.com/bbmumford/whisper"
)

// topicArbitrators is resolved at init time from the protocol fingerprint
// for network isolation.
var topicArbitrators string

func init() {
	topicArbitrators = canonical.ArbitratorTopic()
}

const (
	// maxFeeBPS is the hard cap on arbitrator fee basis points.
	maxFeeBPS = 300

	// maxCategories limits the number of categories an arbitrator can register.
	maxCategories = 10

	// maxBioLength caps the bio field to prevent gossip abuse.
	maxBioLength = 1024
)

// ArbitratorProfile describes a registered arbitrator and their availability,
// fee structure, and expertise categories. Profiles are gossiped via the
// plutus.arbitrators StatefulMerge topic.
type ArbitratorProfile struct {
	PubKey       ed25519.PublicKey  `json:"pubKey"`
	ChainAddrs   map[string]string `json:"chainAddrs"`   // chainID -> chain address
	FeeBPS       uint32            `json:"feeBPS"`        // capped at 300
	Categories   []string          `json:"categories"`    // expertise: "digital-goods", "services", "physical"
	Availability bool              `json:"availability"`
	Bio          string            `json:"bio"`
	Signature    []byte            `json:"signature"`
	RegisteredAt time.Time         `json:"registeredAt"`
}

// profileDigest computes the SHA-256 hash of all profile fields except Signature.
// This is the message that gets signed by the arbitrator.
func profileDigest(p *ArbitratorProfile) []byte {
	h := sha256.New()
	h.Write(p.PubKey)

	// Deterministic chain addresses: sort keys via JSON marshalling
	chainJSON, _ := json.Marshal(p.ChainAddrs)
	h.Write(chainJSON)

	var feeBuf [4]byte
	binary.BigEndian.PutUint32(feeBuf[:], p.FeeBPS)
	h.Write(feeBuf[:])

	catJSON, _ := json.Marshal(p.Categories)
	h.Write(catJSON)

	if p.Availability {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}

	h.Write([]byte(p.Bio))

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(p.RegisteredAt.UnixNano()))
	h.Write(tsBuf[:])

	return h.Sum(nil)
}

// SignProfile signs the profile with the arbitrator's Ed25519 private key.
func SignProfile(p *ArbitratorProfile, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("arbitrator: invalid private key size %d", len(privateKey))
	}
	digest := profileDigest(p)
	p.Signature = ed25519.Sign(privateKey, digest)
	return nil
}

// VerifyProfile checks that the profile's signature is valid.
func VerifyProfile(p *ArbitratorProfile) bool {
	if len(p.PubKey) != ed25519.PublicKeySize {
		return false
	}
	if len(p.Signature) != ed25519.SignatureSize {
		return false
	}
	digest := profileDigest(p)
	return ed25519.Verify(p.PubKey, digest, p.Signature)
}

// ArbitratorRegistry tracks arbitrator profiles via Whisper gossip and Ledger
// storage. Profiles are gossiped on the plutus.arbitrators StatefulMerge topic.
type ArbitratorRegistry struct {
	engine *whisper.Engine
	cache  *cache.DirectoryCache

	mu      sync.RWMutex
	entries map[string]*ArbitratorProfile // hex(pubkey) -> profile
}

// NewArbitratorRegistry creates a registry wired to Whisper for gossip
// propagation and Ledger for persistent storage.
func NewArbitratorRegistry(engine *whisper.Engine, c *cache.DirectoryCache) *ArbitratorRegistry {
	r := &ArbitratorRegistry{
		engine:  engine,
		cache:   c,
		entries: make(map[string]*ArbitratorProfile),
	}

	// Register the StatefulMerge topic before subscribing so that
	// delta-sync and Apply work correctly for arbitrator records.
	engine.RegisterTopic(topicArbitrators, whisper.TopicConfig{
		Mode:  whisper.StatefulMerge,
		Store: &arbitratorStateStore{cache: c, registry: r},
	})

	engine.Subscribe(topicArbitrators, r)
	return r
}

// Register adds or updates an arbitrator profile. The profile must have a valid
// public key and signature, and the fee must not exceed the hard cap.
func (r *ArbitratorRegistry) Register(profile ArbitratorProfile) error {
	if len(profile.PubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("arbitrator: invalid public key size %d", len(profile.PubKey))
	}
	if profile.FeeBPS > maxFeeBPS {
		return fmt.Errorf("arbitrator: fee %d BPS exceeds cap %d", profile.FeeBPS, maxFeeBPS)
	}
	if len(profile.ChainAddrs) == 0 {
		return fmt.Errorf("arbitrator: must have at least one chain address")
	}
	if len(profile.Categories) == 0 {
		return fmt.Errorf("arbitrator: must have at least one category")
	}
	if len(profile.Categories) > maxCategories {
		return fmt.Errorf("arbitrator: categories count %d exceeds limit %d", len(profile.Categories), maxCategories)
	}
	if len(profile.Bio) > maxBioLength {
		return fmt.Errorf("arbitrator: bio length %d exceeds limit %d", len(profile.Bio), maxBioLength)
	}
	if !VerifyProfile(&profile) {
		return fmt.Errorf("arbitrator: invalid signature")
	}
	if profile.RegisteredAt.IsZero() {
		profile.RegisteredAt = time.Now()
	}

	key := hex.EncodeToString(profile.PubKey)

	r.mu.Lock()
	r.entries[key] = &profile
	r.mu.Unlock()

	// Gossip the registration via Whisper. For StatefulMerge topics, we apply
	// to the topic's StateStore. If the topic is not yet registered, we
	// serialize and publish for propagation.
	payload, err := json.Marshal(profile)
	if err != nil {
		return fmt.Errorf("arbitrator: marshal profile: %w", err)
	}

	cfg, ok := r.engine.Registry().Get(topicArbitrators)
	if ok && cfg.Store != nil {
		if err := cfg.Store.Apply(topicArbitrators, payload); err != nil {
			return fmt.Errorf("arbitrator: apply to state store: %w", err)
		}
	}

	return nil
}

// Unregister removes an arbitrator from the registry and publishes a
// tombstone record so remote peers learn about the removal via gossip.
func (r *ArbitratorRegistry) Unregister(pubkey ed25519.PublicKey) error {
	if len(pubkey) != ed25519.PublicKeySize {
		return fmt.Errorf("arbitrator: invalid public key size %d", len(pubkey))
	}
	key := hex.EncodeToString(pubkey)

	r.mu.Lock()
	existing, ok := r.entries[key]
	if !ok {
		r.mu.Unlock()
		return fmt.Errorf("arbitrator: no registration found for %s", key[:16])
	}
	delete(r.entries, key)
	r.mu.Unlock()

	// Publish a tombstone: an unavailable profile with a newer timestamp so
	// remote peers merge it and mark this arbitrator as removed.
	tombstone := *existing
	tombstone.Availability = false
	tombstone.RegisteredAt = time.Now()

	payload, err := json.Marshal(tombstone)
	if err != nil {
		return fmt.Errorf("arbitrator: marshal tombstone: %w", err)
	}

	cfg, ok := r.engine.Registry().Get(topicArbitrators)
	if ok && cfg.Store != nil {
		if err := cfg.Store.Apply(topicArbitrators, payload); err != nil {
			return fmt.Errorf("arbitrator: apply tombstone to state store: %w", err)
		}
	}

	return nil
}

// Find returns arbitrators matching the given category and chain ID.
// Results are filtered by availability. Both category and chainID can be empty
// to match all.
func (r *ArbitratorRegistry) Find(category, chainID string) []ArbitratorProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var results []ArbitratorProfile
	for _, prof := range r.entries {
		if !prof.Availability {
			continue
		}

		// Category filter
		if category != "" {
			found := false
			for _, cat := range prof.Categories {
				if cat == category {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Chain ID filter
		if chainID != "" {
			if _, ok := prof.ChainAddrs[chainID]; !ok {
				continue
			}
		}

		results = append(results, *prof)
	}

	return results
}

// Get returns the profile for a specific public key, or false if not found.
func (r *ArbitratorRegistry) Get(pubkey ed25519.PublicKey) (*ArbitratorProfile, bool) {
	key := hex.EncodeToString(pubkey)
	r.mu.RLock()
	defer r.mu.RUnlock()
	prof, ok := r.entries[key]
	if !ok {
		return nil, false
	}
	cp := *prof
	return &cp, true
}

// All returns all registered arbitrator profiles.
func (r *ArbitratorRegistry) All() []ArbitratorProfile {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ArbitratorProfile, 0, len(r.entries))
	for _, prof := range r.entries {
		result = append(result, *prof)
	}
	return result
}

// Count returns the number of registered arbitrators.
func (r *ArbitratorRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// OnBroadcast implements whisper.Subscriber. It receives gossiped arbitrator
// profiles and merges them into the local registry.
func (r *ArbitratorRegistry) OnBroadcast(topic string, from string, payload []byte) {
	if topic != topicArbitrators {
		return
	}

	var profile ArbitratorProfile
	if err := json.Unmarshal(payload, &profile); err != nil {
		return
	}

	// Validate before accepting
	if len(profile.PubKey) != ed25519.PublicKeySize {
		return
	}
	if profile.FeeBPS > maxFeeBPS {
		return
	}
	if !VerifyProfile(&profile) {
		return
	}

	key := hex.EncodeToString(profile.PubKey)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Only accept if newer than existing entry
	existing, ok := r.entries[key]
	if ok && !profile.RegisteredAt.After(existing.RegisteredAt) {
		return
	}
	r.entries[key] = &profile
}

// arbitratorStateStore implements whisper.StateStore for the arbitrator
// StatefulMerge topic. It wraps the Ledger cache for persistent storage
// and the in-memory registry for fast lookups.
type arbitratorStateStore struct {
	cache    *cache.DirectoryCache
	registry *ArbitratorRegistry

	mu        sync.Mutex
	watermark uint64
}

// Fingerprint returns a cache fingerprint for delta-sync optimisation.
func (s *arbitratorStateStore) Fingerprint(_ string) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.watermark
}

// DeltaSince returns arbitrator records changed since the given watermark.
// For simplicity, if the caller is behind we return all current entries.
func (s *arbitratorStateStore) DeltaSince(_ string, since uint64) ([][]byte, uint64, error) {
	s.mu.Lock()
	current := s.watermark
	s.mu.Unlock()

	if since >= current {
		return nil, current, nil
	}

	s.registry.mu.RLock()
	defer s.registry.mu.RUnlock()

	records := make([][]byte, 0, len(s.registry.entries))
	for _, prof := range s.registry.entries {
		data, err := json.Marshal(prof)
		if err != nil {
			continue
		}
		records = append(records, data)
	}
	return records, current, nil
}

// Apply stores an incoming arbitrator record, merging by timestamp.
func (s *arbitratorStateStore) Apply(_ string, data []byte) error {
	var profile ArbitratorProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("arbitrator: unmarshal state record: %w", err)
	}

	if len(profile.PubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("arbitrator: invalid public key in state record")
	}

	key := hex.EncodeToString(profile.PubKey)

	s.registry.mu.Lock()
	existing, ok := s.registry.entries[key]
	if !ok || profile.RegisteredAt.After(existing.RegisteredAt) {
		s.registry.entries[key] = &profile
	}
	s.registry.mu.Unlock()

	s.mu.Lock()
	s.watermark++
	s.mu.Unlock()

	return nil
}
