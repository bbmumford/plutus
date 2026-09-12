package adapter

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// AdapterDescriptor is the signed metadata blob distributed with each adapter.
// The maintainer signs the descriptor with their Ed25519 key; wallets verify
// the signature against the PRC-registered public key hash before loading.
type AdapterDescriptor struct {
	ChainID    string `json:"chainID"`
	Currency   string `json:"currency"`
	Symbol     string `json:"symbol"`
	Version    string `json:"version"`
	PRCAddress string `json:"prcAddress"`
	// ProtocolFingerprint is the expected protocol fingerprint at signing time.
	// If non-empty, it must match the current ProtocolFingerprint() for the
	// adapter to be accepted. This prevents a forked deployment from loading
	// adapters signed for the canonical network and vice versa.
	ProtocolFingerprint string `json:"protocolFingerprint,omitempty"`
	// AdapterHash is the SHA256 of the adapter binary/WASM blob.
	AdapterHash []byte `json:"adapterHash"`
	// SignerPubKey is the Ed25519 public key that produced Signature.
	SignerPubKey ed25519.PublicKey `json:"signerPubKey"`
	// Signature is the Ed25519 signature over the canonical descriptor payload
	// (all fields except Signature itself).
	Signature []byte `json:"signature"`
}

// descriptorPayload returns the canonical bytes that are signed.
func (d *AdapterDescriptor) descriptorPayload() []byte {
	// Deterministic JSON of the signing-relevant fields.
	payload := struct {
		ChainID             string `json:"chainID"`
		Currency            string `json:"currency"`
		Symbol              string `json:"symbol"`
		Version             string `json:"version"`
		PRCAddress          string `json:"prcAddress"`
		ProtocolFingerprint string `json:"protocolFingerprint,omitempty"`
		AdapterHash         []byte `json:"adapterHash"`
	}{
		ChainID:             d.ChainID,
		Currency:            d.Currency,
		Symbol:              d.Symbol,
		Version:             d.Version,
		PRCAddress:          d.PRCAddress,
		ProtocolFingerprint: d.ProtocolFingerprint,
		AdapterHash:         d.AdapterHash,
	}
	b, _ := json.Marshal(payload)
	return b
}

// Registry manages loaded and verified currency adapters. Adapters must pass
// signature verification against the PRC maintainer public key hash before
// they are accepted into the registry.
//
// The registry also stores per-(chainID, currency) PayoutBuilder values used
// by the witness fee distributor. These are stored as `any` rather than a
// typed interface because the canonical PayoutBuilder interface lives in the
// witness package (which itself imports adapter for FeeBreakdown — a direct
// typed reference here would form an import cycle). Callers cast the result
// of ResolvePayoutBuilder to their expected interface. The BTC builder in
// adapter/btc implements witness.PayoutBuilder directly so a thin
// sdk-level wrapper can hand results straight to the fee distributor.
type Registry struct {
	mu             sync.RWMutex
	adapters       map[string]registryEntry // key: chainID + ":" + symbol
	payoutBuilders map[string]any           // key: chainID + ":" + currency
}

type registryEntry struct {
	adapter    CurrencyAdapter
	descriptor AdapterDescriptor
	info       AdapterInfo
}

// NewRegistry creates an empty adapter registry.
func NewRegistry() *Registry {
	return &Registry{
		adapters:       make(map[string]registryEntry),
		payoutBuilders: make(map[string]any),
	}
}

// RegisterPayoutBuilder associates a PayoutBuilder instance with a
// (chainID, currency) pair. The builder value is stored as `any`; callers
// resolve it via ResolvePayoutBuilder and type-assert to the canonical
// witness.PayoutBuilder interface.
//
// Registration is intentionally separate from Register: payout builders are
// only needed when the witness fee distributor is wired in, so callers that
// never distribute fees don't have to construct one.
func (r *Registry) RegisterPayoutBuilder(chainID, currency string, builder any) error {
	if chainID == "" {
		return errors.New("plutus/adapter: chainID is empty")
	}
	if currency == "" {
		return errors.New("plutus/adapter: currency is empty")
	}
	if builder == nil {
		return errors.New("plutus/adapter: payout builder is nil")
	}
	key := chainID + ":" + currency
	r.mu.Lock()
	if r.payoutBuilders == nil {
		r.payoutBuilders = make(map[string]any)
	}
	r.payoutBuilders[key] = builder
	r.mu.Unlock()
	return nil
}

// ResolvePayoutBuilder returns the PayoutBuilder registered for a given
// (chainID, currency) pair, or an error if none is registered. Returned as
// `any` — callers assert to their expected interface (typically
// witness.PayoutBuilder). See RegisterPayoutBuilder for the rationale.
func (r *Registry) ResolvePayoutBuilder(chainID, currency string) (any, error) {
	key := chainID + ":" + currency
	r.mu.RLock()
	b, ok := r.payoutBuilders[key]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("plutus/adapter: no payout builder registered for %s", key)
	}
	return b, nil
}

// Register adds a verified adapter to the registry. The descriptor must have
// already been validated via ValidateAdapter before calling Register.
func (r *Registry) Register(a CurrencyAdapter, desc AdapterDescriptor) error {
	if a == nil {
		return errors.New("plutus/adapter: adapter is nil")
	}

	key := desc.ChainID + ":" + desc.Symbol
	info := AdapterInfo{
		ChainID:    desc.ChainID,
		Currency:   desc.Currency,
		Symbol:     desc.Symbol,
		Version:    desc.Version,
		PRCAddress: desc.PRCAddress,
		SignedBy:   desc.SignerPubKey,
	}

	r.mu.Lock()
	r.adapters[key] = registryEntry{
		adapter:    a,
		descriptor: desc,
		info:       info,
	}
	r.mu.Unlock()
	return nil
}

// Get returns the adapter for a given chain and symbol, or an error if not found.
func (r *Registry) Get(chainID, symbol string) (CurrencyAdapter, error) {
	key := chainID + ":" + symbol
	r.mu.RLock()
	entry, ok := r.adapters[key]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("plutus/adapter: no adapter registered for %s", key)
	}
	return entry.adapter, nil
}

// List returns metadata for all registered adapters.
func (r *Registry) List() []AdapterInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	infos := make([]AdapterInfo, 0, len(r.adapters))
	for _, entry := range r.adapters {
		infos = append(infos, entry.info)
	}
	return infos
}

// Descriptor returns the full descriptor for a registered adapter.
func (r *Registry) Descriptor(chainID, symbol string) (*AdapterDescriptor, error) {
	key := chainID + ":" + symbol
	r.mu.RLock()
	entry, ok := r.adapters[key]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("plutus/adapter: no adapter registered for %s", key)
	}
	return &entry.descriptor, nil
}

// Remove unregisters an adapter.
func (r *Registry) Remove(chainID, symbol string) {
	key := chainID + ":" + symbol
	r.mu.Lock()
	delete(r.adapters, key)
	r.mu.Unlock()
}

// ParseDescriptor deserializes a JSON-encoded adapter descriptor.
func ParseDescriptor(data []byte) (*AdapterDescriptor, error) {
	var desc AdapterDescriptor
	if err := json.Unmarshal(data, &desc); err != nil {
		return nil, fmt.Errorf("plutus/adapter: failed to parse descriptor: %w", err)
	}
	return &desc, nil
}

// SignDescriptor signs an adapter descriptor with the given Ed25519 private key.
// It populates SignerPubKey and Signature on the descriptor.
func SignDescriptor(desc *AdapterDescriptor, key ed25519.PrivateKey) {
	desc.SignerPubKey = key.Public().(ed25519.PublicKey)
	desc.Signature = ed25519.Sign(key, desc.descriptorPayload())
}

// DescriptorPubKeyHash returns the SHA256 hash of the descriptor's signer public key.
// This is compared against the PRC maintainerPubKeyHash during validation.
func DescriptorPubKeyHash(desc *AdapterDescriptor) [32]byte {
	return sha256.Sum256(desc.SignerPubKey)
}
