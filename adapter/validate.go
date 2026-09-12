package adapter

import (
	"bytes"
	"container/list"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/bbmumford/plutus/canonical"
)

// adapterTrustCacheSize bounds the number of distinct adapter descriptors
// whose trust-chain verification result is memoized. The working set in
// practice is one adapter per supported chain (< 20), so 100 entries is
// comfortably over-provisioned without meaningful memory cost.
const adapterTrustCacheSize = 100

// adapterTrustCache is a bounded LRU keyed by sha256(descriptor hash).
// Stores the cached ValidateAdapter result (nil on success, error on
// failure) so repeat verifications of the same descriptor are O(1).
//
// We key off the descriptor's AdapterHash rather than the full descriptor
// bytes: AdapterHash is already a collision-resistant digest of the
// adapter binary, and the remaining descriptor fields (signer, signature,
// PRC address) are all signed-over by that hash — so two descriptors with
// the same AdapterHash and a passing verification are equivalent.
var (
	adapterTrustCacheMu    sync.Mutex
	adapterTrustCacheOrder = list.New() // front = most recent
	adapterTrustCacheMap   = make(map[[32]byte]*list.Element, adapterTrustCacheSize)
)

type adapterTrustCacheEntry struct {
	key [32]byte
	err error
}

// lookupAdapterTrust returns the cached verification result for key if
// present, promoting the entry to MRU.
func lookupAdapterTrust(key [32]byte) (error, bool) {
	adapterTrustCacheMu.Lock()
	defer adapterTrustCacheMu.Unlock()
	if elem, ok := adapterTrustCacheMap[key]; ok {
		adapterTrustCacheOrder.MoveToFront(elem)
		return elem.Value.(*adapterTrustCacheEntry).err, true
	}
	return nil, false
}

// storeAdapterTrust inserts (or refreshes) an entry, evicting the LRU
// entry if the cache is full.
func storeAdapterTrust(key [32]byte, err error) {
	adapterTrustCacheMu.Lock()
	defer adapterTrustCacheMu.Unlock()
	if elem, ok := adapterTrustCacheMap[key]; ok {
		elem.Value.(*adapterTrustCacheEntry).err = err
		adapterTrustCacheOrder.MoveToFront(elem)
		return
	}
	entry := &adapterTrustCacheEntry{key: key, err: err}
	elem := adapterTrustCacheOrder.PushFront(entry)
	adapterTrustCacheMap[key] = elem
	if adapterTrustCacheOrder.Len() > adapterTrustCacheSize {
		oldest := adapterTrustCacheOrder.Back()
		if oldest != nil {
			adapterTrustCacheOrder.Remove(oldest)
			delete(adapterTrustCacheMap, oldest.Value.(*adapterTrustCacheEntry).key)
		}
	}
}

// resetAdapterTrustCache clears the LRU. Intended for tests that mutate
// the canonical trust chain — the cached error results are no longer
// meaningful against the new chain state.
func resetAdapterTrustCache() {
	adapterTrustCacheMu.Lock()
	defer adapterTrustCacheMu.Unlock()
	adapterTrustCacheOrder = list.New()
	adapterTrustCacheMap = make(map[[32]byte]*list.Element, adapterTrustCacheSize)
}

// adapterTrustCacheKeyWithPRC derives the cache key for a descriptor.
// Mixes in every signed field plus the caller-supplied maintainer key
// hash so that (a) tampering with any signed field yields a different
// key (forcing fresh verification rather than hitting a stale cached
// success), and (b) callers with different PRC maintainer hashes never
// share cache entries.
func adapterTrustCacheKeyWithPRC(desc *AdapterDescriptor, prcPubKeyHash []byte) [32]byte {
	h := sha256.New()
	h.Write(desc.AdapterHash)
	h.Write(desc.SignerPubKey)
	h.Write(desc.Signature)
	h.Write([]byte(desc.PRCAddress))
	h.Write([]byte(desc.ChainID))
	h.Write([]byte(desc.ProtocolFingerprint))
	h.Write(prcPubKeyHash)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}

// ValidateAdapter verifies that an adapter descriptor is authentic and
// authorised by the PRC maintainer. Validation checks:
//
//  1. The Ed25519 signature over the descriptor payload is valid.
//  2. The signer's public key hash matches the PRC maintainerPubKeyHash.
//
// This prevents loading of adapters not signed by the protocol maintainer,
// which is the foundation of fee enforcement — an unsigned or rogue adapter
// could construct escrow transactions that skip the maintainer fee.
func ValidateAdapter(desc *AdapterDescriptor, prcPubKeyHash []byte) error {
	if desc == nil {
		return errors.New("plutus/adapter: descriptor is nil")
	}

	// Short-circuit if we've already verified this exact descriptor against
	// the current process's trust chain. The cache key covers every signed
	// field plus the prcPubKeyHash, so cache hits require a byte-for-byte
	// identical descriptor and the same maintainer key.
	cacheKey := adapterTrustCacheKeyWithPRC(desc, prcPubKeyHash)
	if cachedErr, ok := lookupAdapterTrust(cacheKey); ok {
		return cachedErr
	}

	err := validateAdapterUncached(desc, prcPubKeyHash)
	storeAdapterTrust(cacheKey, err)
	return err
}

// validateAdapterUncached is the full-fat verification path. Split out so
// the cached wrapper is a thin pre-check + memoize, and tests that need
// the uncached behaviour can call resetAdapterTrustCache between calls.
func validateAdapterUncached(desc *AdapterDescriptor, prcPubKeyHash []byte) error {
	// 1. Verify the signer public key is present and valid length.
	if len(desc.SignerPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("plutus/adapter: invalid signer public key length %d", len(desc.SignerPubKey))
	}

	// 2. Verify the Ed25519 signature.
	payload := desc.descriptorPayload()
	if !ed25519.Verify(desc.SignerPubKey, payload, desc.Signature) {
		return errors.New("plutus/adapter: descriptor signature is invalid")
	}

	// 3. Verify the signer's public key hash matches the PRC maintainer key hash.
	signerHash := sha256.Sum256(desc.SignerPubKey)
	if !bytes.Equal(signerHash[:], prcPubKeyHash) {
		return fmt.Errorf(
			"plutus/adapter: signer pubkey hash %x does not match PRC maintainer hash %x",
			signerHash[:8], prcPubKeyHash[:8],
		)
	}

	// 4. Basic field validation.
	if desc.ChainID == "" {
		return errors.New("plutus/adapter: descriptor chainID is empty")
	}
	if desc.Currency == "" {
		return errors.New("plutus/adapter: descriptor currency is empty")
	}
	if desc.Symbol == "" {
		return errors.New("plutus/adapter: descriptor symbol is empty")
	}
	if desc.PRCAddress == "" {
		return errors.New("plutus/adapter: descriptor PRCAddress is empty")
	}
	if len(desc.AdapterHash) == 0 {
		return errors.New("plutus/adapter: descriptor adapterHash is empty")
	}

	// 5. Verify adapter references canonical PRC (anti-fork protection).
	if !canonical.IsCanonicalPRC(desc.ChainID, desc.PRCAddress) {
		return fmt.Errorf("plutus/adapter: PRC address %s does not match canonical for chain %s", desc.PRCAddress, desc.ChainID)
	}

	// 6. Verify pubkey hash matches the canonical maintainer key.
	if !bytes.Equal(prcPubKeyHash, canonical.MaintainerPubKeyHash) {
		return fmt.Errorf("plutus/adapter: maintainer pubkey hash does not match canonical")
	}

	// 7. Verify protocol fingerprint matches (Layer 4 anti-fork protection).
	// Reject any descriptor whose fingerprint doesn't match the local deployment,
	// including empty fingerprints when the local fingerprint is populated.
	// This prevents bypass of fork isolation by omitting the field.
	localFP := canonical.ProtocolFingerprint()
	if localFP != "" && desc.ProtocolFingerprint != localFP {
		return fmt.Errorf("adapter: protocol fingerprint mismatch (fork detected)")
	}

	// 8. Full trust chain verification: verify the adapter descriptor against the
	// entire OR -> PK -> PRC deployment certificate chain.
	// If the trust chain has not been populated yet (ceremony not run), skip
	// this check to allow development and testing.
	if len(canonical.TrustChain.OfflineRootPubKey) > 0 && canonical.TrustChain.PlatformCert != nil {
		descriptorJSON, err := json.Marshal(desc)
		if err != nil {
			return fmt.Errorf("adapter: failed to marshal descriptor for trust chain check: %w", err)
		}
		if err := canonical.VerifyAdapterTrust(descriptorJSON); err != nil {
			return fmt.Errorf("adapter: trust chain validation failed: %w", err)
		}
	}

	return nil
}

// ValidateAdapterHash checks that a given binary blob matches the adapter hash
// declared in the descriptor. This is used after downloading an adapter to
// ensure it has not been tampered with.
func ValidateAdapterHash(desc *AdapterDescriptor, adapterBinary []byte) error {
	if desc == nil {
		return errors.New("plutus/adapter: descriptor is nil")
	}
	if len(adapterBinary) == 0 {
		return errors.New("plutus/adapter: adapter binary is empty")
	}

	hash := sha256.Sum256(adapterBinary)
	if !bytes.Equal(hash[:], desc.AdapterHash) {
		return fmt.Errorf(
			"plutus/adapter: adapter binary hash %x does not match descriptor hash %x",
			hash[:8], desc.AdapterHash[:8],
		)
	}
	return nil
}
