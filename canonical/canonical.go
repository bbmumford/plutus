/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

// Package canonical contains the hardcoded Protocol Registry Contract addresses,
// maintainer public key hash, and the full trust chain anchors. This is a leaf
// package with no internal dependencies, so it can be imported by any other
// plutus subpackage without creating import cycles.
package canonical

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

// SafeSingletonFactory is the canonical Safe Singleton Factory address,
// pre-deployed by the Safe team to ~90 EVM chains. Sending (salt || initCode)
// to this factory produces a CREATE2 deployment — same factory + same salt +
// same initCode yields the same contract address on every chain.
//
// See: https://github.com/safe-global/safe-singleton-factory
const SafeSingletonFactory = "0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7"

// PlutusPRCSalt returns the CREATE2 salt for the canonical PRC deployment.
// It incorporates MaintainerPubKeyHash so that a key rotation ceremony
// produces a different deterministic PRC address — forcing clients to
// deploy fresh PRCs after rotation. This couples the on-chain trust
// anchor to the off-chain identity key.
//
// Formula: keccak256("plutus-v1-prc" || MaintainerPubKeyHash) — raw
// concatenation, not abi-encoded. MUST match the salt computed in
// contracts/evm/script/Deploy.s.sol.
//
// Because MaintainerPubKeyHash is populated by init() in embed.go at
// process start (before any caller can invoke this function), the
// returned salt is stable for the lifetime of the process.
func PlutusPRCSalt() [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte("plutus-v1-prc"))
	h.Write(MaintainerPubKeyHash)
	var salt [32]byte
	copy(salt[:], h.Sum(nil))
	return salt
}

// CanonicalPRCAddress is the deterministic CREATE2 address of the Plutus PRC.
// Because the Safe Singleton Factory address, PlutusPRCSalt, and the PRC
// initCode are identical on every supported chain, the deployed PRC contract
// lives at this same address on every EVM chain.
//
// TODO: populate after deterministic address is computed via the deploy
// script's predicted output. Run `forge script script/Deploy.s.sol --dry-run`
// against any RPC (or call ComputeCanonicalPRCAddress with the compiled
// initCode hash + constructor args) to obtain the address, then paste it here
// as a lowercase-or-checksum hex string (e.g. "0x...").
const CanonicalPRCAddress = ""

// PRC contains the hardcoded Protocol Registry Contract addresses keyed by
// chain ID. Retained as a compatibility layer for callers that still dispatch
// on chainID; every entry is populated from CanonicalPRCAddress by init() in
// embed.go once the ceremony address has been fixed.
//
// Any fork that changes these addresses will break adapter signature
// verification (adapters reference the canonical PRC address hash).
// Wallets refuse to load adapters that don't match the canonical PRC.
var PRC = map[string]string{
	"polygon":  "", // populated from CanonicalPRCAddress
	"ethereum": "", // populated from CanonicalPRCAddress
	"arbitrum": "", // populated from CanonicalPRCAddress
	"bsc":      "", // populated from CanonicalPRCAddress
}

// MaintainerPubKeyHash is the SHA-256 hash of the Plutus maintainer's Ed25519
// Platform Key. Populated by init() in embed.go from keys/platform-key.pub
// at compile time. It CANNOT be changed without a key rotation ceremony.
var MaintainerPubKeyHash []byte

// MaintainerBTCAddress is the canonical maintainer Bitcoin payout address
// (P2WPKH bech32, e.g., "bc1..."). Bitcoin lacks a smart-contract PRC, so
// the payout destination is embedded directly into the canonical trust chain
// at compile time. Populated by init() in embed.go from
// keys/maintainer-btc-addr.txt. If empty, the BTC adapter refuses to load
// (safe default: no accidental fee-stripping deployments).
var MaintainerBTCAddress string

// platformKeyCertJSON is the JSON-serialized form used for embedded certs.
type platformKeyCertJSON struct {
	PlatformPubKey    []byte    `json:"platformPubKey"`
	OfflineRootPubKey []byte    `json:"offlineRootPubKey"`
	IssuedAt          time.Time `json:"issuedAt"`
	Signature         []byte    `json:"signature"`
}

// prcDeploymentCertJSON is the JSON-serialized form used for embedded deployment certs.
type prcDeploymentCertJSON struct {
	ChainID      string    `json:"chainID"`
	PRCAddress   string    `json:"prcAddress"`
	DeployTxHash string    `json:"deployTxHash"`
	BlockNumber  uint64    `json:"blockNumber"`
	DeployedAt   time.Time `json:"deployedAt"`
	Signature    []byte    `json:"signature"`
}

// TrustChain holds the embedded trust anchors for the Plutus protocol.
// These are populated by the maintainer ceremony and compiled into the binary.
var TrustChain = struct {
	// OfflineRootPubKey is the Offline Root public key -- the ultimate trust anchor.
	// This key is generated air-gapped and NEVER changes unless compromised.
	OfflineRootPubKey []byte

	// PlatformCert is the JSON-encoded PlatformKeyCertificate, signed by Offline Root,
	// authorizing daily operations.
	PlatformCert []byte

	// PRCDeployments contains one PRC deployment certificate per chain,
	// signed by the Platform Key. Maps chainID to JSON-encoded certificate.
	PRCDeployments map[string][]byte

	// Checkpoints contains PRC deployment tx hashes for verification against chain.
	// A fork that changes these can't verify against the real blockchain.
	Checkpoints map[string]string
}{
	// OfflineRootPubKey and PlatformCert are populated by init() in embed.go
	// from keys/offline-root.pub and keys/platform-cert.json.
	PRCDeployments: map[string][]byte{},
	Checkpoints:    map[string]string{},
}

// IsCanonicalPRC returns true if the given PRC address matches the canonical
// deployment for the given chain. Retained for backward compatibility;
// prefer IsCanonicalPRCAddress which is chain-independent now that the PRC
// lives at the same CREATE2 address on every EVM chain.
func IsCanonicalPRC(chainID, prcAddress string) bool {
	addr, ok := PRC[chainID]
	if !ok {
		return false
	}
	if addr == "" {
		return false
	}
	return strings.EqualFold(addr, prcAddress)
}

// IsCanonicalPRCAddress returns true if the given address equals the canonical
// CREATE2 PRC address. Comparison is case-insensitive. Returns false if the
// canonical address has not yet been populated (pre-ceremony builds).
func IsCanonicalPRCAddress(prcAddress string) bool {
	if CanonicalPRCAddress == "" {
		return false
	}
	return strings.EqualFold(CanonicalPRCAddress, prcAddress)
}

// keccak256 returns the Keccak-256 (Ethereum-style, NOT SHA3-256) digest of
// the input. Used to compute CREATE2 addresses and salts.
func keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// ComputeCanonicalPRCAddress returns the deterministic CREATE2 address that
// the canonical PRC will be deployed to on every supported chain, given the
// hash of the full initCode (creation bytecode concatenated with ABI-encoded
// constructor args).
//
// Formula: addr = keccak256(0xff || factory || salt || keccak256(initCode))[12:]
//
// The Solidity mirror is Deploy.s.sol#computeAddress — any divergence here
// must be caught by TestComputeCanonicalPRCAddress.
func ComputeCanonicalPRCAddress(initCodeHash [32]byte) string {
	factoryBytes, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(SafeSingletonFactory), "0x"))
	if err != nil {
		// SafeSingletonFactory is a compile-time constant; a parse error here
		// indicates programmer error, not runtime data.
		panic(fmt.Errorf("canonical: invalid SafeSingletonFactory constant: %w", err))
	}

	salt := PlutusPRCSalt()
	digest := keccak256(
		[]byte{0xff},
		factoryBytes,
		salt[:],
		initCodeHash[:],
	)
	// CREATE2 address = last 20 bytes of the digest.
	return "0x" + hex.EncodeToString(digest[12:])
}

// verifyTrustChainOnce guards the cached result of VerifyTrustChain.
// The trust chain inputs (MaintainerPubKeyHash, TrustChain fields) are
// populated at init() time from embedded files and are intended to be
// immutable for the life of the process, so we memoize the verification
// result. Tests that mutate the trust chain must call resetTrustChainCache
// to force recomputation.
var (
	verifyTrustChainOnce sync.Once
	verifyTrustChainErr  error
)

// resetTrustChainCache clears the cached VerifyTrustChain result. It is
// intended for tests that mutate the embedded trust-chain globals and
// need to re-run verification against the new state. Production code must
// never call this — the cache is a permanent, process-lifetime guarantee.
func resetTrustChainCache() {
	verifyTrustChainOnce = sync.Once{}
	verifyTrustChainErr = nil
}

// VerifyTrustChain validates the full certificate chain:
//  1. Platform cert is signed by the embedded Offline Root pubkey.
//  2. Each PRC deployment cert is signed by the Platform Key.
//  3. PRC deployment tx hashes match embedded checkpoints.
//
// The result is cached for the life of the process on first call. The
// trust-chain inputs are compile-time embedded (init() in embed.go) and
// are not expected to change after startup, so subsequent calls return
// the cached error (or nil) in sub-microsecond time.
func VerifyTrustChain() error {
	verifyTrustChainOnce.Do(func() {
		verifyTrustChainErr = verifyTrustChainUncached()
	})
	return verifyTrustChainErr
}

// verifyTrustChainUncached performs the actual chain validation. Kept
// separate from VerifyTrustChain so the cached path is a one-liner and
// tests can exercise the full code path directly via resetTrustChainCache.
func verifyTrustChainUncached() error {
	// 1. Verify we have an Offline Root public key.
	if len(TrustChain.OfflineRootPubKey) == 0 {
		return errors.New("canonical: offline root public key is not set")
	}
	if len(TrustChain.OfflineRootPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("canonical: offline root public key has invalid length %d", len(TrustChain.OfflineRootPubKey))
	}

	// 2. Verify the Platform Key certificate exists and is signed by the OR.
	if TrustChain.PlatformCert == nil {
		return errors.New("canonical: platform key certificate is not set")
	}

	var platformCert platformKeyCertJSON
	if err := json.Unmarshal(TrustChain.PlatformCert, &platformCert); err != nil {
		return fmt.Errorf("canonical: failed to parse platform cert: %w", err)
	}

	if len(platformCert.PlatformPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("canonical: platform public key has invalid length %d", len(platformCert.PlatformPubKey))
	}

	// Verify the OR pubkey in the cert matches our embedded OR pubkey.
	if !ed25519.PublicKey(platformCert.OfflineRootPubKey).Equal(ed25519.PublicKey(TrustChain.OfflineRootPubKey)) {
		return errors.New("canonical: platform cert OR key does not match embedded offline root")
	}

	// Verify the OR signature over the platform cert payload.
	payload := computePlatformCertPayload(platformCert.PlatformPubKey, platformCert.OfflineRootPubKey, platformCert.IssuedAt)
	if !ed25519.Verify(TrustChain.OfflineRootPubKey, payload, platformCert.Signature) {
		return errors.New("canonical: platform key certificate signature is invalid")
	}

	// Cross-check: MaintainerPubKeyHash must equal SHA-256 of the Platform public key.
	expectedHash := sha256.Sum256(platformCert.PlatformPubKey)
	if !bytes.Equal(MaintainerPubKeyHash, expectedHash[:]) {
		return fmt.Errorf("trust chain: MaintainerPubKeyHash does not match SHA-256 of platform public key")
	}

	// 3. Verify each PRC deployment cert is signed by the Platform Key.
	for chainID, certBytes := range TrustChain.PRCDeployments {
		var deployCert prcDeploymentCertJSON
		if err := json.Unmarshal(certBytes, &deployCert); err != nil {
			return fmt.Errorf("canonical: failed to parse PRC deployment cert for chain %s: %w", chainID, err)
		}

		deployPayload := computePRCDeploymentPayload(deployCert.ChainID, deployCert.PRCAddress, deployCert.DeployTxHash, deployCert.BlockNumber, deployCert.DeployedAt)
		if !ed25519.Verify(platformCert.PlatformPubKey, deployPayload, deployCert.Signature) {
			return fmt.Errorf("canonical: PRC deployment cert signature is invalid for chain %s", chainID)
		}

		// 4. Verify checkpoint: tx hash matches.
		if checkpoint, ok := TrustChain.Checkpoints[chainID]; ok {
			if !strings.EqualFold(deployCert.DeployTxHash, checkpoint) {
				return fmt.Errorf("canonical: PRC deployment tx hash for chain %s does not match checkpoint", chainID)
			}
		}

		// 5. Verify the PRC address in the cert matches the canonical PRC map.
		if canonicalAddr, ok := PRC[chainID]; ok {
			if !strings.EqualFold(deployCert.PRCAddress, canonicalAddr) {
				return fmt.Errorf("canonical: PRC deployment cert address %s for chain %s does not match canonical %s", deployCert.PRCAddress, chainID, canonicalAddr)
			}
		}
	}

	return nil
}

// VerifyAdapterTrust validates an adapter descriptor against the full trust chain:
//  1. Adapter signed by Platform Key.
//  2. Platform Key authorized by Offline Root.
//  3. Adapter's PRC address matches a certified deployment.
func VerifyAdapterTrust(descriptor []byte) error {
	// 1. Verify the full trust chain first.
	if err := VerifyTrustChain(); err != nil {
		return fmt.Errorf("canonical: trust chain invalid: %w", err)
	}

	// 2. Parse the platform cert to get the Platform Key.
	var platformCert platformKeyCertJSON
	if err := json.Unmarshal(TrustChain.PlatformCert, &platformCert); err != nil {
		return fmt.Errorf("canonical: failed to parse platform cert: %w", err)
	}

	// 3. Parse the adapter descriptor.
	var desc struct {
		ChainID      string `json:"chainID"`
		Currency     string `json:"currency"`
		Symbol       string `json:"symbol"`
		Version      string `json:"version"`
		PRCAddress   string `json:"prcAddress"`
		AdapterHash  []byte `json:"adapterHash"`
		SignerPubKey []byte `json:"signerPubKey"`
		Signature    []byte `json:"signature"`
	}
	if err := json.Unmarshal(descriptor, &desc); err != nil {
		return fmt.Errorf("canonical: failed to parse adapter descriptor: %w", err)
	}

	// 4. Verify the adapter is signed by the Platform Key.
	if !ed25519.PublicKey(desc.SignerPubKey).Equal(ed25519.PublicKey(platformCert.PlatformPubKey)) {
		return errors.New("canonical: adapter signer is not the authorized Platform Key")
	}

	// 5. Verify the adapter signature.
	adapterPayload := computeAdapterPayload(desc.ChainID, desc.Currency, desc.Symbol, desc.Version, desc.PRCAddress, desc.AdapterHash)
	if !ed25519.Verify(desc.SignerPubKey, adapterPayload, desc.Signature) {
		return errors.New("canonical: adapter descriptor signature is invalid")
	}

	// 6. Verify the adapter's PRC address matches a certified deployment.
	certBytes, ok := TrustChain.PRCDeployments[desc.ChainID]
	if !ok {
		return fmt.Errorf("canonical: no certified PRC deployment for chain %s", desc.ChainID)
	}

	var deployCert prcDeploymentCertJSON
	if err := json.Unmarshal(certBytes, &deployCert); err != nil {
		return fmt.Errorf("canonical: failed to parse PRC deployment cert for chain %s: %w", desc.ChainID, err)
	}

	if !strings.EqualFold(desc.PRCAddress, deployCert.PRCAddress) {
		return fmt.Errorf("canonical: adapter PRC address %s does not match certified deployment %s for chain %s", desc.PRCAddress, deployCert.PRCAddress, desc.ChainID)
	}

	return nil
}

// VerifyPRCDeploymentByChain verifies that a given PRC address on a chain matches
// a certified deployment in the trust chain.
func VerifyPRCDeploymentByChain(chainID, prcAddr string) error {
	// Verify the full trust chain first.
	if err := VerifyTrustChain(); err != nil {
		return fmt.Errorf("canonical: trust chain invalid: %w", err)
	}

	certBytes, ok := TrustChain.PRCDeployments[chainID]
	if !ok {
		return fmt.Errorf("canonical: no certified PRC deployment for chain %s", chainID)
	}

	var deployCert prcDeploymentCertJSON
	if err := json.Unmarshal(certBytes, &deployCert); err != nil {
		return fmt.Errorf("canonical: failed to parse PRC deployment cert for chain %s: %w", chainID, err)
	}

	if !strings.EqualFold(prcAddr, deployCert.PRCAddress) {
		return fmt.Errorf("canonical: PRC address %s does not match certified deployment %s for chain %s", prcAddr, deployCert.PRCAddress, chainID)
	}

	return nil
}

// computePlatformCertPayload computes the canonical bytes for platform key
// certificate verification. Must match maintainer/ceremony.go platformCertPayload.
func computePlatformCertPayload(platformPubKey, offlineRootPubKey []byte, issuedAt time.Time) []byte {
	h := sha256.New()
	h.Write([]byte("plutus:platform-cert:v1:"))
	h.Write(platformPubKey)
	h.Write([]byte{0x00}) // separator for future-proofing
	h.Write(offlineRootPubKey)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(issuedAt.Unix()))
	h.Write(ts)
	return h.Sum(nil)
}

// computePRCDeploymentPayload computes the canonical bytes for PRC deployment
// certificate verification. Must match maintainer/ceremony.go prcDeploymentPayload.
func computePRCDeploymentPayload(chainID, prcAddress, deployTxHash string, blockNumber uint64, deployedAt time.Time) []byte {
	h := sha256.New()
	h.Write([]byte("plutus:prc-deployment:v1:"))
	h.Write([]byte(chainID))
	h.Write([]byte(":"))
	h.Write([]byte(prcAddress))
	h.Write([]byte(":"))
	h.Write([]byte(deployTxHash))
	h.Write([]byte(":"))
	blockBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(blockBytes, blockNumber)
	h.Write(blockBytes)
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(deployedAt.Unix()))
	h.Write(ts)
	return h.Sum(nil)
}

// computeAdapterPayload computes the canonical bytes for adapter descriptor
// verification. This mirrors the adapter.AdapterDescriptor.descriptorPayload()
// method for cross-package verification.
func computeAdapterPayload(chainID, currency, symbol, version, prcAddress string, adapterHash []byte) []byte {
	payload := struct {
		ChainID     string `json:"chainID"`
		Currency    string `json:"currency"`
		Symbol      string `json:"symbol"`
		Version     string `json:"version"`
		PRCAddress  string `json:"prcAddress"`
		AdapterHash []byte `json:"adapterHash"`
	}{
		ChainID:     chainID,
		Currency:    currency,
		Symbol:      symbol,
		Version:     version,
		PRCAddress:  prcAddress,
		AdapterHash: adapterHash,
	}
	b, _ := json.Marshal(payload)
	return b
}

// ---------------------------------------------------------------------------
// Protocol Fingerprint & Gossip Topics (Layer 4 Network Isolation)
// ---------------------------------------------------------------------------

// ProtocolVersion is the Plutus wire protocol version.
// Incremented on breaking gossip format changes.
const ProtocolVersion = "plutus-v1"

// protocolFingerprintOnce caches the computed fingerprint so the SHA-256
// derivation only runs once per process.
var (
	protocolFingerprintOnce sync.Once
	protocolFingerprintVal  string
)

// ProtocolFingerprint computes a unique fingerprint for this Plutus deployment.
// It combines:
//   - Protocol version string
//   - Canonical PRC addresses (sorted by chain ID)
//   - Maintainer public key hash
//   - Offline Root public key
//   - Platform certificate bytes
//   - All PRC deployment checkpoint hashes (sorted by chain ID)
//
// Two Plutus binaries with different trust chains will have different
// fingerprints and cannot gossip with each other.
//
// If the trust chain is not yet populated (ceremony not run), returns ""
// without caching, so the fingerprint will be computed once real data is set.
func ProtocolFingerprint() string {
	if len(TrustChain.OfflineRootPubKey) == 0 {
		return "" // not yet populated — don't cache
	}
	protocolFingerprintOnce.Do(func() {
		h := sha256.New()
		h.Write([]byte(ProtocolVersion))

		// Include canonical PRC addresses sorted by chain ID for determinism.
		for _, chainID := range sortedMapKeys(PRC) {
			h.Write([]byte(chainID))
			h.Write([]byte(PRC[chainID]))
		}

		// Include the maintainer public key hash.
		h.Write(MaintainerPubKeyHash)

		// Include the offline root public key.
		h.Write(TrustChain.OfflineRootPubKey)

		// Include the platform certificate.
		h.Write(TrustChain.PlatformCert)

		// Include all deployment checkpoints sorted by chain ID.
		for _, chainID := range sortedMapKeys(TrustChain.Checkpoints) {
			h.Write([]byte(chainID))
			h.Write([]byte(TrustChain.Checkpoints[chainID]))
		}

		// 16 bytes = 32 hex chars -- enough for topic isolation without bloat.
		protocolFingerprintVal = hex.EncodeToString(h.Sum(nil)[:16])
	})
	return protocolFingerprintVal
}

// sortedMapKeys returns map keys in sorted order.
func sortedMapKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// ---------------------------------------------------------------------------
// Gossip topic names scoped by protocol fingerprint.
// A fork with a different trust chain gets different topic names and
// cannot exchange messages with the canonical network.
// ---------------------------------------------------------------------------

// WitnessTopic returns the gossip topic for witness registrations.
func WitnessTopic() string { return "plutus." + ProtocolFingerprint()[:8] + ".witnesses" }

// AttestRequestTopic returns the gossip topic for attestation requests.
func AttestRequestTopic() string { return "plutus." + ProtocolFingerprint()[:8] + ".attest.request" }

// AttestResponseTopic returns the gossip topic for attestation responses.
func AttestResponseTopic() string {
	return "plutus." + ProtocolFingerprint()[:8] + ".attest.response"
}

// BroadcastTopic returns the gossip topic for transaction broadcast requests.
func BroadcastTopic() string { return "plutus." + ProtocolFingerprint()[:8] + ".broadcast" }

// BroadcastResponseTopic returns the gossip topic for transaction broadcast responses.
func BroadcastResponseTopic() string {
	return "plutus." + ProtocolFingerprint()[:8] + ".broadcast.response"
}

// ArbitratorTopic returns the gossip topic for arbitrator registrations.
func ArbitratorTopic() string { return "plutus." + ProtocolFingerprint()[:8] + ".arbitrators" }

// RepTradesTopic returns the gossip topic for trade completion records.
func RepTradesTopic() string { return "plutus." + ProtocolFingerprint()[:8] + ".rep.trades" }

// RepReviewsTopic returns the gossip topic for review records.
func RepReviewsTopic() string { return "plutus." + ProtocolFingerprint()[:8] + ".rep.reviews" }

// BalanceRequestTopic returns the gossip topic for balance-query requests.
// Clients publish BalanceQuery messages here; witnesses subscribe and respond
// with signed BalanceAttestations on BalanceResponseTopic().
func BalanceRequestTopic() string {
	return "plutus." + ProtocolFingerprint()[:8] + ".balance.request"
}

// BalanceResponseTopic returns the gossip topic for balance-query responses.
func BalanceResponseTopic() string {
	return "plutus." + ProtocolFingerprint()[:8] + ".balance.response"
}
