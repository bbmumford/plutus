package wallet

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/bbmumford/plutus/canonical"
)

// PRCData contains the Protocol Registry Contract state for a given chain.
type PRCData struct {
	MaintainerPayout     string // payout address on this chain
	MaintainerFeeBPS     uint32 // fee in basis points (max 500)
	WitnessBPS           uint32 // witness fee in basis points (max 100)
	MaintainerPubKeyHash []byte // SHA256 hash of maintainer's Ed25519 public key
	ManifestHash         []byte // SHA256 hash of the protocol manifest (32 bytes)
}

// EscrowSnapshot captures attested on-chain escrow state. This is a local
// subset type compatible with witness.EscrowSnapshot, defined here to avoid
// a circular import between wallet and witness packages.
type EscrowSnapshot struct {
	ChainID    string
	EscrowAddr string
}

// MeshVerifier is the interface for verifying blockchain state via the
// Whisper witness gossip network. This is injected by the consumer.
// The interface is a subset that both the local PRC verifier and
// witness.MeshVerifier satisfy.
type MeshVerifier interface {
	// AttestContractState requests quorum-attested contract state from the witness mesh.
	// The witnesses read the on-chain PRC and return an attested snapshot.
	AttestContractState(ctx context.Context, chainID string, contractAddr string) ([]byte, error)

	// AttestEscrowState requests quorum-attested escrow state. Implementations
	// may return nil if escrow attestation is not supported (PRC-only verifiers).
	AttestEscrowState(ctx context.Context, chainID, escrowAddr string) (*EscrowSnapshot, error)
}

// PRCResolver reads Protocol Registry Contract data from on-chain state
// via the mesh witness network. It caches resolved data per chain.
type PRCResolver struct {
	verifier  MeshVerifier
	addresses map[string]string // chainID -> PRC contract address

	mu    sync.RWMutex
	cache map[string]*prcCacheEntry
}

type prcCacheEntry struct {
	data      *PRCData
	fetchedAt time.Time
}

const prcCacheTTL = 5 * time.Minute

// NewPRCResolver creates a PRC resolver with the given mesh verifier and
// chain-specific PRC contract addresses.
func NewPRCResolver(verifier MeshVerifier, addresses map[string]string) *PRCResolver {
	return &PRCResolver{
		verifier:  verifier,
		addresses: addresses,
		cache:     make(map[string]*prcCacheEntry),
	}
}

// Resolve returns the PRC data for the given chain. Results are cached
// for prcCacheTTL to avoid redundant witness attestation requests.
func (r *PRCResolver) Resolve(chainID string) (*PRCData, error) {
	// Verify the full trust chain before accepting any PRC data.
	// This is cached per-process so the crypto only runs once.
	if err := r.verifyTrustChainOnce(); err != nil {
		return nil, fmt.Errorf("wallet: trust chain verification failed: %w", err)
	}

	// Check cache first.
	r.mu.RLock()
	if entry, ok := r.cache[chainID]; ok && time.Since(entry.fetchedAt) < prcCacheTTL {
		r.mu.RUnlock()
		return entry.data, nil
	}
	r.mu.RUnlock()

	addr, ok := r.addresses[chainID]
	if !ok {
		return nil, fmt.Errorf("plutus/wallet: no PRC address configured for chain %q", chainID)
	}

	// Verify the PRC address matches a certified deployment in the trust chain.
	configuredAddr := r.addresses[chainID]
	if configuredAddr != "" {
		if err := canonical.VerifyPRCDeploymentByChain(chainID, configuredAddr); err != nil {
			return nil, fmt.Errorf("wallet: PRC deployment verification failed: %w", err)
		}
	}

	// Verify the PRC address is canonical (anti-fork protection).
	// Even if someone configures a custom PRC address, the wallet refuses to
	// use it unless it matches the hardcoded canonical deployment.
	if !canonical.IsCanonicalPRC(chainID, addr) {
		return nil, fmt.Errorf("plutus/wallet: PRC address %s for chain %q does not match canonical deployment", addr, chainID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	raw, err := r.verifier.AttestContractState(ctx, chainID, addr)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: PRC attestation failed for chain %q: %w", chainID, err)
	}

	data, err := decodePRCData(raw)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: PRC decode failed for chain %q: %w", chainID, err)
	}

	// Validate hard caps.
	if data.MaintainerFeeBPS > 500 {
		return nil, fmt.Errorf("plutus/wallet: PRC maintainer fee %d BPS exceeds 500 cap", data.MaintainerFeeBPS)
	}
	if data.WitnessBPS > 100 {
		return nil, fmt.Errorf("plutus/wallet: PRC witness fee %d BPS exceeds 100 cap", data.WitnessBPS)
	}

	// Update cache.
	r.mu.Lock()
	r.cache[chainID] = &prcCacheEntry{data: data, fetchedAt: time.Now()}
	r.mu.Unlock()

	return data, nil
}

// trustChainVerified tracks whether the trust chain has been verified
// in this process lifetime. Once verified, it doesn't need re-checking.
var (
	trustChainVerified   bool
	trustChainVerifiedMu sync.Mutex
)

// verifyTrustChainOnce performs trust chain verification at most once per process.
// If the trust chain data has not been populated yet (ceremony not run),
// this is a no-op to allow development and testing.
func (r *PRCResolver) verifyTrustChainOnce() error {
	trustChainVerifiedMu.Lock()
	defer trustChainVerifiedMu.Unlock()

	if trustChainVerified {
		return nil
	}

	// If the trust chain has not been populated (ceremony not yet run),
	// skip verification to allow development. The canonical PRC checks
	// still apply as a fallback.
	if len(canonical.TrustChain.OfflineRootPubKey) == 0 || canonical.TrustChain.PlatformCert == nil {
		trustChainVerified = true
		return nil
	}

	if err := canonical.VerifyTrustChain(); err != nil {
		return err
	}

	trustChainVerified = true
	return nil
}

// decodePRCData decodes the raw witness-attested PRC state.
// Format: maintainerPayout (20 bytes) || maintainerFeeBPS (4 bytes) ||
//
//	witnessBPS (4 bytes) || maintainerPubKeyHash (32 bytes)
//
// Total: 60 bytes minimum.
func decodePRCData(raw []byte) (*PRCData, error) {
	if len(raw) < 60 {
		return nil, errors.New("PRC data too short")
	}

	payoutAddr := fmt.Sprintf("0x%x", raw[:20])
	maintainerBPS := binary.BigEndian.Uint32(raw[20:24])
	witnessBPS := binary.BigEndian.Uint32(raw[24:28])
	pubKeyHash := make([]byte, 32)
	copy(pubKeyHash, raw[28:60])

	return &PRCData{
		MaintainerPayout:     payoutAddr,
		MaintainerFeeBPS:     maintainerBPS,
		WitnessBPS:           witnessBPS,
		MaintainerPubKeyHash: pubKeyHash,
	}, nil
}

// EncodePRCData encodes PRC data into the wire format for testing and
// witness attestation construction.
func EncodePRCData(data *PRCData) ([]byte, error) {
	if len(data.MaintainerPubKeyHash) != 32 {
		return nil, errors.New("plutus/wallet: maintainer pubkey hash must be 32 bytes")
	}

	// Parse the payout address (strip 0x prefix).
	payoutHex := data.MaintainerPayout
	if len(payoutHex) >= 2 && payoutHex[:2] == "0x" {
		payoutHex = payoutHex[2:]
	}
	payoutBytes := new(big.Int)
	payoutBytes.SetString(payoutHex, 16)
	addrBytes := make([]byte, 20)
	b := payoutBytes.Bytes()
	copy(addrBytes[20-len(b):], b)

	result := make([]byte, 60)
	copy(result[:20], addrBytes)
	binary.BigEndian.PutUint32(result[20:24], data.MaintainerFeeBPS)
	binary.BigEndian.PutUint32(result[24:28], data.WitnessBPS)
	copy(result[28:60], data.MaintainerPubKeyHash)

	return result, nil
}
