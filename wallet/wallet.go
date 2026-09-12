/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package wallet

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/bbmumford/plutus/adapter"
)

// WalletAccount represents a named account for a specific chain. Each account
// maps to a unique BIP44 derivation path (m/44'/coinType'/account'/0/0).
// Account index 0 is the default created implicitly on first use.
type WalletAccount struct {
	Index     uint32    `json:"index"`
	Name      string    `json:"name"`
	ChainID   string    `json:"chainId"`
	Address   string    `json:"address"`
	CreatedAt time.Time `json:"createdAt"`
}

// Wallet is the concrete wallet implementation that holds the seed, protocol
// identity key, and derived chain keys. It delegates signing to Signer (with
// PRC fee enforcement) and provides chain address derivation with caching.
type Wallet struct {
	seed        []byte
	mnemonic    string
	passphrase  string
	signer      *Signer
	prc         *PRCResolver
	chainKeys   map[string]*ECDSAPrivateKey // "chainID:account" -> derived key, cached
	accounts    map[string][]WalletAccount  // chainID -> accounts
	protocolKey ed25519.PrivateKey
	mu          sync.RWMutex

	// balanceQuerier is set via AttachBalanceVerifier; consumed by Balance().
	// Declared as interface here to avoid an import cycle with witness.
	balanceQuerier BalanceQuerier
}

// NewWallet creates a Wallet from a raw 64-byte seed and PRC resolver.
func NewWallet(seed []byte, prc *PRCResolver) (*Wallet, error) {
	if len(seed) != 64 {
		return nil, fmt.Errorf("plutus/wallet: expected 64-byte seed, got %d", len(seed))
	}

	protocolKey, err := DeriveProtocolIdentity(seed)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive protocol identity: %w", err)
	}

	signer := NewSigner(protocolKey, prc)

	return &Wallet{
		seed:        seed,
		signer:      signer,
		prc:         prc,
		chainKeys:   make(map[string]*ECDSAPrivateKey),
		accounts:    make(map[string][]WalletAccount),
		protocolKey: protocolKey,
	}, nil
}

// NewWalletFromMnemonic creates a Wallet from a BIP39 mnemonic and passphrase.
func NewWalletFromMnemonic(mnemonic, passphrase string, prc *PRCResolver) (*Wallet, error) {
	seed, err := MnemonicToSeed(mnemonic, passphrase)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: mnemonic to seed: %w", err)
	}

	w, err := NewWallet(seed, prc)
	if err != nil {
		return nil, err
	}
	w.mnemonic = mnemonic
	w.passphrase = passphrase
	return w, nil
}

// PeerID returns the hex-encoded SHA-256 hash of the protocol public key.
// This serves as the stable peer identifier on the mesh.
func (w *Wallet) PeerID() string {
	pub := w.protocolKey.Public().(ed25519.PublicKey)
	hash := sha256.Sum256(pub)
	return hex.EncodeToString(hash[:])
}

// PublicKey returns the Ed25519 protocol public key.
func (w *Wallet) PublicKey() ed25519.PublicKey {
	return w.protocolKey.Public().(ed25519.PublicKey)
}

// chainIDToCoinType maps a chain ID to its BIP44 coin type.
func chainIDToCoinType(chainID string) (uint32, error) {
	switch chainID {
	case "ethereum", "polygon", "arbitrum", "bsc":
		return 60, nil // ETH coin type for all EVM chains
	case "bitcoin":
		return 0, nil
	default:
		return 0, fmt.Errorf("plutus/wallet: unsupported chain ID %q", chainID)
	}
}

// chainKeyID returns the cache key for a chain+account pair.
func chainKeyID(chainID string, account uint32) string {
	return fmt.Sprintf("%s:%d", chainID, account)
}

// ChainAddress returns the address for a specific chain and account.
// account=0 is the default. Users can create multiple accounts per chain.
// Derives the key at m/44'/coinType'/account'/0/0.
func (w *Wallet) ChainAddress(chainID string, account ...uint32) (string, error) {
	acct := uint32(0)
	if len(account) > 0 {
		acct = account[0]
	}

	cacheKey := chainKeyID(chainID, acct)

	w.mu.RLock()
	if key, ok := w.chainKeys[cacheKey]; ok {
		w.mu.RUnlock()
		return ChainAddress(key), nil
	}
	w.mu.RUnlock()

	key, err := w.deriveChainKey(chainID, acct)
	if err != nil {
		return "", err
	}

	return ChainAddress(key), nil
}

// deriveChainKey derives and caches an ECDSA key for the given chain and account.
func (w *Wallet) deriveChainKey(chainID string, account uint32) (*ECDSAPrivateKey, error) {
	coinType, err := chainIDToCoinType(chainID)
	if err != nil {
		return nil, err
	}

	key, err := DeriveChainKey(w.seed, coinType, account)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: derive chain key for %s account %d: %w", chainID, account, err)
	}

	cacheKey := chainKeyID(chainID, account)
	w.mu.Lock()
	w.chainKeys[cacheKey] = key
	w.mu.Unlock()

	return key, nil
}

// CreateAccount adds a new named account for a chain. The account index is
// assigned automatically as the next unused index. The address is derived
// eagerly and cached.
func (w *Wallet) CreateAccount(chainID string, name string) (*WalletAccount, error) {
	if chainID == "" {
		return nil, errors.New("plutus/wallet: chainID is required")
	}

	coinType, err := chainIDToCoinType(chainID)
	if err != nil {
		return nil, err
	}

	w.mu.Lock()
	idx := w.nextAccountIndexLocked(chainID)

	key, err := DeriveChainKey(w.seed, coinType, idx)
	if err != nil {
		w.mu.Unlock()
		return nil, fmt.Errorf("plutus/wallet: derive chain key for %s account %d: %w", chainID, idx, err)
	}

	addr := ChainAddress(key)
	cacheKey := chainKeyID(chainID, idx)
	w.chainKeys[cacheKey] = key

	acct := WalletAccount{
		Index:     idx,
		Name:      name,
		ChainID:   chainID,
		Address:   addr,
		CreatedAt: time.Now(),
	}

	w.accounts[chainID] = append(w.accounts[chainID], acct)
	w.mu.Unlock()

	return &acct, nil
}

// ListAccounts returns all accounts for a chain. If chainID is empty, returns
// accounts across all chains sorted by chain then index.
func (w *Wallet) ListAccounts(chainID string) []WalletAccount {
	w.mu.RLock()
	defer w.mu.RUnlock()

	if chainID != "" {
		accts := w.accounts[chainID]
		out := make([]WalletAccount, len(accts))
		copy(out, accts)
		return out
	}

	var all []WalletAccount
	for _, accts := range w.accounts {
		all = append(all, accts...)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].ChainID != all[j].ChainID {
			return all[i].ChainID < all[j].ChainID
		}
		return all[i].Index < all[j].Index
	})
	return all
}

// DefaultAccount returns account index 0 for a chain. If no account has been
// explicitly created, it creates the default account with the name "Default".
func (w *Wallet) DefaultAccount(chainID string) (*WalletAccount, error) {
	w.mu.RLock()
	accts := w.accounts[chainID]
	for i := range accts {
		if accts[i].Index == 0 {
			a := accts[i]
			w.mu.RUnlock()
			return &a, nil
		}
	}
	w.mu.RUnlock()

	// No default account exists; create one.
	return w.CreateAccount(chainID, "Default")
}

// NextAccountIndex returns the next unused account index for a chain.
func (w *Wallet) NextAccountIndex(chainID string) uint32 {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.nextAccountIndexLocked(chainID)
}

// nextAccountIndexLocked returns the next unused index. Caller must hold w.mu.
func (w *Wallet) nextAccountIndexLocked(chainID string) uint32 {
	accts := w.accounts[chainID]
	if len(accts) == 0 {
		return 0
	}
	max := uint32(0)
	for _, a := range accts {
		if a.Index >= max {
			max = a.Index + 1
		}
	}
	return max
}

// IsIdentityOnly returns true if no chain accounts have been created.
// An identity-only wallet can browse, chat, and interact via P2P
// but cannot make payments.
func (w *Wallet) IsIdentityOnly() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return len(w.accounts) == 0
}

// SignEscrowFunding signs an escrow funding transaction.
// If account is specified, it identifies the account being funded from.
func (w *Wallet) SignEscrowFunding(tx *adapter.UnsignedTx, account ...uint32) ([]byte, error) {
	acct := uint32(0)
	if len(account) > 0 {
		acct = account[0]
	}
	return w.signer.SignEscrowFunding(tx, acct)
}

// SignSettlement signs a settlement transaction after verifying that the fee
// breakdown matches PRC rates. Refuses to sign if fees are below protocol minimums.
// If account is specified, it identifies the account receiving settlement.
func (w *Wallet) SignSettlement(tx *adapter.UnsignedTx, expectedFees adapter.FeeBreakdown, account ...uint32) ([]byte, error) {
	if tx == nil {
		return nil, errors.New("plutus/wallet: transaction is nil")
	}

	acct := uint32(0)
	if len(account) > 0 {
		acct = account[0]
	}

	// Resolve PRC data for the chain and verify fees meet minimums.
	prcData, err := w.prc.Resolve(tx.ChainID)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: PRC resolve for settlement: %w", err)
	}

	if err := validateFeesAgainstPRC(expectedFees, prcData); err != nil {
		return nil, fmt.Errorf("plutus/wallet: PRC fee validation failed, refusing to sign: %w", err)
	}

	return w.signer.SignSettlement(tx, expectedFees, acct)
}

// SignDispute signs a dispute transaction.
// If account is specified, it identifies the account filing the dispute.
func (w *Wallet) SignDispute(tx *adapter.UnsignedTx, account ...uint32) ([]byte, error) {
	acct := uint32(0)
	if len(account) > 0 {
		acct = account[0]
	}
	return w.signer.SignDispute(tx, acct)
}

// LoadAdapter parses and returns metadata for an adapter descriptor blob.
func (w *Wallet) LoadAdapter(descriptor []byte) (*adapter.AdapterInfo, error) {
	desc, err := adapter.ParseDescriptor(descriptor)
	if err != nil {
		return nil, fmt.Errorf("plutus/wallet: parse adapter descriptor: %w", err)
	}

	info := &adapter.AdapterInfo{
		ChainID:    desc.ChainID,
		Currency:   desc.Currency,
		Symbol:     desc.Symbol,
		Version:    desc.Version,
		PRCAddress: desc.PRCAddress,
		SignedBy:   desc.SignerPubKey,
	}
	return info, nil
}

// ListAdapters returns an empty list since the wallet does not maintain its
// own adapter registry. Use the SDK's AdapterRegistry for adapter management.
func (w *Wallet) ListAdapters() []adapter.AdapterInfo {
	return nil
}

// Mnemonic returns the BIP39 mnemonic if the wallet was created from one.
// Returns an empty string if the wallet was created from a raw seed.
func (w *Wallet) Mnemonic() string {
	return w.mnemonic
}

// validateFeesAgainstPRC verifies that the fee breakdown meets PRC minimums.
// - MaintainerFee must be >= amount * MaintainerFeeBPS / 10000
// - WitnessFee must be >= amount * WitnessBPS / 10000 (if witness fees present)
func validateFeesAgainstPRC(fees adapter.FeeBreakdown, prc *PRCData) error {
	if fees.Total == nil || fees.Total.Sign() <= 0 {
		return errors.New("total must be positive")
	}

	base := new(big.Int).Set(fees.Total)
	bpsBase := big.NewInt(10000)

	// Verify maintainer fee meets PRC minimum.
	minMaintainer := new(big.Int).Mul(base, big.NewInt(int64(prc.MaintainerFeeBPS)))
	minMaintainer.Div(minMaintainer, bpsBase)

	if fees.MaintainerFee == nil || fees.MaintainerFee.Cmp(minMaintainer) < 0 {
		return fmt.Errorf("maintainer fee %s below PRC minimum %s (%d BPS)",
			feeStr(fees.MaintainerFee), minMaintainer, prc.MaintainerFeeBPS)
	}

	// Verify witness fee meets PRC minimum (only if witness fee is present).
	if fees.WitnessFee != nil && fees.WitnessFee.Sign() > 0 {
		minWitness := new(big.Int).Mul(base, big.NewInt(int64(prc.WitnessBPS)))
		minWitness.Div(minWitness, bpsBase)

		if fees.WitnessFee.Cmp(minWitness) < 0 {
			return fmt.Errorf("witness fee %s below PRC minimum %s (%d BPS)",
				fees.WitnessFee, minWitness, prc.WitnessBPS)
		}
	}

	return nil
}

// feeStr returns the string of a big.Int or "nil".
func feeStr(v *big.Int) string {
	if v == nil {
		return "nil"
	}
	return v.String()
}
