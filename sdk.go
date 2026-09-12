/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package plutus

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"math/big"
	"path/filepath"
	"sync"
	"time"

	"github.com/bbmumford/plutus/adapter"
	"github.com/bbmumford/plutus/adapter/btc"
	"github.com/bbmumford/plutus/arbitrator"
	"github.com/bbmumford/plutus/escrow"
	"github.com/bbmumford/plutus/receipt"
	"github.com/bbmumford/plutus/reputation"
	"github.com/bbmumford/plutus/settle"
	"github.com/bbmumford/plutus/wallet"
	"github.com/bbmumford/plutus/witness"

	"github.com/bbmumford/ledger/cache"
	"github.com/bbmumford/whisper"
)

// Config configures the PlutusSDK at creation time.
type Config struct {
	// Mnemonic is an optional BIP39 mnemonic to restore a wallet.
	// If empty, a new mnemonic is generated.
	Mnemonic string

	// Passphrase is the optional BIP39 passphrase for seed derivation.
	Passphrase string

	// PRCAddresses maps chain IDs to their Protocol Registry Contract addresses.
	PRCAddresses map[string]string

	// Engine is the Whisper gossip engine. If nil, a new one is created.
	Engine *whisper.Engine

	// DirectoryCache is the Ledger directory cache. If nil, a new one is created.
	DirectoryCache *cache.DirectoryCache

	// BalanceProviders maps chain_id to the ChainBalanceProvider this node
	// will use when acting as a balance-witness. Leave nil for client-only
	// nodes (WASM clients, typical wallet users).
	BalanceProviders map[string]witness.ChainBalanceProvider

	// WitnessRoles lists additional witness roles this SDK should run.
	// Supported: "balance" — starts BalanceVerifier.Run() in a background
	// goroutine. Other roles are accepted but ignored by this package (they
	// may be consumed by higher layers like mercury-node).
	WitnessRoles []string

	// BalanceCacheTTL overrides the default 30s client-side balance cache TTL.
	// Zero (or unset) uses the default.
	BalanceCacheTTL time.Duration

	// DataDir is the root directory where the SDK persists local state
	// (earning log, future ledger shards, etc). Empty disables persistence
	// and only volatile in-memory components are wired — intended for tests
	// and WASM contexts.
	DataDir string

	// Reserved for future collusion detector configuration.
}

// PlutusSDK is the top-level entry point that wires together all Plutus
// subsystems: wallet, escrow, settlement, witness, arbitrator, and reputation.
type PlutusSDK struct {
	// Wallet
	Mnemonic    string
	IdentityKey ed25519.PrivateKey
	Signer      *wallet.Signer
	PRCResolver *wallet.PRCResolver

	// Adapters
	AdapterRegistry *adapter.Registry

	// Escrow
	EscrowManager *escrow.EscrowManager

	// Settlement
	FeeCalculator      *settle.FeeCalculator
	SettlementExecutor *settle.SettlementExecutor

	// Witness
	WitnessRegistry *witness.WitnessRegistry
	MeshVerifier    *witness.MeshVerifier
	BroadcastService *witness.BroadcastService
	CollusionDetector *witness.CollusionDetector
	BalanceVerifier *witness.BalanceVerifier

	// EarningLog is the durable per-witness earnings record that feeds the
	// fee distributor. Nil when Config.DataDir is empty.
	EarningLog *witness.EarningLog

	// DistributionStore is the durable per-round dedup log consumed by the
	// fee distributor to survive process restarts without double-paying.
	// Nil when Config.DataDir is empty; NewFeeDistributor falls back to an
	// in-memory store in that case (acceptable for tests and WASM only).
	DistributionStore *witness.PersistentDistributionStore

	// Arbitrator
	ArbitratorRegistry *arbitrator.ArbitratorRegistry

	// Reputation
	ReputationService *reputation.ReputationService
	AntiGaming        *reputation.AntiGamingService

	// Receipts
	Receipts *receipt.ReceiptManager

	// Infrastructure
	Engine         *whisper.Engine
	DirectoryCache *cache.DirectoryCache

	// btcWatchers tracks the BTCEscrowWatcher started for each registered
	// BTC adapter (keyed by chainID). Set by StartBTCWatchers.
	btcWatchersMu sync.Mutex
	btcWatchers   map[string]*escrow.BTCEscrowWatcher
}

// New creates and wires a fully initialized PlutusSDK from the given config.
// All subsystems are created, connected, and ready to use.
func New(cfg Config) (*PlutusSDK, error) {
	sdk := &PlutusSDK{}

	// --- Infrastructure ---

	if cfg.Engine != nil {
		sdk.Engine = cfg.Engine
	} else {
		sdk.Engine = whisper.NewEngine()
	}

	if cfg.DirectoryCache != nil {
		sdk.DirectoryCache = cfg.DirectoryCache
	} else {
		sdk.DirectoryCache = cache.NewDirectoryCache(nil)
	}

	// --- Wallet ---

	mnemonic := cfg.Mnemonic
	if mnemonic == "" {
		var err error
		mnemonic, err = wallet.GenerateMnemonic()
		if err != nil {
			return nil, fmt.Errorf("plutus: generate mnemonic: %w", err)
		}
	}
	sdk.Mnemonic = mnemonic

	seed, err := wallet.MnemonicToSeed(mnemonic, cfg.Passphrase)
	if err != nil {
		return nil, fmt.Errorf("plutus: derive seed: %w", err)
	}

	identityKey, err := wallet.DeriveProtocolIdentity(seed)
	if err != nil {
		return nil, fmt.Errorf("plutus: derive identity key: %w", err)
	}
	sdk.IdentityKey = identityKey

	// PRC resolver for fee verification
	prcVerifier := &sdkPRCVerifier{sdk: sdk}
	prcAddrs := cfg.PRCAddresses
	if prcAddrs == nil {
		prcAddrs = make(map[string]string)
	}
	sdk.PRCResolver = wallet.NewPRCResolver(prcVerifier, prcAddrs)
	sdk.Signer = wallet.NewSigner(identityKey, sdk.PRCResolver)

	// --- Adapters ---

	sdk.AdapterRegistry = adapter.NewRegistry()

	// --- Witness ---

	sdk.CollusionDetector = witness.NewCollusionDetector()
	sdk.WitnessRegistry = witness.NewWitnessRegistry(sdk.Engine, sdk.DirectoryCache)
	sdk.MeshVerifier = witness.NewMeshVerifier(sdk.Engine, sdk.WitnessRegistry, sdk.CollusionDetector)
	sdk.BroadcastService = witness.NewBroadcastService(sdk.Engine)

	// BalanceVerifier is the witness-mesh balance-query subsystem. It runs
	// client-side by default (QueryBalance). When cfg.WitnessRoles contains
	// "balance", higher layers (mercury-node) should call Run() in a goroutine.
	sdk.BalanceVerifier = witness.NewBalanceVerifier(sdk.Engine, witness.BalanceVerifierConfig{
		Providers:      cfg.BalanceProviders,
		CacheTTL:       cfg.BalanceCacheTTL,
		WitnessPrivKey: identityKey,
	})

	// --- Settlement (fee calculator needed by escrow) ---

	sdk.FeeCalculator = settle.NewFeeCalculator()

	// --- Escrow ---

	escrowVerifier := &sdkEscrowVerifier{sdk: sdk}
	escrowWallet := &sdkEscrowWallet{sdk: sdk, seed: seed}
	escrowAdapters := &sdkAdapterResolver{registry: sdk.AdapterRegistry}
	sdk.EscrowManager = escrow.NewEscrowManager(escrowAdapters, escrowWallet, escrowVerifier,
		escrow.WithFeeCalculator(&sdkFeeCalcBridge{calc: sdk.FeeCalculator}),
	)
	settleSigner := &sdkSettleSigner{signer: sdk.Signer}
	settleBroadcaster := &sdkSettleBroadcaster{sdk: sdk}
	executor, err := settle.NewSettlementExecutor(sdk.FeeCalculator, settleSigner, settleBroadcaster)
	if err != nil {
		return nil, fmt.Errorf("plutus: create settlement executor: %w", err)
	}
	sdk.SettlementExecutor = executor

	// --- Earning log + distribution store (optional, only when DataDir is set) ---

	if cfg.DataDir != "" {
		earningDir := filepath.Join(cfg.DataDir, "earnings")
		el, err := witness.NewEarningLog(earningDir)
		if err != nil {
			return nil, fmt.Errorf("plutus: open earning log: %w", err)
		}
		sdk.EarningLog = el
		sdk.SettlementExecutor.SetEarningRecorder(el)

		// The distribution store shares DataDir with the earning log so an
		// operator configuring a single --data-dir picks up both durability
		// guarantees automatically. Keeping it in a sibling directory
		// (distributions/) makes backup + log rotation scripts easy to
		// reason about.
		distDir := filepath.Join(cfg.DataDir, "distributions")
		ds, err := witness.NewPersistentDistributionStore(distDir)
		if err != nil {
			// Close the earning log we just opened so we don't leak a file
			// handle when SDK construction fails mid-wire.
			_ = el.Close()
			sdk.EarningLog = nil
			return nil, fmt.Errorf("plutus: open distribution store: %w", err)
		}
		sdk.DistributionStore = ds
	}

	// --- Arbitrator ---

	sdk.ArbitratorRegistry = arbitrator.NewArbitratorRegistry(sdk.Engine, sdk.DirectoryCache)

	// --- Reputation ---

	sdk.ReputationService = reputation.NewReputationService(sdk.Engine, sdk.DirectoryCache)
	antiGamingVerifier := &sdkAntiGamingVerifier{sdk: sdk}
	sdk.AntiGaming = reputation.NewAntiGamingService(sdk.ReputationService, antiGamingVerifier)

	// --- Receipts ---

	sdk.Receipts = receipt.NewReceiptManager(identityKey)

	return sdk, nil
}

// PublicKey returns the protocol identity public key.
func (s *PlutusSDK) PublicKey() ed25519.PublicKey {
	return s.IdentityKey.Public().(ed25519.PublicKey)
}

// ChainAddress derives the chain address for a given chain ID.
func (s *PlutusSDK) ChainAddress(chainID string) (string, error) {
	seed, err := wallet.MnemonicToSeed(s.Mnemonic, "")
	if err != nil {
		return "", err
	}
	coinType := chainIDToCoinType(chainID)
	chainKey, err := wallet.DeriveChainKey(seed, coinType, 0)
	if err != nil {
		return "", err
	}
	return wallet.ChainAddress(chainKey), nil
}

// SignReceipt signs a service receipt with the protocol identity key.
func (s *PlutusSDK) SignReceipt(r *receipt.ServiceReceipt) error {
	return receipt.SignReceipt(r, s.IdentityKey)
}

// FindArbitrators returns arbitrators matching the criteria, scored by reputation.
func (s *PlutusSDK) FindArbitrators(criteria arbitrator.SelectionCriteria) []arbitrator.ScoredArbitrator {
	return arbitrator.FindBest(s.ArbitratorRegistry, s.ReputationService, criteria)
}

// StartBTCWatchers scans the AdapterRegistry for any registered BTCAdapter
// instances and starts a BTCEscrowWatcher for each. Returns the number of
// watchers started. Safe to call multiple times — already-running watchers
// are not duplicated. The given context controls watcher lifetime; cancel it
// or call StopBTCWatchers to terminate them.
//
// Wire-up note: callers register their BTC adapters via
// btc.RegisterBitcoinAdapters (or directly on AdapterRegistry) BEFORE calling
// StartBTCWatchers. The watcher uses the adapter itself as both the UTXO
// source (via its mesh-routed BTCClient.ListUnspent) and the funding recorder.
func (s *PlutusSDK) StartBTCWatchers(ctx context.Context) int {
	s.btcWatchersMu.Lock()
	if s.btcWatchers == nil {
		s.btcWatchers = make(map[string]*escrow.BTCEscrowWatcher)
	}
	s.btcWatchersMu.Unlock()

	started := 0
	for _, info := range s.AdapterRegistry.List() {
		if info.Symbol != "BTC" {
			continue
		}
		raw, err := s.AdapterRegistry.Get(info.ChainID, info.Symbol)
		if err != nil {
			continue
		}
		btcAdapter, ok := raw.(*btc.BTCAdapter)
		if !ok {
			continue
		}
		s.btcWatchersMu.Lock()
		if _, exists := s.btcWatchers[info.ChainID]; exists {
			s.btcWatchersMu.Unlock()
			continue
		}
		watcher := escrow.NewBTCEscrowWatcher(btcAdapter, btcAdapter)
		s.btcWatchers[info.ChainID] = watcher
		s.btcWatchersMu.Unlock()
		watcher.Start(ctx)
		started++
	}
	return started
}

// WatchBTCEscrow registers a BTC escrow address with the watcher for the
// given chain so funding will be recorded automatically once it confirms
// on-chain. Returns an error if no watcher has been started for the chain
// (call StartBTCWatchers first).
func (s *PlutusSDK) WatchBTCEscrow(chainID, address string, handler escrow.EventHandler) error {
	s.btcWatchersMu.Lock()
	w, ok := s.btcWatchers[chainID]
	s.btcWatchersMu.Unlock()
	if !ok {
		return fmt.Errorf("plutus: no BTC watcher running for chain %q (call StartBTCWatchers first)", chainID)
	}
	w.Watch(address, handler)
	return nil
}

// FeeDistributorHelperConfig configures NewFeeDistributor. It captures the
// caller-supplied parameters that the SDK cannot derive from its own
// subsystems (pool addresses, signer, window, etc.).
type FeeDistributorHelperConfig struct {
	// PayoutAddresses maps chainID → on-chain maintainer-pool address. The
	// distributor uses these both as the "from" address the PayoutBuilder
	// spends from and as the address whose balance the PoolBalanceProvider
	// queries for the cap check.
	PayoutAddresses map[string]string

	// Signer is the FeeDistributionSigner that proves ownership of the pool
	// keys. Typically a *witness.WalletSigner constructed by the caller from
	// encrypted keyfiles on disk.
	Signer witness.FeeDistributionSigner

	// Window is the rolling distribution cadence. Zero means "use the
	// distributor default" (24 hours per DESIGN §17).
	Window time.Duration

	// UseMulticall3 enables batch payouts through Multicall3 for EVM groups.
	UseMulticall3 bool

	// MinPayout is the dust-equivalent threshold in the smallest chain unit
	// (satoshis / wei). Zero means "pay every non-zero witness".
	MinPayout *big.Int

	// PoolBalance is the optional PoolBalanceProvider. When nil, the SDK
	// wires a ChainPoolBalanceProvider whose BTC branch is disabled (no
	// Neutrino client) and whose EVM branch returns ErrPortalNetworkPending.
	// Production deployments should construct their own provider with a live
	// NeutrinoClient and pass it here.
	PoolBalance witness.PoolBalanceProvider

	// Store is the optional DistributionStore. When nil, the SDK's
	// persistent distribution store (DataDir/distributions) is used when
	// one was opened at SDK construction time; otherwise an in-memory
	// store is used as a last-resort fallback (intended only for tests
	// and WASM deployments that deliberately run without a DataDir).
	Store witness.DistributionStore

	// Logger is the optional distributor-level logger.
	Logger witness.Logger
}

// NewFeeDistributor assembles the six collaborator dependencies the witness
// fee distributor needs from the SDK's existing subsystems and returns a
// configured *witness.WitnessFeeDistributor. Callers are responsible for
// starting its RunTicker in a goroutine; this helper only wires.
//
// The six collaborators resolve as follows:
//
//   - Registry     → s.WitnessRegistry
//   - PoolProvider → cfg.PoolBalance (or a default ChainPoolBalanceProvider
//     with no Neutrino client — EVM returns ErrPortalNetworkPending, BTC
//     fails loudly if invoked)
//   - Adapters     → NewWitnessPayoutResolver(s.AdapterRegistry)
//   - Signer       → cfg.Signer
//   - Source       → s.EarningLog (via EarningSource()); required
//   - Broadcaster  → s.BroadcastService (already satisfies the interface)
//   - Store        → cfg.Store, or the SDK's PersistentDistributionStore
//     (opened automatically when Config.DataDir was set), or a last-resort
//     witness.NewInMemoryDistributionStore() when neither is available
//   - PoolAddresses, Window, UseMulticall3, MinPayout → from cfg
//
// Returns an error when the required subsystems are not yet initialized on
// the SDK (EarningLog nil, BroadcastService nil, etc.) so callers see the
// wiring failure at construction time rather than the first round tick.
func (s *PlutusSDK) NewFeeDistributor(cfg FeeDistributorHelperConfig) (*witness.WitnessFeeDistributor, error) {
	if s == nil {
		return nil, fmt.Errorf("plutus: nil SDK receiver")
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("plutus: FeeDistributorHelperConfig.Signer is required")
	}
	if s.WitnessRegistry == nil {
		return nil, fmt.Errorf("plutus: SDK WitnessRegistry not initialized")
	}
	if s.AdapterRegistry == nil {
		return nil, fmt.Errorf("plutus: SDK AdapterRegistry not initialized")
	}
	if s.BroadcastService == nil {
		return nil, fmt.Errorf("plutus: SDK BroadcastService not initialized")
	}
	source := s.EarningSource()
	if source == nil {
		return nil, fmt.Errorf("plutus: SDK has no earning log (Config.DataDir empty); fee distributor requires a persistent source")
	}

	pool := cfg.PoolBalance
	if pool == nil {
		pool = witness.NewChainPoolBalanceProvider(witness.ChainPoolBalanceProviderConfig{
			PoolAddresses: cfg.PayoutAddresses,
		})
	}

	store := cfg.Store
	if store == nil {
		// Prefer the SDK's persistent distribution store when one was opened
		// at New() time (Config.DataDir set). This gives production nodes
		// crash-recovery semantics for free — without it, a restart between
		// ticks would re-process the already-paid window and attempt to
		// double-spend the pool.
		if s.DistributionStore != nil {
			store = s.DistributionStore
		} else {
			// Last-resort in-memory fallback for tests and WASM contexts
			// that deliberately run without a DataDir. Rounds are
			// idempotent within one process lifetime but do NOT survive
			// restarts — do not use this path in production.
			store = witness.NewInMemoryDistributionStore()
		}
	}

	return witness.NewWitnessFeeDistributor(witness.FeeDistributorConfig{
		Registry:      s.WitnessRegistry,
		PoolProvider:  pool,
		Adapters:      NewWitnessPayoutResolver(s.AdapterRegistry),
		Signer:        cfg.Signer,
		Broadcaster:   s.BroadcastService,
		Source:        source,
		Store:         store,
		PoolAddresses: cfg.PayoutAddresses,
		Window:        cfg.Window,
		MinPayout:     cfg.MinPayout,
		UseMulticall3: cfg.UseMulticall3,
		Logger:        cfg.Logger,
	})
}

// EarningSource returns the AttestationSource view of the SDK's earning log,
// suitable for wiring into witness.WitnessFeeDistributor. Returns a typed nil
// when no persistent log was configured (Config.DataDir unset); callers that
// require a live source should check for nil.
func (s *PlutusSDK) EarningSource() witness.AttestationSource {
	// Return a typed nil so interface-value comparisons against nil behave
	// consistently — callers that pass the result to a distributor that
	// requires a non-nil source will see the zero interface value when no
	// log is configured.
	if s.EarningLog == nil {
		return nil
	}
	return s.EarningLog
}

// Close releases any resources held by the SDK. Today this closes the
// EarningLog when one was opened. Safe to call multiple times and on a nil
// receiver.
func (s *PlutusSDK) Close() error {
	if s == nil {
		return nil
	}
	s.StopBTCWatchers()
	var firstErr error
	if s.EarningLog != nil {
		if err := s.EarningLog.Close(); err != nil {
			firstErr = fmt.Errorf("plutus: close earning log: %w", err)
		}
	}
	if s.DistributionStore != nil {
		if err := s.DistributionStore.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("plutus: close distribution store: %w", err)
		}
	}
	return firstErr
}

// StopBTCWatchers stops all running BTC funding watchers and clears the
// internal table.
func (s *PlutusSDK) StopBTCWatchers() {
	s.btcWatchersMu.Lock()
	watchers := s.btcWatchers
	s.btcWatchers = nil
	s.btcWatchersMu.Unlock()
	for _, w := range watchers {
		w.Stop()
	}
}

// --- Bridge adapters ---

// PRCAttester is the interface for attesting Protocol Registry Contract state
// via the witness mesh. Unlike escrow attestation, PRC attestation reads the
// contract's public view functions (maintainerFeeBPS, witnessBPS, maintainerPayout,
// maintainerPubKeyHash) via eth_call through the witness mesh.
type PRCAttester interface {
	// AttestPRCState reads PRC public view functions via the witness mesh and
	// returns the encoded PRC data. Witnesses independently call eth_call on
	// the PRC contract and return quorum-agreed results.
	AttestPRCState(ctx context.Context, chainID, prcAddr string) ([]byte, error)
}

// sdkPRCVerifier implements wallet.MeshVerifier for PRC resolution.
// It uses a dedicated PRC attestation path that reads view functions via
// eth_call, NOT via AttestEscrowState (which is for escrow contracts).
type sdkPRCVerifier struct {
	sdk *PlutusSDK
}

func (v *sdkPRCVerifier) AttestContractState(ctx context.Context, chainID, contractAddr string) ([]byte, error) {
	// Use dedicated PRC attestation: witnesses read the PRC's public view
	// functions (maintainerFeeBPS, witnessBPS, maintainerPayout, maintainerPubKeyHash)
	// via eth_call and return quorum-agreed encoded state.
	//
	// This is intentionally NOT delegated to AttestEscrowState because:
	// 1. The PRC is a regular contract, not an escrow
	// 2. PRC view functions have different ABI than escrow state
	// 3. The witness request type is "prc-state" not "escrow-state"
	snapshot, err := v.sdk.MeshVerifier.AttestPRCState(ctx, chainID, contractAddr)
	if err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (v *sdkPRCVerifier) AttestEscrowState(ctx context.Context, chainID, escrowAddr string) (*wallet.EscrowSnapshot, error) {
	// Delegate to the real witness MeshVerifier so this returns meaningful
	// attested state instead of an empty stub.
	witnessSnapshot, err := v.sdk.MeshVerifier.AttestEscrowState(ctx, chainID, escrowAddr)
	if err != nil {
		return nil, err
	}
	return &wallet.EscrowSnapshot{
		ChainID:    witnessSnapshot.Address,
		EscrowAddr: escrowAddr,
	}, nil
}

// sdkEscrowVerifier implements escrow.MeshVerifier.
type sdkEscrowVerifier struct {
	sdk *PlutusSDK
}

func (v *sdkEscrowVerifier) IsConfirmed(ctx context.Context, chainID string, txHash string) (bool, error) {
	policy := witness.PolicyForValue(50)
	return v.sdk.MeshVerifier.IsConfirmed(ctx, chainID, txHash, policy)
}

func (v *sdkEscrowVerifier) AttestEscrowState(ctx context.Context, chainID string, escrowAddr string) (*escrow.EscrowSnapshot, error) {
	snap, err := v.sdk.MeshVerifier.AttestEscrowState(ctx, chainID, escrowAddr)
	if err != nil {
		return nil, err
	}
	return &escrow.EscrowSnapshot{
		ChainID:    chainID,
		EscrowAddr: escrowAddr,
		State: escrow.OnChainEscrowState{
			Buyer:        snap.Buyer,
			Seller:       snap.Seller,
			Arbitrator:   snap.Arbitrator,
			Amount:       snap.Amount,
			Funded:       snap.Status == witness.EscrowSnapshotStatusFunded,
			Released:     snap.Status == witness.EscrowSnapshotStatusReleased,
			Disputed:     snap.Status == witness.EscrowSnapshotStatusDisputed,
			Settled:      snap.Status == witness.EscrowSnapshotStatusSettled,
			TimeoutBlock: snap.TimeoutAt,
		},
		AttestedAt:   time.Now(),
		WitnessCount: 1,
		Quorum:       true,
	}, nil
}

func (v *sdkEscrowVerifier) BroadcastTx(ctx context.Context, chainID string, signedTx []byte) (string, error) {
	return v.sdk.BroadcastService.BroadcastTx(ctx, chainID, signedTx)
}

// sdkEscrowWallet implements escrow.Wallet.
type sdkEscrowWallet struct {
	sdk  *PlutusSDK
	seed []byte
}

func (w *sdkEscrowWallet) PublicKey() ed25519.PublicKey {
	return w.sdk.PublicKey()
}

func (w *sdkEscrowWallet) ChainAddress(chainID string) (string, error) {
	return w.sdk.ChainAddress(chainID)
}

func (w *sdkEscrowWallet) SignEscrowFunding(tx *escrow.UnsignedTx) ([]byte, error) {
	return ed25519.Sign(w.sdk.IdentityKey, tx.Data), nil
}

func (w *sdkEscrowWallet) SignSettlement(tx *escrow.UnsignedTx, expectedFees escrow.FeeBreakdown) ([]byte, error) {
	// Delegate to the Signer with adapter-level fee breakdown for PRC enforcement.
	adapterFees := adapter.FeeBreakdown{
		MaintainerFee:      expectedFees.MaintainerFee,
		ServiceProviderFee: expectedFees.ServiceProviderFee,
		ArbitratorFee:      expectedFees.ArbitratorFee,
		WitnessFee:         expectedFees.WitnessFee,
		SellerProceeds:     expectedFees.SellerProceeds,
		Total:              expectedFees.Total,
	}
	adapterTx := &adapter.UnsignedTx{
		ChainID: tx.ChainID,
		To:      tx.To,
		Amount:  tx.Value,
		Payload: tx.Data,
	}
	return w.sdk.Signer.SignSettlement(adapterTx, adapterFees)
}

func (w *sdkEscrowWallet) SignDispute(tx *escrow.UnsignedTx) ([]byte, error) {
	return ed25519.Sign(w.sdk.IdentityKey, tx.Data), nil
}

// sdkAdapterResolver implements escrow.AdapterResolver.
type sdkAdapterResolver struct {
	registry *adapter.Registry
}

func (r *sdkAdapterResolver) Resolve(chainID, currency string) (escrow.CurrencyAdapter, error) {
	a, err := r.registry.Get(chainID, currency)
	if err != nil {
		return nil, fmt.Errorf("plutus: no adapter for %s on %s", currency, chainID)
	}
	return &adapterBridge{inner: a}, nil
}

// WitnessPayoutResolver adapts a *adapter.Registry to witness.AdapterResolver
// by looking up registered PayoutBuilders and asserting them back to the
// canonical witness.PayoutBuilder interface. This wrapper exists here rather
// than in the adapter package because adapter → witness would form an import
// cycle (witness depends on adapter.FeeBreakdown).
type WitnessPayoutResolver struct {
	Registry *adapter.Registry
}

// NewWitnessPayoutResolver returns a witness.AdapterResolver backed by the
// given adapter registry. Callers supply the returned value to
// witness.FeeDistributorConfig.Adapters.
func NewWitnessPayoutResolver(r *adapter.Registry) *WitnessPayoutResolver {
	return &WitnessPayoutResolver{Registry: r}
}

// ResolvePayoutBuilder satisfies witness.AdapterResolver.
func (r *WitnessPayoutResolver) ResolvePayoutBuilder(chainID, currency string) (witness.PayoutBuilder, error) {
	if r == nil || r.Registry == nil {
		return nil, fmt.Errorf("plutus: witness payout resolver has no registry")
	}
	raw, err := r.Registry.ResolvePayoutBuilder(chainID, currency)
	if err != nil {
		return nil, err
	}
	b, ok := raw.(witness.PayoutBuilder)
	if !ok {
		return nil, fmt.Errorf("plutus: payout builder for %s/%s does not implement witness.PayoutBuilder (got %T)", chainID, currency, raw)
	}
	return b, nil
}

// adapterBridge adapts adapter.CurrencyAdapter to escrow.CurrencyAdapter.
// The two interfaces have compatible semantics but different parameter/return types
// because escrow defines its own local types to avoid circular imports.
type adapterBridge struct {
	inner adapter.CurrencyAdapter
}

func (b *adapterBridge) ChainID() string   { return b.inner.ChainID() }
func (b *adapterBridge) Currency() string   { return b.inner.Currency() }

func (b *adapterBridge) ConstructEscrow(params escrow.EscrowConstructParams) (*escrow.UnsignedTx, error) {
	ap := adapter.EscrowParams{
		Buyer:          params.Buyer,
		Seller:         params.Seller,
		Amount:         params.Amount,
		TimeoutSeconds: params.TimeoutBlocks,
		ArbitratorAddr: params.Arbitrator,
		WitnessHashes:  params.WitnessHashes,
	}
	if len(params.ReceiptHashes) > 0 {
		ap.ReceiptHash = params.ReceiptHashes[0]
	}
	tx, err := b.inner.ConstructEscrow(ap)
	if err != nil {
		return nil, err
	}
	return adapterTxToEscrowTx(tx), nil
}

func (b *adapterBridge) ReleaseEscrow(escrowAddr string, params escrow.ReleaseParams) (*escrow.UnsignedTx, error) {
	ap := adapter.ReleaseParams{
		WitnessHashes: nil,
	}
	if len(params.ReceiptHashes) > 0 {
		ap.ReceiptHash = params.ReceiptHashes[0]
	}
	tx, err := b.inner.ReleaseEscrow(escrowAddr, ap)
	if err != nil {
		return nil, err
	}
	return adapterTxToEscrowTx(tx), nil
}

func (b *adapterBridge) DisputeEscrow(escrowAddr string, params escrow.DisputeParams) (*escrow.UnsignedTx, error) {
	ap := adapter.DisputeParams{
		EvidenceHash: params.EvidenceHash,
	}
	tx, err := b.inner.DisputeEscrow(escrowAddr, ap)
	if err != nil {
		return nil, err
	}
	return adapterTxToEscrowTx(tx), nil
}

func (b *adapterBridge) SettleWithRuling(escrowAddr string, ruling escrow.Ruling) (*escrow.UnsignedTx, error) {
	ar := adapter.Ruling{
		BuyerPercent:  ruling.BuyerPercent,
		SellerPercent: ruling.SellerPercent,
		Signature:     ruling.ArbitratorSig,
	}
	tx, err := b.inner.SettleWithRuling(escrowAddr, ar)
	if err != nil {
		return nil, err
	}
	return adapterTxToEscrowTx(tx), nil
}

func (b *adapterBridge) RefundAfterTimeout(escrowAddr string) (*escrow.UnsignedTx, error) {
	tx, err := b.inner.RefundAfterTimeout(escrowAddr)
	if err != nil {
		return nil, err
	}
	return adapterTxToEscrowTx(tx), nil
}

func (b *adapterBridge) EscrowState(escrowAddr string) (*escrow.OnChainEscrowState, error) {
	state, err := b.inner.EscrowState(escrowAddr)
	if err != nil {
		return nil, err
	}
	return &escrow.OnChainEscrowState{
		Buyer:        state.Buyer,
		Seller:       state.Seller,
		Arbitrator:   state.ArbitratorAddr,
		Amount:       state.Amount,
		Funded:       state.Status == adapter.EscrowStatusFunded,
		Released:     state.Status == adapter.EscrowStatusReleased,
		Disputed:     state.Status == adapter.EscrowStatusDisputed,
		Settled:      state.Status == adapter.EscrowStatusSettled,
		TimeoutBlock: state.TimeoutAt,
	}, nil
}

// adapterTxToEscrowTx converts an adapter.UnsignedTx to escrow.UnsignedTx.
func adapterTxToEscrowTx(tx *adapter.UnsignedTx) *escrow.UnsignedTx {
	return &escrow.UnsignedTx{
		ChainID:  tx.ChainID,
		To:       tx.To,
		Data:     tx.Payload,
		Value:    tx.Amount,
		GasLimit: tx.GasLimit,
		Nonce:    tx.Nonce,
	}
}

// sdkSettleSigner implements settle.Signer.
type sdkSettleSigner struct {
	signer *wallet.Signer
}

func (s *sdkSettleSigner) SignSettlement(tx *adapter.UnsignedTx, expected adapter.FeeBreakdown) ([]byte, error) {
	return s.signer.SignSettlement(tx, expected)
}

// sdkSettleBroadcaster implements settle.Broadcaster.
type sdkSettleBroadcaster struct {
	sdk *PlutusSDK
}

func (b *sdkSettleBroadcaster) BroadcastTx(ctx context.Context, chainID string, signedTx []byte) (string, error) {
	return b.sdk.BroadcastService.BroadcastTx(ctx, chainID, signedTx)
}

// sdkAntiGamingVerifier implements reputation.ChainVerifier.
type sdkAntiGamingVerifier struct {
	sdk *PlutusSDK
}

func (v *sdkAntiGamingVerifier) IsConfirmed(ctx context.Context, chainID string, txHash string) (bool, error) {
	policy := witness.PolicyForValue(50)
	return v.sdk.MeshVerifier.IsConfirmed(ctx, chainID, txHash, policy)
}

// chainIDToCoinType maps chain IDs to BIP44 coin types.
func chainIDToCoinType(chainID string) uint32 {
	switch chainID {
	case "ethereum", "eth":
		return 60
	case "polygon", "matic":
		return 966
	case "bitcoin", "btc":
		return 0
	case "solana", "sol":
		return 501
	case "avalanche", "avax":
		return 9005
	default:
		return 60
	}
}

// sdkFeeCalcBridge adapts settle.FeeCalculator to escrow.FeeCalculator.
// The two packages define compatible types but cannot import each other.
type sdkFeeCalcBridge struct {
	calc *settle.FeeCalculator
}

func (b *sdkFeeCalcBridge) Calculate(amount *big.Int, opts escrow.FeeOptions) (escrow.FeeBreakdown, error) {
	adapterOpts := adapter.FeeOptions{
		MaintainerBPS:      opts.MaintainerBPS,
		HasServiceProvider: opts.HasServiceProvider,
		ServiceProviderBPS: opts.ServiceProviderBPS,
		HasDispute:         opts.HasDispute,
		ArbitratorBPS:      opts.ArbitratorBPS,
		HasWitness:         opts.HasWitness,
		WitnessBPS:         opts.WitnessBPS,
	}
	result, err := b.calc.Calculate(amount, adapterOpts)
	if err != nil {
		return escrow.FeeBreakdown{}, err
	}
	return escrow.FeeBreakdown{
		MaintainerFee:      result.MaintainerFee,
		ServiceProviderFee: result.ServiceProviderFee,
		ArbitratorFee:      result.ArbitratorFee,
		WitnessFee:         result.WitnessFee,
		SellerProceeds:     result.SellerProceeds,
		Total:              result.Total,
	}, nil
}
