/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package witness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"
)

// WitnessFeeDistributor sweeps attestation records over a rolling window,
// aggregates witness earnings per (chainID, currency, witnessPubkey), resolves
// each witness's declared chain-specific payout address from the
// WitnessRegistry, and signs + broadcasts a batch payout transaction per
// (chainID, currency) group.
//
// Rationale (see PlutusEscrow.sol:191): the EVM escrow contract knows only the
// aggregate maintainerPayout address at deployment time. Actual attesting
// witnesses are determined by quorum *after* the contract is deployed, so they
// cannot be split on-chain at release. This distributor closes that loop
// off-chain by periodically paying out from the maintainer pool balance.
//
// Key architectural note on signer separation:
//
// The distributor's signer is a SEPARATE key from the Offline Root / Platform
// Key that signs protocol attestations and the adapter descriptors. It is a
// hot wallet key with custody of the maintainer pool balance. Compromise of
// the distributor signer is bounded to at most one distribution window's
// worth of fees (typically 24h of accumulated witness fees), not the
// protocol's root trust chain. Operators are expected to rotate this key on
// a regular cadence and to cap the pool balance via off-boarding sweeps to
// cold storage.
//
// Invariant: for each (chainID, currency) group, the sum of individual payouts
// is <= the pool balance at the start of the distribution round. Any residual
// (rounding truncation, dust-skipped witnesses, missing-address witnesses)
// remains in the pool for the next round.
type WitnessFeeDistributor struct {
	registry     *WitnessRegistry
	poolProvider PoolBalanceProvider
	adapters     AdapterResolver
	signer       FeeDistributionSigner
	broadcaster  FeeDistributionBroadcaster
	source       AttestationSource
	store        DistributionStore

	// Pool payout addresses per chain, keyed by chainID. These are the
	// maintainer-pool source addresses that own the aggregate fees.
	poolAddresses map[string]string

	window        time.Duration // e.g. 24h
	minPayout     *big.Int      // dust threshold per (witness, chain, currency)
	useMulticall3 bool          // EVM: prefer Multicall3 batching when true

	log Logger

	mu         sync.Mutex
	lastRoundAt time.Time
}

// FeeDistributorConfig configures a new WitnessFeeDistributor. The zero value
// is invalid; at minimum Registry, Signer, Broadcaster, Adapters and Source
// must be set.
type FeeDistributorConfig struct {
	Registry      *WitnessRegistry
	PoolProvider  PoolBalanceProvider
	Adapters      AdapterResolver
	Signer        FeeDistributionSigner
	Broadcaster   FeeDistributionBroadcaster
	Source        AttestationSource
	Store         DistributionStore
	PoolAddresses map[string]string
	Window        time.Duration
	MinPayout     *big.Int
	UseMulticall3 bool
	Logger        Logger
}

// Logger is a minimal logging interface so the distributor can operate in
// WASM and test contexts without pulling a structured-logging dependency.
type Logger interface {
	Printf(format string, args ...interface{})
}

// nopLogger discards all output. Default when the caller supplies no logger.
type nopLogger struct{}

func (nopLogger) Printf(string, ...interface{}) {}

// PoolBalanceProvider reports the current balance of the maintainer pool
// address on a specific chain. Implementations wrap a ChainBalanceProvider
// or equivalent adapter-side hook.
type PoolBalanceProvider interface {
	PoolBalance(ctx context.Context, chainID, currency string) (*big.Int, error)
}

// AdapterResolver is the subset of adapter.Registry the distributor needs to
// build chain-specific payout transactions. Implementations typically wrap
// adapter.Registry.Get. Kept as a local interface to avoid a hard dependency
// on the adapter package from within the witness package.
type AdapterResolver interface {
	// ResolvePayoutBuilder returns a PayoutBuilder suitable for constructing
	// batch payout transactions on (chainID, currency). Returns an error when
	// no adapter is registered for the pair.
	ResolvePayoutBuilder(chainID, currency string) (PayoutBuilder, error)
}

// PayoutBuilder is the chain-specific transaction assembler the distributor
// calls to turn a list of Payouts into an unsigned batch tx. EVM builders
// emit either a Multicall3-style payload or a slice of individual transfers;
// BTC builders emit a single tx with N outputs.
type PayoutBuilder interface {
	BuildBatchPayout(from string, payouts []Payout, useMulticall3 bool) (UnsignedBatch, error)
}

// WindowAwarePayoutBuilder is an optional extension of PayoutBuilder for
// builders that can embed DESIGN §17 first-writer-wins metadata directly into
// the emitted transaction payload (EVM: call PRC.distributeWindow rather than
// Multicall3; BTC: append an OP_RETURN with (windowID, attestationLogRoot)).
//
// The distributor prefers the window-aware path when the builder implements
// this interface AND both windowID and attestationLogRoot are non-zero. Plain
// PayoutBuilder implementations still work — they just produce a batch whose
// windowID/root are stamped onto UnsignedBatch metadata rather than embedded
// in the serialized tx.
type WindowAwarePayoutBuilder interface {
	PayoutBuilder
	// BuildWindowedBatchPayout is called by the distributor when first-writer-wins
	// metadata is available. Implementations should fall back to the non-windowed
	// path when windowID == 0 || attestationLogRoot is zero; callers (the
	// distributor) guarantee both are non-zero at the call site, but belt-and-
	// braces checks keep the interface safe to invoke from audit tooling.
	BuildWindowedBatchPayout(
		from string,
		payouts []Payout,
		useMulticall3 bool,
		windowID uint64,
		attestationLogRoot [32]byte,
	) (UnsignedBatch, error)
}

// UnsignedBatch is the chain-agnostic handle for an assembled batch payout.
// The Kind field tells the signer how to interpret Payload/Items/ItemPayloads.
type UnsignedBatch struct {
	ChainID  string
	Currency string
	Kind     BatchKind
	// WindowID is the distribution-window nonce that identifies THIS round
	// to the chain's idempotency gate. Computed as the window-start Unix
	// timestamp truncated to the configured window duration (so two
	// witnesses that race the same round produce the same WindowID and the
	// contract-side DistributeWindow(chainID, windowID, ...) rejects the
	// second call as a replay). See DESIGN.md §17 first-writer-wins.
	WindowID uint64
	// AttestationLogRoot is a Merkle root over the (sorted) AttestationIDs
	// that fed this round's aggregated earnings. It binds the payout batch
	// to the specific set of attestations that earned the fees, so auditors
	// and the on-chain gate can detect a witness that omitted or fabricated
	// earning records. A zero value indicates the builder had no attestation
	// IDs to bind (e.g. fallback path during settle.Executor rollout).
	//
	// NOTE: the EVM contract-side DistributeWindow(chainID, windowID,
	// attestationLogRoot, payouts[]) check is a SEPARATE follow-up; today
	// the distributor populates the value and builders embed it in calldata
	// (EVM: trailing OP-style word; BTC: OP_RETURN output) so the on-chain
	// gate can ratchet onto it without a protocol break once it ships.
	AttestationLogRoot [32]byte
	// Payload is the single-tx serialization. For BatchKindEVMMulticall3
	// this is one marshaled EVMBatchEnvelope (the aggregate Multicall3 tx).
	// For BatchKindBTCMultiOutput this is the unsigned BTC tx. Nil/empty
	// for BatchKindEVMIndividual, where each sub-tx is carried in
	// ItemPayloads instead.
	Payload []byte
	// Items are the per-witness structured summaries (to/amount/optional
	// calldata) for individual-transfers kinds. Informational — the
	// signer works off ItemPayloads for true per-item signing. Populated
	// alongside ItemPayloads for BatchKindEVMIndividual.
	Items []UnsignedBatchItem
	// ItemPayloads holds one fully-marshaled sub-transaction envelope per
	// payout item, in item-order. Populated for BatchKindEVMIndividual
	// (each entry is one marshaled EVMBatchEnvelope with its own to/value/
	// data, and later its own nonce stamped by the EVMEnvelopeFinalizer).
	// Nil for single-tx kinds (which use Payload instead).
	ItemPayloads [][]byte
	// Sighashes is the per-input signing digest produced by the builder.
	// Populated for BatchKindBTCMultiOutput (one entry per pool UTXO, in
	// input order) so the signer can produce ECDSA signatures without
	// re-deriving BIP143 preimages. Empty for EVM kinds (EVM signers hash
	// the full tx themselves).
	Sighashes [][]byte
	// InputScripts is the per-input scriptCode used to derive each
	// corresponding entry in Sighashes. Populated alongside Sighashes for
	// BTC so signers can verify they are re-deriving the same digest before
	// signing. Empty for EVM kinds.
	InputScripts [][]byte
	// InputValues is the per-input previous-output amount (satoshis) used
	// in the BIP143 preimage. Populated alongside Sighashes for BTC; empty
	// for EVM kinds.
	InputValues []int64
}

// BatchKind identifies how the signer should process an UnsignedBatch.
type BatchKind int

const (
	// BatchKindUnspecified is the zero value — builders must set a real kind.
	BatchKindUnspecified BatchKind = iota
	// BatchKindEVMMulticall3 is a single Multicall3 transaction aggregating N
	// safeTransfer calls. Lowest gas per payout when Multicall3 is deployed
	// on the target chain (0xcA11bde05977b3631167028862bE2a173976CA11).
	BatchKindEVMMulticall3
	// BatchKindEVMIndividual is N separate EVM transactions, one per payout.
	// Used when Multicall3 is unavailable or the pool is a multisig that
	// cannot delegate calls through Multicall3 safely.
	BatchKindEVMIndividual
	// BatchKindBTCMultiOutput is a single Bitcoin transaction with N outputs
	// (one per witness). Signed with BIP143 P2WSH identically to the Release
	// tx, with deterministic output ordering (by witness address).
	BatchKindBTCMultiOutput
)

// UnsignedBatchItem is one sub-transaction in a KindIndividualTransfers
// batch. Only relevant for the EVM individual-transfers fallback.
type UnsignedBatchItem struct {
	To      string
	Amount  *big.Int
	Payload []byte
}

// FeeDistributionSigner signs an UnsignedBatch with the distributor's hot
// wallet key. Returns a chain-ready signed payload (or a slice of signed
// payloads for BatchKindEVMIndividual).
type FeeDistributionSigner interface {
	SignBatchPayout(ctx context.Context, batch UnsignedBatch) (SignedBatch, error)
}

// SignedBatch is the signer's output: one serialized tx per on-wire
// broadcast (one element for the single-tx kinds; N for
// BatchKindEVMIndividual).
type SignedBatch struct {
	ChainID string
	Txs     [][]byte
}

// FeeDistributionBroadcaster pushes the signed batch to the chain. Typically
// wraps BroadcastService.BroadcastTx or an adapter-side mempool submission.
type FeeDistributionBroadcaster interface {
	BroadcastTx(ctx context.Context, chainID string, signedTx []byte) (string, error)
}

// AttestationSource is the read-side of accumulated per-order earnings. The
// canonical implementation reads from settlement records emitted by
// settle.Executor (each record contains the FeeBreakdown.WitnessFees map).
// Kept as a narrow interface so tests can feed records deterministically.
type AttestationSource interface {
	// CollectEarnings returns all witness earnings in the given window,
	// already grouped by (chainID, currency, hex(pubkey)).
	CollectEarnings(ctx context.Context, start, end time.Time) ([]EarningRecord, error)
}

// EarningRecord captures a single witness's earnings for one settled order.
// The distributor aggregates EarningRecords across many orders before
// computing per-witness payouts.
type EarningRecord struct {
	OrderID        string
	ChainID        string
	Currency       string
	WitnessPubKey  string // hex
	Amount         *big.Int
	AttestationID  []byte // audit handle (e.g. settlement receipt hash)
	SettledAt      time.Time
}

// Payout is the per-witness, per-chain, per-currency payout command that the
// chain-side PayoutBuilder assembles into a batch transaction.
type Payout struct {
	WitnessPubKey  []byte
	WitnessAddr    string // chain-specific; hex (EVM) or bech32 (BTC)
	ChainID        string
	Currency       string
	Amount         *big.Int
	AttestationIDs [][]byte
}

// DistributionStore persists per-round records for audit and idempotency.
// Implementations can be in-memory (tests) or backed by Ledger.
type DistributionStore interface {
	// LoadRound returns a previously-written round keyed by the deterministic
	// round ID derived from the window bounds. Returns (nil, nil) when the
	// round has not been persisted.
	LoadRound(ctx context.Context, roundID string) (*DistributionRoundResult, error)
	// SaveRound writes a completed round. Implementations must be atomic with
	// respect to LoadRound so concurrent Run calls never double-pay.
	SaveRound(ctx context.Context, round *DistributionRoundResult) error
}

// DistributionRoundResult is the audit record for one distribution run.
type DistributionRoundResult struct {
	RoundID     string
	WindowStart time.Time
	WindowEnd   time.Time
	StartedAt   time.Time
	CompletedAt time.Time
	Receipts    []DistributionReceipt
	Skipped     []SkippedPayout
	// ResidualByGroup tracks the amount left in the pool after this round
	// for each (chainID, currency) key. Values include both dust-skipped and
	// missing-address amounts, so the next round knows how much carries over.
	ResidualByGroup map[string]*big.Int
}

// DistributionReceipt is one successful broadcast within a round.
type DistributionReceipt struct {
	ChainID       string
	Currency      string
	TxHash        string
	Payouts       []Payout
	BroadcastedAt time.Time
}

// SkippedPayout records a witness that was skipped this round (dust or
// missing payout address) so the next round's operator can diagnose.
type SkippedPayout struct {
	WitnessPubKey string // hex
	ChainID       string
	Currency      string
	Amount        *big.Int
	Reason        string
}

// Errors surfaced by the distributor. Callers can errors.Is these to decide
// whether to retry or surface to the operator.
var (
	// ErrRoundAlreadyProcessed is returned when Run is invoked for a window
	// whose deterministic round ID is already present in the store.
	ErrRoundAlreadyProcessed = errors.New("witness/fee_distributor: round already processed")
	// ErrDistributorNotConfigured is returned when required dependencies are
	// missing at Run time.
	ErrDistributorNotConfigured = errors.New("witness/fee_distributor: not configured")
)

// NewWitnessFeeDistributor constructs a distributor from cfg. The only
// required fields are Registry, Signer, Broadcaster, Adapters, and Source —
// the rest have sane defaults (24h window, zero dust threshold, in-memory
// store, noop logger).
func NewWitnessFeeDistributor(cfg FeeDistributorConfig) (*WitnessFeeDistributor, error) {
	if cfg.Registry == nil {
		return nil, fmt.Errorf("%w: registry is required", ErrDistributorNotConfigured)
	}
	if cfg.Signer == nil {
		return nil, fmt.Errorf("%w: signer is required", ErrDistributorNotConfigured)
	}
	if cfg.Broadcaster == nil {
		return nil, fmt.Errorf("%w: broadcaster is required", ErrDistributorNotConfigured)
	}
	if cfg.Adapters == nil {
		return nil, fmt.Errorf("%w: adapters is required", ErrDistributorNotConfigured)
	}
	if cfg.Source == nil {
		return nil, fmt.Errorf("%w: source is required", ErrDistributorNotConfigured)
	}
	window := cfg.Window
	if window <= 0 {
		window = 24 * time.Hour
	}
	minPayout := cfg.MinPayout
	if minPayout == nil {
		minPayout = new(big.Int) // zero dust threshold: pay everything
	}
	store := cfg.Store
	if store == nil {
		store = newMemDistributionStore()
	}
	logger := cfg.Logger
	if logger == nil {
		logger = nopLogger{}
	}
	pools := cfg.PoolAddresses
	if pools == nil {
		pools = make(map[string]string)
	}
	return &WitnessFeeDistributor{
		registry:      cfg.Registry,
		poolProvider:  cfg.PoolProvider,
		adapters:      cfg.Adapters,
		signer:        cfg.Signer,
		broadcaster:   cfg.Broadcaster,
		source:        cfg.Source,
		store:         store,
		poolAddresses: pools,
		window:        window,
		minPayout:     new(big.Int).Set(minPayout),
		useMulticall3: cfg.UseMulticall3,
		log:           logger,
	}, nil
}

// Window returns the configured distribution window (default 24h).
func (d *WitnessFeeDistributor) Window() time.Duration { return d.window }

// Run executes a single distribution round covering [windowStart, windowEnd].
// Steps (see plan):
//  1. Derive a deterministic round ID and early-out when the store already
//     has a record (idempotency).
//  2. Collect all EarningRecords in the window from the AttestationSource.
//  3. Aggregate by (chainID, currency, witnessPubkey).
//  4. For each (chainID, currency) group:
//     a. Check pool balance via PoolProvider (when configured); cap the
//        total by the pool balance so we never overspend.
//     b. Resolve each witness's payout address from the WitnessRegistry,
//        filtering out below-minPayout and missing-address entries to the
//        Skipped slice (residual stays in the pool for the next round).
//     c. Build a batch payout via the chain's PayoutBuilder, sign via
//        FeeDistributionSigner, broadcast via FeeDistributionBroadcaster.
//  5. Persist the round result.
func (d *WitnessFeeDistributor) Run(ctx context.Context, windowStart, windowEnd time.Time) (*DistributionRoundResult, error) {
	if windowEnd.Before(windowStart) {
		return nil, fmt.Errorf("witness/fee_distributor: window end %s before start %s", windowEnd, windowStart)
	}

	roundID := roundIDFor(windowStart, windowEnd)
	if existing, err := d.store.LoadRound(ctx, roundID); err != nil {
		return nil, fmt.Errorf("witness/fee_distributor: load round: %w", err)
	} else if existing != nil {
		return existing, ErrRoundAlreadyProcessed
	}

	startedAt := time.Now()

	records, err := d.source.CollectEarnings(ctx, windowStart, windowEnd)
	if err != nil {
		return nil, fmt.Errorf("witness/fee_distributor: collect earnings: %w", err)
	}

	// DESIGN §17 first-writer-wins metadata.
	//
	// windowID is the window-start Unix timestamp truncated to the configured
	// window duration. Two witnesses racing the same round produce the same
	// value, which is what the on-chain DistributeWindow gate uses to reject
	// a duplicate call as a replay.
	//
	// attestationLogRoot is the Merkle root of the (sorted) AttestationIDs
	// that fed this round's aggregated earnings. It binds the payout batch
	// to the specific attestation set that earned the fees so a cheating
	// witness cannot silently drop or fabricate earning records.
	windowID := uint64(truncateToWindow(windowStart, d.window).Unix())
	attestationLogRoot := attestationMerkleRoot(records)

	groups := aggregateEarnings(records)

	result := &DistributionRoundResult{
		RoundID:         roundID,
		WindowStart:     windowStart,
		WindowEnd:       windowEnd,
		StartedAt:       startedAt,
		ResidualByGroup: make(map[string]*big.Int),
	}

	// Process groups in deterministic order so tests and audit logs are stable.
	groupKeys := make([]groupKey, 0, len(groups))
	for k := range groups {
		groupKeys = append(groupKeys, k)
	}
	sort.Slice(groupKeys, func(i, j int) bool {
		if groupKeys[i].chainID != groupKeys[j].chainID {
			return groupKeys[i].chainID < groupKeys[j].chainID
		}
		return groupKeys[i].currency < groupKeys[j].currency
	})

	for _, gk := range groupKeys {
		agg := groups[gk]
		groupResidual := new(big.Int)
		receipts, skipped, err := d.processGroup(ctx, gk, agg, groupResidual, windowID, attestationLogRoot)
		// Record residual regardless of error so the next round has the full
		// picture of what wasn't paid.
		d.recordResidual(result, gk, groupResidual)
		result.Skipped = append(result.Skipped, skipped...)
		// Partial success: for BatchKindEVMIndividual a mid-batch broadcast
		// failure returns both the receipts for txs that DID land AND an
		// error for the group. Preserve those receipts so the audit log
		// reflects reality; the residual already accounts for the unpaid
		// payouts via recordResidual above.
		result.Receipts = append(result.Receipts, receipts...)
		if err != nil {
			// Log and continue to the next group — one chain's outage must not
			// stall payouts on other chains. The round is still persisted
			// with whatever succeeded, so the operator can investigate.
			d.log.Printf("fee_distributor: group %s/%s failed: %v", gk.chainID, gk.currency, err)
			continue
		}
	}

	result.CompletedAt = time.Now()
	if err := d.store.SaveRound(ctx, result); err != nil {
		return result, fmt.Errorf("witness/fee_distributor: save round: %w", err)
	}

	d.mu.Lock()
	d.lastRoundAt = result.CompletedAt
	d.mu.Unlock()

	return result, nil
}

// RunTicker invokes Run on a d.window cadence until ctx is cancelled. Each
// tick pays out the window ending at the tick time. Designed to be called
// from a goroutine by the mercury-node --distribute-witness-fees mode.
//
// Equivalent to RunTickerWith(ctx, 0, nil).
func (d *WitnessFeeDistributor) RunTicker(ctx context.Context) error {
	return d.RunTickerWith(ctx, 0, nil)
}

// RunTickerWith is the configurable form of RunTicker.
//
//   - initialDelay: a jitter before the first round fires (useful when many
//     witnesses share the same window duration and we want to stagger their
//     first tick so they don't all race the same round). Zero runs immediately.
//   - throttle: optional predicate. If non-nil and it returns true at tick
//     time, the scheduled round is skipped for this window. Callers use this
//     to wire an ORBTR-style resource governor into the loop without
//     duplicating the ticker plumbing.
//
// Both parameters are safe to leave at their zero value; RunTicker wraps this
// with (0, nil). ctx cancellation always takes precedence.
func (d *WitnessFeeDistributor) RunTickerWith(ctx context.Context, initialDelay time.Duration, throttle func() bool) error {
	if initialDelay > 0 {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(initialDelay):
		}
	}

	ticker := time.NewTicker(d.window)
	defer ticker.Stop()

	runOnce := func(end time.Time) {
		if throttle != nil && throttle() {
			d.log.Printf("fee_distributor: throttled by governor, deferring window ending %s", end.UTC().Format(time.RFC3339))
			return
		}
		start := end.Add(-d.window)
		if _, err := d.Run(ctx, start, end); err != nil && !errors.Is(err, ErrRoundAlreadyProcessed) {
			d.log.Printf("fee_distributor: round [%s → %s]: %v",
				start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339), err)
		}
	}

	// Run once immediately so operators don't wait a full window before the
	// first payout. Safe because the store dedupes by round ID.
	runOnce(time.Now())

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case t := <-ticker.C:
			runOnce(t)
		}
	}
}

// LastRoundAt returns the wall-clock time the last Run completed, or the
// zero value if Run has not yet succeeded on this instance.
func (d *WitnessFeeDistributor) LastRoundAt() time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastRoundAt
}

// processGroup handles one (chainID, currency) group. Errors returned here
// are scoped to one group — the caller (Run) logs and moves on so other
// groups can still settle. residual is mutated in place to reflect amounts
// that stayed in the pool (dust, missing address, cap truncation).
//
// windowID and attestationLogRoot are the DESIGN §17 first-writer-wins
// metadata computed once per round by Run; processGroup stamps them onto
// the UnsignedBatch so builders can embed them in calldata (EVM) or in
// an OP_RETURN output (BTC).
func (d *WitnessFeeDistributor) processGroup(
	ctx context.Context,
	gk groupKey,
	agg map[string]*aggEntry,
	residual *big.Int,
	windowID uint64,
	attestationLogRoot [32]byte,
) ([]DistributionReceipt, []SkippedPayout, error) {
	// Assemble per-witness payouts, resolving addresses and applying the dust
	// threshold.
	var (
		payouts []Payout
		skipped []SkippedPayout
	)
	// Deterministic order by hex pubkey.
	witKeys := make([]string, 0, len(agg))
	for k := range agg {
		witKeys = append(witKeys, k)
	}
	sort.Strings(witKeys)

	for _, witHex := range witKeys {
		e := agg[witHex]
		if e.amount.Cmp(d.minPayout) < 0 {
			skipped = append(skipped, SkippedPayout{
				WitnessPubKey: witHex,
				ChainID:       gk.chainID,
				Currency:      gk.currency,
				Amount:        new(big.Int).Set(e.amount),
				Reason:        "below min payout",
			})
			residual.Add(residual, e.amount)
			continue
		}
		addr, err := d.resolvePayoutAddress(witHex, gk.chainID)
		if err != nil {
			skipped = append(skipped, SkippedPayout{
				WitnessPubKey: witHex,
				ChainID:       gk.chainID,
				Currency:      gk.currency,
				Amount:        new(big.Int).Set(e.amount),
				Reason:        err.Error(),
			})
			residual.Add(residual, e.amount)
			d.log.Printf("fee_distributor: no payout address for witness %s on %s: %v", witHex[:16], gk.chainID, err)
			continue
		}
		pk, err := hex.DecodeString(witHex)
		if err != nil {
			// Defensive — aggregation keys come from hex-encoded pubkeys, so
			// this branch should be unreachable.
			skipped = append(skipped, SkippedPayout{
				WitnessPubKey: witHex,
				ChainID:       gk.chainID,
				Currency:      gk.currency,
				Amount:        new(big.Int).Set(e.amount),
				Reason:        "invalid pubkey hex",
			})
			residual.Add(residual, e.amount)
			continue
		}
		payouts = append(payouts, Payout{
			WitnessPubKey:  pk,
			WitnessAddr:    addr,
			ChainID:        gk.chainID,
			Currency:       gk.currency,
			Amount:         new(big.Int).Set(e.amount),
			AttestationIDs: append([][]byte(nil), e.attestationIDs...),
		})
	}

	if len(payouts) == 0 {
		return nil, skipped, nil
	}

	// Cap against pool balance when a provider is configured. Any overflow is
	// proportionally deferred to the next round (we simply drop the highest-
	// index witnesses since payouts are sorted by hex — deterministic). The
	// residual is added to "residual" for audit.
	if d.poolProvider != nil {
		poolBal, err := d.poolProvider.PoolBalance(ctx, gk.chainID, gk.currency)
		if err != nil {
			// Pool balance check is best-effort. Log and continue; on-chain
			// broadcasts will fail loudly if the pool is actually empty, and
			// that's what the retry-next-round path handles.
			d.log.Printf("fee_distributor: pool balance check failed for %s/%s: %v", gk.chainID, gk.currency, err)
		} else if poolBal != nil {
			payouts = capPayoutsToBalance(payouts, poolBal, residual)
			if len(payouts) == 0 {
				d.log.Printf("fee_distributor: pool balance zero for %s/%s, deferring full group", gk.chainID, gk.currency)
				return nil, skipped, nil
			}
		}
	}

	// Resolve the chain-specific payout builder and assemble the batch.
	builder, err := d.adapters.ResolvePayoutBuilder(gk.chainID, gk.currency)
	if err != nil {
		// Entire group's amount is residual for next round.
		for _, p := range payouts {
			residual.Add(residual, p.Amount)
		}
		return nil, skipped, fmt.Errorf("resolve payout builder: %w", err)
	}
	fromAddr := d.poolAddresses[gk.chainID]
	// Prefer the window-aware builder path when the implementation supports
	// it AND the round has non-zero first-writer-wins metadata. This lets
	// EVM builders target PRC.distributeWindow (the on-chain idempotency
	// gate) and BTC builders append an OP_RETURN carrying (windowID, root)
	// for off-chain audit. Plain PayoutBuilder falls back to the legacy
	// Multicall3 / multi-output path and only stamps the metadata onto the
	// UnsignedBatch envelope.
	var (
		batch UnsignedBatch
	)
	var zeroRoot [32]byte
	useWindowed := windowID != 0 && attestationLogRoot != zeroRoot
	if aware, ok := builder.(WindowAwarePayoutBuilder); ok && useWindowed {
		batch, err = aware.BuildWindowedBatchPayout(fromAddr, payouts, d.useMulticall3, windowID, attestationLogRoot)
	} else {
		batch, err = builder.BuildBatchPayout(fromAddr, payouts, d.useMulticall3)
	}
	if err != nil {
		for _, p := range payouts {
			residual.Add(residual, p.Amount)
		}
		return nil, skipped, fmt.Errorf("build batch payout: %w", err)
	}
	// Stamp DESIGN §17 first-writer-wins metadata onto the batch even when a
	// window-aware builder has already embedded it in calldata, so downstream
	// audit consumers can read the values off the UnsignedBatch envelope
	// without having to decode the serialized payload.
	batch.WindowID = windowID
	batch.AttestationLogRoot = attestationLogRoot

	signed, err := d.signer.SignBatchPayout(ctx, batch)
	if err != nil {
		for _, p := range payouts {
			residual.Add(residual, p.Amount)
		}
		return nil, skipped, fmt.Errorf("sign batch payout: %w", err)
	}

	// Broadcast each sub-transaction. For single-tx kinds (Multicall3,
	// BTC multi-output) len(signed.Txs) is 1 and the whole payouts slice
	// settles atomically on-chain. For BatchKindEVMIndividual there is
	// exactly one signed tx per payout, indexed 1:1 via signed.Txs[i] ↔
	// payouts[i]; a mid-batch failure must NOT over-count the residual by
	// adding already-successful payouts[0..i-1], and each receipt is
	// stamped with just the one payout its tx actually paid.
	isIndividual := batch.Kind == BatchKindEVMIndividual
	if isIndividual && len(signed.Txs) != len(payouts) {
		// Signer broke the 1:1 contract. Roll the whole group back into
		// residual and surface so the operator can debug the signer.
		for _, p := range payouts {
			residual.Add(residual, p.Amount)
		}
		return nil, skipped, fmt.Errorf("signer returned %d txs for %d individual payouts", len(signed.Txs), len(payouts))
	}
	var receipts []DistributionReceipt
	for i, tx := range signed.Txs {
		txHash, err := d.broadcaster.BroadcastTx(ctx, gk.chainID, tx)
		if err != nil {
			if isIndividual {
				// Only the tx at index i (and any later, un-broadcast txs)
				// are still in the pool. Payouts[0..i-1] already landed on
				// chain and MUST NOT be added back into residual.
				for j := i; j < len(payouts); j++ {
					residual.Add(residual, payouts[j].Amount)
				}
			} else {
				// Single-tx kinds (Multicall3, BTC multi-output): failure
				// means the entire batch is still in the pool.
				for _, p := range payouts {
					residual.Add(residual, p.Amount)
				}
			}
			return receipts, skipped, fmt.Errorf("broadcast: %w", err)
		}
		// Attribute the receipt to just the payout(s) this tx actually paid.
		var receiptPayouts []Payout
		if isIndividual {
			receiptPayouts = []Payout{payouts[i]}
		} else {
			receiptPayouts = payouts
		}
		receipts = append(receipts, DistributionReceipt{
			ChainID:       gk.chainID,
			Currency:      gk.currency,
			TxHash:        txHash,
			Payouts:       receiptPayouts,
			BroadcastedAt: time.Now(),
		})
	}
	return receipts, skipped, nil
}

// resolvePayoutAddress looks up the witness's configured on-chain payout
// address for the given chain from its registration record. Returns a
// non-nil error if the witness is not registered or has no address
// configured for the requested chain; callers are expected to route the
// corresponding fee share into the residual bucket and log the skip rather
// than fabricate a fallback address.
func (d *WitnessFeeDistributor) resolvePayoutAddress(witHex string, chainID string) (string, error) {
	pk, err := hex.DecodeString(witHex)
	if err != nil {
		return "", fmt.Errorf("invalid witness pubkey hex: %w", err)
	}
	reg := d.registry.Get(pk)
	if reg == nil {
		return "", fmt.Errorf("witness not registered")
	}
	addr, ok := reg.PayoutAddresses[chainID]
	if !ok || addr == "" {
		return "", fmt.Errorf("witness %s has no payout address configured for chain %s", witHex[:16], chainID)
	}
	return addr, nil
}

// capPayoutsToBalance scales the payouts slice proportionally when the
// aggregate amount exceeds poolBal. Every witness's payout is multiplied by
// poolBal / sum(payouts) using *big.Int math (floor-division so truncation
// dust falls to residual). Payouts of zero after scaling (under-dust shares
// on very small pool balances) are dropped into residual so we don't emit
// zero-value on-chain transfers.
//
// Ordering is preserved for deterministic output. A pool balance of zero
// (or negative, defensively) scales every payout to zero and returns an
// empty slice; a pool balance that covers every payout in full returns the
// slice unchanged.
//
// Rationale: the old lex-drop behaviour (iterate in pubkey-sorted order,
// skip anything that wouldn't fit) starved late-sorted witnesses forever,
// because their hex prefix put them at the tail of a deterministic sort.
// Pro-rata scaling gives every witness their fair share of the available
// balance in the same round, preserving the witness-fair invariant.
func capPayoutsToBalance(payouts []Payout, poolBal, residual *big.Int) []Payout {
	if poolBal == nil {
		return payouts
	}
	// Defensive: a negative pool balance is a provider bug — treat as zero
	// so we don't emit payouts signed against a phantom balance.
	if poolBal.Sign() <= 0 {
		for _, p := range payouts {
			residual.Add(residual, p.Amount)
		}
		return nil
	}
	total := new(big.Int)
	for i := range payouts {
		total.Add(total, payouts[i].Amount)
	}
	if total.Sign() == 0 {
		return payouts
	}
	if total.Cmp(poolBal) <= 0 {
		return payouts
	}
	// Pro-rata: scaled[i] = floor(payouts[i].Amount * poolBal / total).
	// We use integer-math-then-reconcile so dust from floor-division falls
	// to residual instead of silently inflating someone's share.
	scaled := make([]Payout, 0, len(payouts))
	scaledSum := new(big.Int)
	for _, p := range payouts {
		// newAmount = p.Amount * poolBal / total
		numer := new(big.Int).Mul(p.Amount, poolBal)
		newAmount := new(big.Int).Quo(numer, total)
		if newAmount.Sign() <= 0 {
			// Under-dust scale — drop this payout entirely into residual.
			residual.Add(residual, p.Amount)
			continue
		}
		// Track what stayed in the pool for this witness (original - scaled).
		leftover := new(big.Int).Sub(p.Amount, newAmount)
		if leftover.Sign() > 0 {
			residual.Add(residual, leftover)
		}
		scaledSum.Add(scaledSum, newAmount)
		cp := p
		cp.Amount = newAmount
		scaled = append(scaled, cp)
	}
	// Any remaining dust from floor-division that we haven't already
	// attributed above (should be zero given our accounting, but
	// defensively roll it in) falls to residual too.
	if diff := new(big.Int).Sub(poolBal, scaledSum); diff.Sign() > 0 {
		// Note: we deliberately do NOT add this to residual — it never left
		// the pool in the first place. Pool balance includes it already.
		_ = diff
	}
	return scaled
}

func (d *WitnessFeeDistributor) recordResidual(result *DistributionRoundResult, gk groupKey, residual *big.Int) {
	if residual == nil || residual.Sign() == 0 {
		return
	}
	key := gk.chainID + ":" + gk.currency
	if existing, ok := result.ResidualByGroup[key]; ok {
		existing.Add(existing, residual)
		return
	}
	result.ResidualByGroup[key] = new(big.Int).Set(residual)
}

// groupKey is the aggregation pivot: (chainID, currency). Witnesses are the
// inner axis.
type groupKey struct {
	chainID  string
	currency string
}

// aggEntry holds the running total and attestation trail for one witness in
// one (chainID, currency) group.
type aggEntry struct {
	amount         *big.Int
	attestationIDs [][]byte
}

// aggregateEarnings collapses a flat EarningRecord slice into a nested map
// of (group -> witness hex -> aggEntry). Nil or zero amounts are dropped.
func aggregateEarnings(records []EarningRecord) map[groupKey]map[string]*aggEntry {
	out := make(map[groupKey]map[string]*aggEntry)
	for _, r := range records {
		if r.Amount == nil || r.Amount.Sign() <= 0 {
			continue
		}
		if r.WitnessPubKey == "" || r.ChainID == "" {
			continue
		}
		gk := groupKey{chainID: r.ChainID, currency: r.Currency}
		inner, ok := out[gk]
		if !ok {
			inner = make(map[string]*aggEntry)
			out[gk] = inner
		}
		entry, ok := inner[r.WitnessPubKey]
		if !ok {
			entry = &aggEntry{amount: new(big.Int)}
			inner[r.WitnessPubKey] = entry
		}
		entry.amount.Add(entry.amount, r.Amount)
		if len(r.AttestationID) > 0 {
			entry.attestationIDs = append(entry.attestationIDs, r.AttestationID)
		}
	}
	return out
}

// truncateToWindow rounds t down to the nearest multiple of window. Used by
// Run to derive a deterministic WindowID that two witnesses racing the same
// round will compute identically. A non-positive window degrades to t itself
// so callers (tests, ad-hoc invocations) with zero window don't divide by
// zero.
func truncateToWindow(t time.Time, window time.Duration) time.Time {
	if window <= 0 {
		return t
	}
	return t.Truncate(window)
}

// attestationMerkleRoot returns the Merkle root of the deduped AttestationIDs
// in records. Sorting is byte-lexicographic by the hashed-leaf form so the
// root is deterministic across witnesses with different record-collection
// orders. Empty input (or records with no AttestationIDs populated) yields
// the zero [32]byte.
//
// Hash function is keccak256 and inner-node folding uses the OpenZeppelin
// sorted-pair convention: node = keccak256(min(a,b) || max(a,b)). This
// matches libraries/MerkleProof.sol so the on-chain PRC disputeDistribution
// gate can verify a Merkle proof against the same root this function
// produces — see DESIGN §17 anti-omission.
//
// Leaves are keccak256(attestationID) so the 32-byte domain boundary between
// leaf and inner-node hashes is explicit. This is consistent with the OZ
// Merkle-tree JavaScript helpers that hash leaves once before tree building.
func attestationMerkleRoot(records []EarningRecord) [32]byte {
	// Collect non-empty attestation IDs, dedup, hash each to a leaf.
	seen := make(map[string]struct{}, len(records))
	leaves := make([][]byte, 0, len(records))
	for _, r := range records {
		if len(r.AttestationID) == 0 {
			continue
		}
		key := string(r.AttestationID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		leaves = append(leaves, keccakLeaf(r.AttestationID))
	}
	if len(leaves) == 0 {
		return [32]byte{}
	}
	return foldSortedPairTree(leaves)
}

// keccakLeaf computes the keccak256 hash of data for use as a Merkle-tree
// leaf. Separated out so BuildMerkleRoot (public) and attestationMerkleRoot
// (internal) hash leaves identically.
func keccakLeaf(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// foldSortedPairTree folds a slice of 32-byte leaves into a single Merkle
// root using the OpenZeppelin sorted-pair convention:
//
//	parent = keccak256(min(L, R) || max(L, R))
//
// Leaves are sorted byte-lexicographically before folding so that two
// witnesses computing the root over the same set of attestation IDs
// converge to the same value regardless of iteration order. Odd tails are
// promoted unchanged to the next level (also matching OZ standard trees).
func foldSortedPairTree(leaves [][]byte) [32]byte {
	if len(leaves) == 0 {
		return [32]byte{}
	}
	// Copy before sort so we don't mutate caller-owned slices.
	work := make([][]byte, len(leaves))
	for i, l := range leaves {
		work[i] = append([]byte(nil), l...)
	}
	sort.Slice(work, func(i, j int) bool {
		return bytes.Compare(work[i], work[j]) < 0
	})
	for len(work) > 1 {
		next := make([][]byte, 0, (len(work)+1)/2)
		for i := 0; i < len(work); i += 2 {
			if i+1 == len(work) {
				// Odd tail: promote unchanged (OZ standard-tree behaviour).
				next = append(next, work[i])
				continue
			}
			next = append(next, keccakPair(work[i], work[i+1]))
		}
		work = next
	}
	var out [32]byte
	copy(out[:], work[0])
	return out
}

// keccakPair hashes two 32-byte words in canonical sorted order
// (keccak256(min || max)), matching libraries/MerkleProof.sol._hashPair.
func keccakPair(a, b []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	if bytes.Compare(a, b) <= 0 {
		h.Write(a)
		h.Write(b)
	} else {
		h.Write(b)
		h.Write(a)
	}
	return h.Sum(nil)
}

// roundIDFor derives a deterministic round ID from the window bounds. Two
// calls with the same bounds produce the same ID, which is how
// DistributionStore provides the idempotency guarantee.
func roundIDFor(start, end time.Time) string {
	h := sha256.New()
	var buf [8]byte
	writeU64(h, &buf, uint64(start.UnixNano()))
	writeU64(h, &buf, uint64(end.UnixNano()))
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:16])
}

func writeU64(h interface{ Write([]byte) (int, error) }, buf *[8]byte, v uint64) {
	buf[0] = byte(v >> 56)
	buf[1] = byte(v >> 48)
	buf[2] = byte(v >> 40)
	buf[3] = byte(v >> 32)
	buf[4] = byte(v >> 24)
	buf[5] = byte(v >> 16)
	buf[6] = byte(v >> 8)
	buf[7] = byte(v)
	_, _ = h.Write(buf[:])
}

// memDistributionStore is an in-memory DistributionStore used as the default
// when no persistent store is wired. Tests rely on this implementation and
// production deployments should override with a Ledger-backed store.
type memDistributionStore struct {
	mu     sync.Mutex
	rounds map[string]*DistributionRoundResult
}

func newMemDistributionStore() *memDistributionStore {
	return &memDistributionStore{rounds: make(map[string]*DistributionRoundResult)}
}

func (s *memDistributionStore) LoadRound(_ context.Context, roundID string) (*DistributionRoundResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.rounds[roundID]
	if !ok {
		return nil, nil
	}
	return r, nil
}

func (s *memDistributionStore) SaveRound(_ context.Context, round *DistributionRoundResult) error {
	if round == nil {
		return errors.New("witness/fee_distributor: save nil round")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.rounds[round.RoundID]; exists {
		return fmt.Errorf("%w: %s", ErrRoundAlreadyProcessed, round.RoundID)
	}
	s.rounds[round.RoundID] = round
	return nil
}
