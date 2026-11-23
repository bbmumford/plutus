/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package escrow

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/bbmumford/plutus/observability"
	"go.opentelemetry.io/otel/attribute"
)

// CurrencyAdapter is the interface that chain-specific adapters implement.
// Defined locally to avoid circular imports with the adapter package.
type CurrencyAdapter interface {
	ChainID() string
	Currency() string
	ConstructEscrow(params EscrowConstructParams) (*UnsignedTx, error)
	ReleaseEscrow(escrowAddr string, params ReleaseParams) (*UnsignedTx, error)
	DisputeEscrow(escrowAddr string, params DisputeParams) (*UnsignedTx, error)
	SettleWithRuling(escrowAddr string, ruling Ruling) (*UnsignedTx, error)
	RefundAfterTimeout(escrowAddr string) (*UnsignedTx, error)
	EscrowState(escrowAddr string) (*OnChainEscrowState, error)
}

// FeeBreakdown contains the fee split for a settlement transaction.
// Defined locally to avoid circular imports with the adapter package.
type FeeBreakdown struct {
	MaintainerFee      *big.Int
	ServiceProviderFee *big.Int
	ArbitratorFee      *big.Int
	WitnessFee         *big.Int
	SellerProceeds     *big.Int
	Total              *big.Int
}

// Wallet is the interface for transaction signing with fee enforcement.
type Wallet interface {
	PublicKey() ed25519.PublicKey
	ChainAddress(chainID string) (string, error)
	SignEscrowFunding(tx *UnsignedTx) ([]byte, error)
	SignSettlement(tx *UnsignedTx, expectedFees FeeBreakdown) ([]byte, error)
	SignDispute(tx *UnsignedTx) ([]byte, error)
}

// MeshVerifier verifies chain state via witness quorum attestations.
type MeshVerifier interface {
	IsConfirmed(ctx context.Context, chainID string, txHash string) (bool, error)
	AttestEscrowState(ctx context.Context, chainID string, escrowAddr string) (*EscrowSnapshot, error)
	BroadcastTx(ctx context.Context, chainID string, signedTx []byte) (string, error)
}

// UnsignedTx represents a transaction ready for signing.
type UnsignedTx struct {
	ChainID  string
	To       string
	Data     []byte
	Value    *big.Int
	GasLimit uint64
	Nonce    uint64
}

// EscrowConstructParams are passed to the CurrencyAdapter to build the escrow TX.
type EscrowConstructParams struct {
	Amount        *big.Int
	Buyer         string
	Seller        string
	Arbitrator    string
	TimeoutBlocks uint64
	ReceiptHashes [][]byte
	WitnessHashes [][]byte
	AppID         string
}

// OnChainEscrowState is the raw state returned by a CurrencyAdapter.
type OnChainEscrowState struct {
	Buyer         string
	Seller        string
	Arbitrator    string
	Amount        *big.Int
	Funded        bool
	Released      bool
	Disputed      bool
	Settled       bool
	TimedOut      bool
	TimeoutBlock  uint64
	CurrentBlock  uint64
}

// EscrowSnapshot is the witness-attested view of escrow state.
type EscrowSnapshot struct {
	ChainID      string
	EscrowAddr   string
	State        OnChainEscrowState
	AttestedAt   time.Time
	WitnessCount int
	Quorum       bool
}

// Manager defines the full escrow lifecycle API.
type Manager interface {
	Fund(ctx context.Context, params FundParams) (*EscrowInstance, error)
	Release(ctx context.Context, escrowAddr string, params ReleaseParams) (string, error)
	Dispute(ctx context.Context, escrowAddr string, params DisputeParams) (string, error)
	SettleWithRuling(ctx context.Context, escrowAddr string, ruling Ruling) (string, error)
	RefundAfterTimeout(ctx context.Context, escrowAddr string) (string, error)
	State(ctx context.Context, escrowAddr string) (*EscrowState, error)
	Watch(ctx context.Context, escrowAddr string, handler EventHandler) (cancel func())
}

// FundParams contains all parameters needed to create and fund an escrow.
type FundParams struct {
	Amount        *big.Int
	Buyer         string
	Seller        string
	Currency      string
	ChainID       string
	Arbitrator    string   // optional
	TimeoutBlocks uint64
	ReceiptHashes [][]byte // service provider receipts
	WitnessHashes [][]byte // witness attestation hashes
	AppID         string   // optional tracking
}

// EscrowInstance represents a funded escrow on-chain.
type EscrowInstance struct {
	Address   string
	ChainID   string
	TxHash    string
	Params    FundParams
	CreatedAt time.Time
}

// EscrowState is the current state of an escrow as attested by witnesses.
type EscrowState struct {
	Address      string
	ChainID      string
	Buyer        string
	Seller       string
	Arbitrator   string
	Amount       *big.Int
	Status       EscrowStatus
	Funded       bool
	Released     bool
	Disputed     bool
	Settled      bool
	TimedOut     bool
	TimeoutBlock uint64
	CurrentBlock uint64
	AttestedAt   time.Time
	WitnessCount int
	Quorum       bool
}

// EscrowStatus enumerates escrow lifecycle states.
type EscrowStatus string

const (
	StatusPending  EscrowStatus = "pending"
	StatusFunded   EscrowStatus = "funded"
	StatusReleased EscrowStatus = "released"
	StatusDisputed EscrowStatus = "disputed"
	StatusSettled  EscrowStatus = "settled"
	StatusTimedOut EscrowStatus = "timed_out"
)

// EventHandler receives escrow lifecycle events.
type EventHandler func(event EscrowEvent)

// EscrowEvent represents a state change on an escrow.
type EscrowEvent struct {
	Type   string
	TxHash string
	Data   interface{}
}

// ReleaseParams contains parameters for releasing escrow funds.
type ReleaseParams struct {
	ReceiptHashes [][]byte // proof of service delivery
	Memo          string   // optional note
}

// DisputeParams contains parameters for filing a dispute.
type DisputeParams struct {
	Evidence     []byte
	EvidenceHash []byte
}

// Ruling represents an arbitrator's decision on a disputed escrow.
type Ruling struct {
	Outcome       string
	BuyerPercent  uint32
	SellerPercent uint32
	ArbitratorSig []byte
}

// AdapterResolver looks up a CurrencyAdapter by chainID + currency pair.
type AdapterResolver interface {
	Resolve(chainID, currency string) (CurrencyAdapter, error)
}

// FeeCalculator computes fee breakdowns for settlement signing.
// Defined here to avoid circular imports with the settle package.
type FeeCalculator interface {
	Calculate(amount *big.Int, opts FeeOptions) (FeeBreakdown, error)
}

// FeeOptions configures the fee calculation inputs for escrow release.
type FeeOptions struct {
	MaintainerBPS      uint32
	HasServiceProvider bool
	ServiceProviderBPS uint32
	HasDispute         bool
	ArbitratorBPS      uint32
	HasWitness         bool
	WitnessBPS         uint32
}

// EscrowManager implements the Manager interface by orchestrating
// CurrencyAdapter, Wallet, and MeshVerifier interactions.
type EscrowManager struct {
	adapters AdapterResolver
	wallet   Wallet
	verifier MeshVerifier
	feeCalc  FeeCalculator

	mu       sync.RWMutex
	escrows  map[string]*EscrowInstance // address -> instance
	watchers map[string]*watcher        // address -> active watcher
}

// NewEscrowManager creates a new EscrowManager.
func NewEscrowManager(adapters AdapterResolver, wallet Wallet, verifier MeshVerifier, opts ...EscrowManagerOption) *EscrowManager {
	m := &EscrowManager{
		adapters: adapters,
		wallet:   wallet,
		verifier: verifier,
		escrows:  make(map[string]*EscrowInstance),
		watchers: make(map[string]*watcher),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// EscrowManagerOption configures optional EscrowManager dependencies.
type EscrowManagerOption func(*EscrowManager)

// WithFeeCalculator sets the fee calculator used for release signing.
func WithFeeCalculator(fc FeeCalculator) EscrowManagerOption {
	return func(m *EscrowManager) {
		m.feeCalc = fc
	}
}

// State queries the current escrow state via witness attestations.
func (m *EscrowManager) State(ctx context.Context, escrowAddr string) (*EscrowState, error) {
	ctx, span := observability.Tracer("plutus.escrow").Start(ctx, "EscrowManager.State")
	defer span.End()
	span.SetAttributes(attribute.String(observability.AttrEscrowAddr, escrowAddr))
	observability.EscrowStateQueries().Add(ctx, 1)

	inst, err := m.getInstance(escrowAddr)
	if err != nil {
		observability.RecordError(span, err)
		return nil, err
	}

	snapshot, err := m.verifier.AttestEscrowState(ctx, inst.ChainID, escrowAddr)
	if err != nil {
		wrapped := fmt.Errorf("escrow: witness attestation failed for %s: %w", escrowAddr, err)
		observability.RecordError(span, wrapped)
		return nil, wrapped
	}

	return snapshotToState(escrowAddr, inst.ChainID, snapshot), nil
}

// Watch starts monitoring an escrow for state changes via witnesses.
// Returns a cancel function that stops the watcher.
func (m *EscrowManager) Watch(ctx context.Context, escrowAddr string, handler EventHandler) func() {
	inst, err := m.getInstance(escrowAddr)
	if err != nil {
		// Fire an error event and return a no-op cancel
		handler(EscrowEvent{Type: "error", Data: err})
		return func() {}
	}

	w := newWatcher(m.verifier, inst.ChainID, escrowAddr, handler)

	m.mu.Lock()
	m.watchers[escrowAddr] = w
	m.mu.Unlock()

	watchCtx, cancel := context.WithCancel(ctx)
	go w.run(watchCtx)

	return func() {
		cancel()
		m.mu.Lock()
		delete(m.watchers, escrowAddr)
		m.mu.Unlock()
	}
}

// getInstance retrieves a tracked escrow instance.
func (m *EscrowManager) getInstance(escrowAddr string) (*EscrowInstance, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	inst, ok := m.escrows[escrowAddr]
	if !ok {
		return nil, fmt.Errorf("escrow: unknown escrow address %s", escrowAddr)
	}
	return inst, nil
}

// resolveAdapter finds the adapter for a given escrow instance.
func (m *EscrowManager) resolveAdapter(inst *EscrowInstance) (CurrencyAdapter, error) {
	return m.adapters.Resolve(inst.ChainID, inst.Params.Currency)
}

// snapshotToState converts a witness snapshot to an EscrowState.
func snapshotToState(addr, chainID string, snap *EscrowSnapshot) *EscrowState {
	status := StatusPending
	switch {
	case snap.State.TimedOut:
		status = StatusTimedOut
	case snap.State.Settled:
		status = StatusSettled
	case snap.State.Disputed:
		status = StatusDisputed
	case snap.State.Released:
		status = StatusReleased
	case snap.State.Funded:
		status = StatusFunded
	}

	return &EscrowState{
		Address:      addr,
		ChainID:      chainID,
		Buyer:        snap.State.Buyer,
		Seller:       snap.State.Seller,
		Arbitrator:   snap.State.Arbitrator,
		Amount:       snap.State.Amount,
		Status:       status,
		Funded:       snap.State.Funded,
		Released:     snap.State.Released,
		Disputed:     snap.State.Disputed,
		Settled:      snap.State.Settled,
		TimedOut:     snap.State.TimedOut,
		TimeoutBlock: snap.State.TimeoutBlock,
		CurrentBlock: snap.State.CurrentBlock,
		AttestedAt:   snap.AttestedAt,
		WitnessCount: snap.WitnessCount,
		Quorum:       snap.Quorum,
	}
}

// AnchorEvidence computes the SHA-256 hash of dispute evidence for on-chain anchoring.
func AnchorEvidence(evidence []byte) ([]byte, error) {
	if len(evidence) == 0 {
		return nil, fmt.Errorf("escrow: evidence must not be empty")
	}
	h := sha256.Sum256(evidence)
	return h[:], nil
}
