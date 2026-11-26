package settle

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/bbmumford/plutus/adapter"
	"github.com/bbmumford/plutus/observability"
	"go.opentelemetry.io/otel/attribute"
)

// Signer signs settlement transactions after fee verification.
type Signer interface {
	SignSettlement(tx *adapter.UnsignedTx, expected adapter.FeeBreakdown) ([]byte, error)
}

// Broadcaster relays signed transactions to the blockchain via the witness mesh.
type Broadcaster interface {
	BroadcastTx(ctx context.Context, chainID string, signedTx []byte) (string, error)
}

// SettlementResult contains the outcome of a settlement execution.
type SettlementResult struct {
	TxHash     string
	Fees       adapter.FeeBreakdown
	EscrowAddr string
	ChainID    string
}

// BalanceAttesterLookup returns the hex-encoded witness pubkeys that should
// share the witness fee for a given settlement context (typically an escrow
// address or order ID). Returning an empty slice (or nil) causes the executor
// to fall back to single-recipient legacy witness payouts. Implementations
// are typically backed by BalanceVerifier.RecentBalanceAttesters.
type BalanceAttesterLookup func(orderContext string) []string

// EarningRecorder is the write side of the per-witness settlement earnings
// log. The executor invokes Record after every successful settlement so the
// witness fee distributor can later compute pro-rata payouts. The canonical
// implementation is witness.EarningLog, but the executor depends on the
// narrow interface for testability and to keep the settle package decoupled
// from witness.
type EarningRecorder interface {
	Record(ctx context.Context, orderID string, chainID string, currency string, at time.Time, breakdown adapter.FeeBreakdown) error
}

// noopEarningRecorder is the default Recorder when no EarningLog is wired.
// Its Record method always returns nil so settlement proceeds identically
// whether or not an earning log has been attached.
type noopEarningRecorder struct{}

func (noopEarningRecorder) Record(context.Context, string, string, string, time.Time, adapter.FeeBreakdown) error {
	return nil
}

// SettlementExecutor orchestrates the end-to-end settlement flow:
//  1. Calculate fees via FeeCalculator.
//  2. Construct a release transaction via the CurrencyAdapter.
//  3. Sign the transaction via the Signer (which enforces fee correctness).
//  4. Broadcast the signed transaction via the Broadcaster.
//  5. Record per-witness earnings via the EarningRecorder (for later fee
//     distribution).
//
// Every step is verified independently — the adapter constructs, the calculator
// verifies, the signer re-verifies, and the broadcaster confirms.
type SettlementExecutor struct {
	calculator  *FeeCalculator
	signer      Signer
	broadcaster Broadcaster
	attesters   BalanceAttesterLookup // optional; nil = no per-witness split
	recorder    EarningRecorder       // optional; defaults to no-op
}

// SetBalanceAttesterLookup installs a BalanceAttesterLookup so subsequent
// Execute/ExecuteWithRuling calls attribute a share of the witness fee to
// each balance witness that attested the queried balances leading up to
// settlement. Safe to call once at wiring time; concurrent callers must
// synchronise externally.
func (e *SettlementExecutor) SetBalanceAttesterLookup(l BalanceAttesterLookup) {
	e.attesters = l
}

// SetEarningRecorder installs an EarningRecorder so subsequent Execute /
// ExecuteWithRuling calls log per-witness fee earnings for later pro-rata
// distribution. Passing nil restores the no-op default. Safe to call once at
// wiring time; concurrent callers must synchronise externally.
func (e *SettlementExecutor) SetEarningRecorder(r EarningRecorder) {
	if r == nil {
		e.recorder = noopEarningRecorder{}
		return
	}
	e.recorder = r
}

// NewSettlementExecutor creates a new settlement executor.
func NewSettlementExecutor(calculator *FeeCalculator, signer Signer, broadcaster Broadcaster) (*SettlementExecutor, error) {
	if calculator == nil {
		return nil, errors.New("plutus/settle: calculator is nil")
	}
	if signer == nil {
		return nil, errors.New("plutus/settle: signer is nil")
	}
	if broadcaster == nil {
		return nil, errors.New("plutus/settle: broadcaster is nil")
	}
	return &SettlementExecutor{
		calculator:  calculator,
		signer:      signer,
		broadcaster: broadcaster,
		recorder:    noopEarningRecorder{},
	}, nil
}

// Execute performs a full settlement on the given escrow.
//
// Parameters:
//   - ctx: context for cancellation and timeouts
//   - currAdapter: the chain-specific adapter for this escrow's chain/currency
//   - escrowAddr: the on-chain escrow contract address
//   - opts: fee options sourced from PRC data and escrow metadata
//
// The executor refuses to proceed if any verification step fails.
func (e *SettlementExecutor) Execute(
	ctx context.Context,
	currAdapter adapter.CurrencyAdapter,
	escrowAddr string,
	opts adapter.FeeOptions,
) (*SettlementResult, error) {
	ctx, span := observability.Tracer("plutus.settle").Start(ctx, "SettlementExecutor.Execute")
	defer span.End()
	span.SetAttributes(attribute.String(observability.AttrEscrowAddr, escrowAddr))
	start := time.Now()
	defer func() {
		observability.SettlementDuration().Record(ctx, float64(time.Since(start).Milliseconds()))
	}()

	if currAdapter == nil {
		err := errors.New("plutus/settle: adapter is nil")
		observability.RecordError(span, err)
		return nil, err
	}
	if escrowAddr == "" {
		err := errors.New("plutus/settle: escrow address is empty")
		observability.RecordError(span, err)
		return nil, err
	}
	span.SetAttributes(attribute.String(observability.AttrChainID, currAdapter.ChainID()))

	// 1. Query escrow state to get the amount.
	state, err := currAdapter.EscrowState(escrowAddr)
	if err != nil {
		return nil, fmt.Errorf("plutus/settle: query escrow state: %w", err)
	}
	if state.Status != adapter.EscrowStatusFunded && state.Status != adapter.EscrowStatusDisputed {
		return nil, fmt.Errorf("plutus/settle: escrow status %d is not settleable", state.Status)
	}

	// 2. Calculate fees deterministically. When an attester lookup is wired,
	// split the witness fee across balance-attesting witnesses for this
	// escrow context; otherwise the aggregate witness fee flows to the
	// transaction witness as before.
	var attesters []string
	if e.attesters != nil {
		attesters = e.attesters(escrowAddr)
	}
	fees, err := e.calculator.CalculateWithWitnesses(state.Amount, opts, attesters)
	if err != nil {
		return nil, fmt.Errorf("plutus/settle: fee calculation: %w", err)
	}

	// 3. Construct the release transaction via the adapter.
	releaseParams := adapter.ReleaseParams{
		Fees: fees,
	}
	tx, err := currAdapter.ReleaseEscrow(escrowAddr, releaseParams)
	if err != nil {
		return nil, fmt.Errorf("plutus/settle: construct release tx: %w", err)
	}

	// 4. Verify fees against the transaction (belt and suspenders).
	if err := e.calculator.Verify(tx, fees); err != nil {
		return nil, fmt.Errorf("plutus/settle: fee verification: %w", err)
	}

	// 5. Sign the transaction (signer re-verifies fees independently).
	sig, err := e.signer.SignSettlement(tx, fees)
	if err != nil {
		return nil, fmt.Errorf("plutus/settle: signing: %w", err)
	}

	// 6. Build the signed transaction payload (signature prepended to payload).
	signedTx := make([]byte, 0, len(sig)+len(tx.Payload))
	signedTx = append(signedTx, sig...)
	signedTx = append(signedTx, tx.Payload...)

	// 7. Broadcast via the witness mesh.
	txHash, err := e.broadcaster.BroadcastTx(ctx, currAdapter.ChainID(), signedTx)
	if err != nil {
		wrapped := fmt.Errorf("plutus/settle: broadcast: %w", err)
		observability.RecordError(span, wrapped)
		observability.GossipBroadcastFailures().Add(ctx, 1)
		return nil, wrapped
	}
	observability.GossipBroadcastCount().Add(ctx, 1)
	observability.SettlementCount().Add(ctx, 1,
		observability.AttrSet(attribute.String(observability.AttrChainID, currAdapter.ChainID())))
	if total := feeTotal(fees); total.IsInt64() {
		observability.SettlementFeeTotal().Record(ctx, total.Int64())
	}
	span.SetAttributes(attribute.String(observability.AttrTxHash, txHash))

	// Record per-witness earnings for later fee distribution. Record errors
	// are non-fatal — settlement already succeeded on-chain, so we surface via
	// span recording and continue.
	if err := e.recorder.Record(ctx, escrowAddr, currAdapter.ChainID(), currAdapter.Currency(), time.Now().UTC(), fees); err != nil {
		observability.RecordError(span, fmt.Errorf("plutus/settle: record earnings: %w", err))
	}

	return &SettlementResult{
		TxHash:     txHash,
		Fees:       fees,
		EscrowAddr: escrowAddr,
		ChainID:    currAdapter.ChainID(),
	}, nil
}

// ExecuteWithRuling performs settlement for a disputed escrow with an
// arbitrator ruling. The ruling determines how funds are split between
// buyer and seller, with all protocol fees still enforced.
func (e *SettlementExecutor) ExecuteWithRuling(
	ctx context.Context,
	currAdapter adapter.CurrencyAdapter,
	escrowAddr string,
	ruling adapter.Ruling,
	opts adapter.FeeOptions,
) (*SettlementResult, error) {
	ctx, span := observability.Tracer("plutus.settle").Start(ctx, "SettlementExecutor.ExecuteWithRuling")
	defer span.End()
	span.SetAttributes(attribute.String(observability.AttrEscrowAddr, escrowAddr))
	start := time.Now()
	defer func() {
		observability.SettlementDuration().Record(ctx, float64(time.Since(start).Milliseconds()))
	}()

	if currAdapter == nil {
		err := errors.New("plutus/settle: adapter is nil")
		observability.RecordError(span, err)
		return nil, err
	}
	if escrowAddr == "" {
		err := errors.New("plutus/settle: escrow address is empty")
		observability.RecordError(span, err)
		return nil, err
	}
	if ruling.BuyerPercent+ruling.SellerPercent != 100 {
		err := fmt.Errorf("plutus/settle: ruling percentages must sum to 100, got %d", ruling.BuyerPercent+ruling.SellerPercent)
		observability.RecordError(span, err)
		return nil, err
	}
	span.SetAttributes(attribute.String(observability.AttrChainID, currAdapter.ChainID()))

	// Query escrow state.
	state, err := currAdapter.EscrowState(escrowAddr)
	if err != nil {
		return nil, fmt.Errorf("plutus/settle: query escrow state: %w", err)
	}
	if state.Status != adapter.EscrowStatusDisputed {
		return nil, fmt.Errorf("plutus/settle: escrow status %d is not disputed", state.Status)
	}

	// Ensure dispute flag is set in fee options.
	opts.HasDispute = true

	// Calculate fees with optional per-witness distribution.
	var attesters []string
	if e.attesters != nil {
		attesters = e.attesters(escrowAddr)
	}
	fees, err := e.calculator.CalculateWithWitnesses(state.Amount, opts, attesters)
	if err != nil {
		return nil, fmt.Errorf("plutus/settle: fee calculation: %w", err)
	}

	// Construct ruling settlement transaction.
	tx, err := currAdapter.SettleWithRuling(escrowAddr, ruling)
	if err != nil {
		return nil, fmt.Errorf("plutus/settle: construct ruling tx: %w", err)
	}

	// Verify fees.
	if err := e.calculator.Verify(tx, fees); err != nil {
		return nil, fmt.Errorf("plutus/settle: fee verification: %w", err)
	}

	// Sign.
	sig, err := e.signer.SignSettlement(tx, fees)
	if err != nil {
		return nil, fmt.Errorf("plutus/settle: signing: %w", err)
	}

	signedTx := make([]byte, 0, len(sig)+len(tx.Payload))
	signedTx = append(signedTx, sig...)
	signedTx = append(signedTx, tx.Payload...)

	// Broadcast.
	txHash, err := e.broadcaster.BroadcastTx(ctx, currAdapter.ChainID(), signedTx)
	if err != nil {
		wrapped := fmt.Errorf("plutus/settle: broadcast: %w", err)
		observability.RecordError(span, wrapped)
		observability.GossipBroadcastFailures().Add(ctx, 1)
		return nil, wrapped
	}
	observability.GossipBroadcastCount().Add(ctx, 1)
	observability.SettlementCount().Add(ctx, 1,
		observability.AttrSet(
			attribute.String(observability.AttrChainID, currAdapter.ChainID()),
			attribute.Int(observability.AttrOutcome+".buyer_pct", int(ruling.BuyerPercent)),
		))
	span.SetAttributes(attribute.String(observability.AttrTxHash, txHash))

	// Record per-witness earnings for later fee distribution. Non-fatal.
	if err := e.recorder.Record(ctx, escrowAddr, currAdapter.ChainID(), currAdapter.Currency(), time.Now().UTC(), fees); err != nil {
		observability.RecordError(span, fmt.Errorf("plutus/settle: record earnings: %w", err))
	}

	return &SettlementResult{
		TxHash:     txHash,
		Fees:       fees,
		EscrowAddr: escrowAddr,
		ChainID:    currAdapter.ChainID(),
	}, nil
}

// feeTotal is what a settlement pays out in fees: the maintainer, service
// provider, arbitrator and witness fees, without the seller's proceeds. The
// SettlementFeeTotal histogram records it; fees.Total is the whole escrow
// amount, proceeds included.
func feeTotal(fees adapter.FeeBreakdown) *big.Int {
	sum := new(big.Int)
	for _, f := range []*big.Int{fees.MaintainerFee, fees.ServiceProviderFee, fees.ArbitratorFee, fees.WitnessFee} {
		if f != nil {
			sum.Add(sum, f)
		}
	}
	return sum
}
