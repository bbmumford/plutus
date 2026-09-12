/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package settle

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/bbmumford/plutus/adapter"
)

// fakeAdapter is a minimal CurrencyAdapter for testing the executor.
type fakeAdapter struct {
	chainID string
	state   *adapter.EscrowState
}

func (f *fakeAdapter) ChainID() string  { return f.chainID }
func (f *fakeAdapter) Currency() string { return "USDC" }
func (f *fakeAdapter) Symbol() string   { return "USDC" }

func (f *fakeAdapter) ConstructEscrow(adapter.EscrowParams) (*adapter.UnsignedTx, error) {
	return nil, errors.New("not used")
}
func (f *fakeAdapter) FundEscrow(string, *big.Int) (*adapter.UnsignedTx, error) {
	return nil, errors.New("not used")
}
func (f *fakeAdapter) ReleaseEscrow(addr string, p adapter.ReleaseParams) (*adapter.UnsignedTx, error) {
	return &adapter.UnsignedTx{
		ChainID: f.chainID,
		To:      addr,
		Amount:  new(big.Int).Set(p.Fees.Total),
		Payload: []byte("release-payload"),
	}, nil
}
func (f *fakeAdapter) DisputeEscrow(string, adapter.DisputeParams) (*adapter.UnsignedTx, error) {
	return nil, errors.New("not used")
}
func (f *fakeAdapter) SettleWithRuling(addr string, r adapter.Ruling) (*adapter.UnsignedTx, error) {
	return &adapter.UnsignedTx{
		ChainID: f.chainID,
		To:      addr,
		Amount:  new(big.Int).Set(f.state.Amount),
		Payload: []byte("settle-payload"),
	}, nil
}
func (f *fakeAdapter) RefundAfterTimeout(string) (*adapter.UnsignedTx, error) {
	return nil, errors.New("not used")
}
func (f *fakeAdapter) EscrowState(string) (*adapter.EscrowState, error) {
	return f.state, nil
}
func (f *fakeAdapter) Balance(string) (*big.Int, error) { return nil, errors.New("not used") }
func (f *fakeAdapter) CalculateFees(*big.Int, adapter.FeeOptions) adapter.FeeBreakdown {
	return adapter.FeeBreakdown{}
}

type fakeSigner struct {
	lastFees adapter.FeeBreakdown
	err      error
}

func (f *fakeSigner) SignSettlement(tx *adapter.UnsignedTx, expected adapter.FeeBreakdown) ([]byte, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.lastFees = expected
	return []byte("signature"), nil
}

type fakeBroadcaster struct {
	lastChainID string
	lastTx      []byte
	txHash      string
	err         error
}

func (f *fakeBroadcaster) BroadcastTx(ctx context.Context, chainID string, signedTx []byte) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	f.lastChainID = chainID
	f.lastTx = signedTx
	if f.txHash == "" {
		return "0xTXHASH", nil
	}
	return f.txHash, nil
}

func TestSettlementExecutor_HappyPath(t *testing.T) {
	t.Parallel()

	adapterImpl := &fakeAdapter{
		chainID: "ethereum",
		state: &adapter.EscrowState{
			Address: "0xESCROW",
			Amount:  big.NewInt(10_000),
			Status:  adapter.EscrowStatusFunded,
		},
	}
	signer := &fakeSigner{}
	bcast := &fakeBroadcaster{}

	ex, err := NewSettlementExecutor(NewFeeCalculator(), signer, bcast)
	if err != nil {
		t.Fatalf("NewSettlementExecutor: %v", err)
	}

	res, err := ex.Execute(context.Background(), adapterImpl, "0xESCROW", adapter.FeeOptions{MaintainerBPS: 100})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.TxHash != "0xTXHASH" {
		t.Errorf("TxHash: got %q", res.TxHash)
	}
	if signer.lastFees.MaintainerFee.Int64() != 100 {
		t.Errorf("signer saw MaintainerFee=%d, want 100", signer.lastFees.MaintainerFee.Int64())
	}
	if signer.lastFees.Total.Int64() != 10_000 {
		t.Errorf("signer saw Total=%d", signer.lastFees.Total.Int64())
	}
}

func TestSettlementExecutor_RejectsUnfundedEscrow(t *testing.T) {
	t.Parallel()
	adapterImpl := &fakeAdapter{
		chainID: "ethereum",
		state: &adapter.EscrowState{
			Amount: big.NewInt(1000),
			Status: adapter.EscrowStatusPending,
		},
	}
	ex, _ := NewSettlementExecutor(NewFeeCalculator(), &fakeSigner{}, &fakeBroadcaster{})
	_, err := ex.Execute(context.Background(), adapterImpl, "0xE", adapter.FeeOptions{MaintainerBPS: 100})
	if err == nil {
		t.Fatal("expected error for unfunded escrow")
	}
}

func TestSettlementExecutor_PropagatesSignerError(t *testing.T) {
	t.Parallel()
	adapterImpl := &fakeAdapter{
		chainID: "ethereum",
		state: &adapter.EscrowState{
			Amount: big.NewInt(1000),
			Status: adapter.EscrowStatusFunded,
		},
	}
	ex, _ := NewSettlementExecutor(NewFeeCalculator(), &fakeSigner{err: errors.New("refuse")}, &fakeBroadcaster{})
	_, err := ex.Execute(context.Background(), adapterImpl, "0xE", adapter.FeeOptions{MaintainerBPS: 100})
	if err == nil {
		t.Fatal("expected signer error to propagate")
	}
}

func TestNewSettlementExecutor_NilArgs(t *testing.T) {
	t.Parallel()
	if _, err := NewSettlementExecutor(nil, &fakeSigner{}, &fakeBroadcaster{}); err == nil {
		t.Error("expected error for nil calculator")
	}
	if _, err := NewSettlementExecutor(NewFeeCalculator(), nil, &fakeBroadcaster{}); err == nil {
		t.Error("expected error for nil signer")
	}
	if _, err := NewSettlementExecutor(NewFeeCalculator(), &fakeSigner{}, nil); err == nil {
		t.Error("expected error for nil broadcaster")
	}
}

// fakeEarningRecorder captures Record calls for assertions.
type fakeEarningRecorder struct {
	calls []earningRecordCall
	err   error
}

type earningRecordCall struct {
	orderID   string
	chainID   string
	currency  string
	at        time.Time
	breakdown adapter.FeeBreakdown
}

func (f *fakeEarningRecorder) Record(_ context.Context, orderID, chainID, currency string, at time.Time, breakdown adapter.FeeBreakdown) error {
	f.calls = append(f.calls, earningRecordCall{
		orderID:   orderID,
		chainID:   chainID,
		currency:  currency,
		at:        at,
		breakdown: breakdown,
	})
	return f.err
}

func TestSettlementExecutor_CallsEarningRecorder(t *testing.T) {
	t.Parallel()

	adapterImpl := &fakeAdapter{
		chainID: "ethereum",
		state: &adapter.EscrowState{
			Address: "0xESCROW",
			Amount:  big.NewInt(10_000),
			Status:  adapter.EscrowStatusFunded,
		},
	}
	ex, err := NewSettlementExecutor(NewFeeCalculator(), &fakeSigner{}, &fakeBroadcaster{})
	if err != nil {
		t.Fatalf("NewSettlementExecutor: %v", err)
	}

	// Install an attester lookup so fees are split per witness — the recorder
	// should see a non-empty WitnessFees map.
	ex.SetBalanceAttesterLookup(func(string) []string {
		return []string{"aaaa", "bbbb"}
	})
	recorder := &fakeEarningRecorder{}
	ex.SetEarningRecorder(recorder)

	opts := adapter.FeeOptions{
		MaintainerBPS: 100,
		HasWitness:    true,
		WitnessBPS:    50,
	}
	if _, err := ex.Execute(context.Background(), adapterImpl, "0xESCROW", opts); err != nil {
		t.Fatalf("Execute: %v", err)
	}

	if len(recorder.calls) != 1 {
		t.Fatalf("expected 1 Record call, got %d", len(recorder.calls))
	}
	call := recorder.calls[0]
	if call.orderID != "0xESCROW" {
		t.Errorf("orderID: got %q, want %q", call.orderID, "0xESCROW")
	}
	if call.chainID != "ethereum" {
		t.Errorf("chainID: got %q", call.chainID)
	}
	if call.currency != "USDC" {
		t.Errorf("currency: got %q", call.currency)
	}
	// WitnessFee total = 10000 * 50 / 10000 = 50, split across two attesters (25+25).
	wf := call.breakdown.WitnessFees
	if len(wf) != 2 {
		t.Fatalf("WitnessFees: got %d entries, want 2", len(wf))
	}
	sum := new(big.Int)
	for _, v := range wf {
		sum.Add(sum, v)
	}
	if sum.Int64() != 50 {
		t.Errorf("witness fees sum: got %d, want 50", sum.Int64())
	}
	if call.breakdown.Total.Int64() != 10_000 {
		t.Errorf("Total: got %d, want 10_000", call.breakdown.Total.Int64())
	}
}

func TestSettlementExecutor_DefaultRecorderIsNoop(t *testing.T) {
	t.Parallel()
	// With no recorder installed, a happy-path settlement should still succeed.
	adapterImpl := &fakeAdapter{
		chainID: "ethereum",
		state: &adapter.EscrowState{
			Address: "0xESCROW",
			Amount:  big.NewInt(10_000),
			Status:  adapter.EscrowStatusFunded,
		},
	}
	ex, err := NewSettlementExecutor(NewFeeCalculator(), &fakeSigner{}, &fakeBroadcaster{})
	if err != nil {
		t.Fatalf("NewSettlementExecutor: %v", err)
	}
	// Explicitly pass nil to exercise the nil-guard in SetEarningRecorder.
	ex.SetEarningRecorder(nil)

	if _, err := ex.Execute(context.Background(), adapterImpl, "0xESCROW", adapter.FeeOptions{MaintainerBPS: 100}); err != nil {
		t.Fatalf("Execute: %v", err)
	}
}

func TestSettlementExecutor_RecorderErrorIsNonFatal(t *testing.T) {
	t.Parallel()
	adapterImpl := &fakeAdapter{
		chainID: "ethereum",
		state: &adapter.EscrowState{
			Address: "0xESCROW",
			Amount:  big.NewInt(10_000),
			Status:  adapter.EscrowStatusFunded,
		},
	}
	ex, err := NewSettlementExecutor(NewFeeCalculator(), &fakeSigner{}, &fakeBroadcaster{})
	if err != nil {
		t.Fatalf("NewSettlementExecutor: %v", err)
	}
	ex.SetEarningRecorder(&fakeEarningRecorder{err: errors.New("disk full")})

	res, err := ex.Execute(context.Background(), adapterImpl, "0xESCROW", adapter.FeeOptions{MaintainerBPS: 100})
	if err != nil {
		t.Fatalf("settlement should succeed despite recorder error: %v", err)
	}
	if res == nil || res.TxHash == "" {
		t.Fatal("expected non-empty settlement result")
	}
}

func TestSettlementExecutor_RulingPercentsValidation(t *testing.T) {
	t.Parallel()
	adapterImpl := &fakeAdapter{
		chainID: "ethereum",
		state: &adapter.EscrowState{
			Amount: big.NewInt(1000),
			Status: adapter.EscrowStatusDisputed,
		},
	}
	ex, _ := NewSettlementExecutor(NewFeeCalculator(), &fakeSigner{}, &fakeBroadcaster{})
	// Percents don't sum to 100 — should reject.
	_, err := ex.ExecuteWithRuling(context.Background(), adapterImpl, "0xE",
		adapter.Ruling{BuyerPercent: 30, SellerPercent: 50},
		adapter.FeeOptions{MaintainerBPS: 100})
	if err == nil {
		t.Fatal("expected ruling percent error")
	}
}
