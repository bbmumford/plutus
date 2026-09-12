/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package escrow

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"math/big"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeAdapter implements CurrencyAdapter with recordable, programmable behavior.
type fakeAdapter struct {
	chainID  string
	currency string

	mu    sync.Mutex
	state OnChainEscrowState

	constructCalls int32
	releaseCalls   int32
	disputeCalls   int32
	settleCalls    int32
	refundCalls    int32
	stateCalls     int32

	// failure injection
	failConstruct bool
	failRelease   bool
}

func newFakeAdapter(chainID, currency string) *fakeAdapter {
	return &fakeAdapter{
		chainID:  chainID,
		currency: currency,
		state: OnChainEscrowState{
			Buyer:  "0xBuyer",
			Seller: "0xSeller",
			Amount: big.NewInt(1000),
		},
	}
}

func (a *fakeAdapter) ChainID() string  { return a.chainID }
func (a *fakeAdapter) Currency() string { return a.currency }

func (a *fakeAdapter) ConstructEscrow(params EscrowConstructParams) (*UnsignedTx, error) {
	atomic.AddInt32(&a.constructCalls, 1)
	if a.failConstruct {
		return nil, errors.New("fakeAdapter: construct failed")
	}
	a.mu.Lock()
	a.state.Buyer = params.Buyer
	a.state.Seller = params.Seller
	a.state.Arbitrator = params.Arbitrator
	a.state.Amount = params.Amount
	a.state.TimeoutBlock = params.TimeoutBlocks
	a.state.Funded = true // simulate fund-on-construct for simplicity
	a.mu.Unlock()
	return &UnsignedTx{
		ChainID: a.chainID,
		To:      "",
		Data:    []byte("construct-tx-data"),
		Value:   params.Amount,
	}, nil
}

func (a *fakeAdapter) ReleaseEscrow(escrowAddr string, params ReleaseParams) (*UnsignedTx, error) {
	atomic.AddInt32(&a.releaseCalls, 1)
	if a.failRelease {
		return nil, errors.New("fakeAdapter: release failed")
	}
	a.mu.Lock()
	a.state.Released = true
	a.mu.Unlock()
	return &UnsignedTx{
		ChainID: a.chainID,
		To:      escrowAddr,
		Data:    []byte("release-tx-data"),
		Value:   big.NewInt(0),
	}, nil
}

func (a *fakeAdapter) DisputeEscrow(escrowAddr string, params DisputeParams) (*UnsignedTx, error) {
	atomic.AddInt32(&a.disputeCalls, 1)
	a.mu.Lock()
	a.state.Disputed = true
	a.mu.Unlock()
	return &UnsignedTx{
		ChainID: a.chainID,
		To:      escrowAddr,
		Data:    append([]byte("dispute-tx-data"), params.EvidenceHash...),
	}, nil
}

func (a *fakeAdapter) SettleWithRuling(escrowAddr string, ruling Ruling) (*UnsignedTx, error) {
	atomic.AddInt32(&a.settleCalls, 1)
	a.mu.Lock()
	a.state.Settled = true
	a.mu.Unlock()
	return &UnsignedTx{
		ChainID: a.chainID,
		To:      escrowAddr,
		Data:    []byte("settle-tx-data"),
	}, nil
}

func (a *fakeAdapter) RefundAfterTimeout(escrowAddr string) (*UnsignedTx, error) {
	atomic.AddInt32(&a.refundCalls, 1)
	return &UnsignedTx{
		ChainID: a.chainID,
		To:      escrowAddr,
		Data:    []byte("refund-tx-data"),
	}, nil
}

func (a *fakeAdapter) EscrowState(escrowAddr string) (*OnChainEscrowState, error) {
	atomic.AddInt32(&a.stateCalls, 1)
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.state
	return &s, nil
}

// fakeAdapterResolver returns a registered adapter by (chainID, currency).
type fakeAdapterResolver struct {
	adapters map[string]*fakeAdapter // key = chainID|currency
}

func newFakeAdapterResolver(adapters ...*fakeAdapter) *fakeAdapterResolver {
	r := &fakeAdapterResolver{adapters: make(map[string]*fakeAdapter)}
	for _, a := range adapters {
		r.adapters[a.chainID+"|"+a.currency] = a
	}
	return r
}

func (r *fakeAdapterResolver) Resolve(chainID, currency string) (CurrencyAdapter, error) {
	a, ok := r.adapters[chainID+"|"+currency]
	if !ok {
		return nil, errors.New("fakeResolver: no adapter")
	}
	return a, nil
}

// fakeWallet records signing calls and returns deterministic signatures.
type fakeWallet struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey

	mu              sync.Mutex
	fundingCalls    int
	settlementCalls int
	disputeCalls    int
	lastFees        FeeBreakdown

	failSettlement bool
}

func newFakeWallet() *fakeWallet {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &fakeWallet{pub: pub, priv: priv}
}

func (w *fakeWallet) PublicKey() ed25519.PublicKey { return w.pub }
func (w *fakeWallet) ChainAddress(chainID string) (string, error) {
	return "0xFakeAddr-" + chainID, nil
}
func (w *fakeWallet) SignEscrowFunding(tx *UnsignedTx) ([]byte, error) {
	w.mu.Lock()
	w.fundingCalls++
	w.mu.Unlock()
	return ed25519.Sign(w.priv, tx.Data), nil
}
func (w *fakeWallet) SignSettlement(tx *UnsignedTx, expectedFees FeeBreakdown) ([]byte, error) {
	w.mu.Lock()
	w.settlementCalls++
	w.lastFees = expectedFees
	w.mu.Unlock()
	if w.failSettlement {
		return nil, errors.New("fakeWallet: settlement signing rejected")
	}
	return ed25519.Sign(w.priv, tx.Data), nil
}
func (w *fakeWallet) SignDispute(tx *UnsignedTx) ([]byte, error) {
	w.mu.Lock()
	w.disputeCalls++
	w.mu.Unlock()
	return ed25519.Sign(w.priv, tx.Data), nil
}

// fakeMeshVerifier lets tests dictate confirmation status and snapshot state.
type fakeMeshVerifier struct {
	mu sync.Mutex

	// programmable confirmation status (default true)
	confirmed    bool
	confirmErr   error
	broadcastErr error
	attestErr    error

	// programmable snapshot. If nil, a default funded snapshot is returned.
	snapshot *EscrowSnapshot

	txHashes       []string // canned broadcast tx hashes, consumed in order
	broadcastCalls int
	attestCalls    int
	confirmCalls   int
}

func newFakeMeshVerifier() *fakeMeshVerifier {
	return &fakeMeshVerifier{
		confirmed: true,
		txHashes:  []string{"0xFakeTxHash-1", "0xFakeTxHash-2", "0xFakeTxHash-3"},
	}
}

func (v *fakeMeshVerifier) IsConfirmed(ctx context.Context, chainID, txHash string) (bool, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.confirmCalls++
	if v.confirmErr != nil {
		return false, v.confirmErr
	}
	return v.confirmed, nil
}

func (v *fakeMeshVerifier) AttestEscrowState(ctx context.Context, chainID, addr string) (*EscrowSnapshot, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.attestCalls++
	if v.attestErr != nil {
		return nil, v.attestErr
	}
	if v.snapshot != nil {
		return v.snapshot, nil
	}
	return &EscrowSnapshot{
		ChainID:      chainID,
		EscrowAddr:   addr,
		State:        OnChainEscrowState{Funded: true, Amount: big.NewInt(1000), Buyer: "0xBuyer", Seller: "0xSeller"},
		AttestedAt:   time.Now(),
		WitnessCount: 4,
		Quorum:       true,
	}, nil
}

func (v *fakeMeshVerifier) BroadcastTx(ctx context.Context, chainID string, signedTx []byte) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.broadcastCalls++
	if v.broadcastErr != nil {
		return "", v.broadcastErr
	}
	if len(v.txHashes) == 0 {
		return "0xFakeDefaultTx", nil
	}
	h := v.txHashes[0]
	v.txHashes = v.txHashes[1:]
	return h, nil
}

// fakeFeeCalc returns a deterministic FeeBreakdown computed from MaintainerBPS.
type fakeFeeCalc struct {
	calls int
	mu    sync.Mutex
	err   error
}

func (f *fakeFeeCalc) Calculate(amount *big.Int, opts FeeOptions) (FeeBreakdown, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.err != nil {
		return FeeBreakdown{}, f.err
	}
	maintainer := new(big.Int).Mul(amount, big.NewInt(int64(opts.MaintainerBPS)))
	maintainer.Div(maintainer, big.NewInt(10000))
	return FeeBreakdown{
		MaintainerFee:      maintainer,
		ServiceProviderFee: big.NewInt(0),
		ArbitratorFee:      big.NewInt(0),
		WitnessFee:         big.NewInt(0),
		SellerProceeds:     new(big.Int).Sub(amount, maintainer),
		Total:              amount,
	}, nil
}

// testHarness wires together a complete, fake-backed EscrowManager.
type testHarness struct {
	adapter  *fakeAdapter
	wallet   *fakeWallet
	verifier *fakeMeshVerifier
	feeCalc  *fakeFeeCalc
	manager  *EscrowManager
}

func newTestHarness() *testHarness {
	adapter := newFakeAdapter("ethereum", "USDC")
	resolver := newFakeAdapterResolver(adapter)
	wallet := newFakeWallet()
	verifier := newFakeMeshVerifier()
	feeCalc := &fakeFeeCalc{}
	manager := NewEscrowManager(resolver, wallet, verifier, WithFeeCalculator(feeCalc))
	return &testHarness{
		adapter:  adapter,
		wallet:   wallet,
		verifier: verifier,
		feeCalc:  feeCalc,
		manager:  manager,
	}
}

func defaultFundParams() FundParams {
	return FundParams{
		Amount:        big.NewInt(1000),
		Buyer:         "0xBuyer",
		Seller:        "0xSeller",
		Currency:      "USDC",
		ChainID:       "ethereum",
		Arbitrator:    "0xArb",
		TimeoutBlocks: 100,
		ReceiptHashes: [][]byte{[]byte("receipt-1")},
		WitnessHashes: [][]byte{[]byte("witness-1")},
	}
}

// ---------- Tests ----------

func TestFund_Success(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	ctx := context.Background()

	inst, err := h.manager.Fund(ctx, defaultFundParams())
	if err != nil {
		t.Fatalf("Fund: %v", err)
	}
	if inst.Address == "" {
		t.Error("instance address must not be empty")
	}
	if inst.ChainID != "ethereum" {
		t.Errorf("chainID: got %s, want ethereum", inst.ChainID)
	}
	if inst.TxHash == "" {
		t.Error("tx hash must not be empty")
	}
	if atomic.LoadInt32(&h.adapter.constructCalls) != 1 {
		t.Error("expected ConstructEscrow called once")
	}
	h.wallet.mu.Lock()
	if h.wallet.fundingCalls != 1 {
		t.Errorf("funding calls: got %d, want 1", h.wallet.fundingCalls)
	}
	h.wallet.mu.Unlock()
	if h.verifier.broadcastCalls != 1 {
		t.Errorf("broadcast calls: got %d, want 1", h.verifier.broadcastCalls)
	}
}

func TestFund_Validation(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	ctx := context.Background()

	cases := map[string]FundParams{
		"zero amount":   {Amount: big.NewInt(0), Buyer: "B", Seller: "S", Currency: "USDC", ChainID: "ethereum", TimeoutBlocks: 10},
		"nil amount":    {Amount: nil, Buyer: "B", Seller: "S", Currency: "USDC", ChainID: "ethereum", TimeoutBlocks: 10},
		"empty buyer":   {Amount: big.NewInt(1), Buyer: "", Seller: "S", Currency: "USDC", ChainID: "ethereum", TimeoutBlocks: 10},
		"empty seller":  {Amount: big.NewInt(1), Buyer: "B", Seller: "", Currency: "USDC", ChainID: "ethereum", TimeoutBlocks: 10},
		"empty currency": {Amount: big.NewInt(1), Buyer: "B", Seller: "S", Currency: "", ChainID: "ethereum", TimeoutBlocks: 10},
		"empty chain":   {Amount: big.NewInt(1), Buyer: "B", Seller: "S", Currency: "USDC", ChainID: "", TimeoutBlocks: 10},
		"zero timeout":  {Amount: big.NewInt(1), Buyer: "B", Seller: "S", Currency: "USDC", ChainID: "ethereum", TimeoutBlocks: 0},
	}
	for name, p := range cases {
		if _, err := h.manager.Fund(ctx, p); err == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestFund_AdapterMissing(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	params := defaultFundParams()
	params.Currency = "UNKNOWN"
	if _, err := h.manager.Fund(context.Background(), params); err == nil {
		t.Error("expected missing adapter error")
	}
}

func TestFund_AdapterConstructError(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	h.adapter.failConstruct = true
	if _, err := h.manager.Fund(context.Background(), defaultFundParams()); err == nil {
		t.Error("expected construct error")
	}
}

func TestFund_BroadcastError(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	h.verifier.broadcastErr = errors.New("broadcast failed")
	if _, err := h.manager.Fund(context.Background(), defaultFundParams()); err == nil {
		t.Error("expected broadcast error")
	}
}

func TestFund_NotConfirmed(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	h.verifier.confirmed = false
	if _, err := h.manager.Fund(context.Background(), defaultFundParams()); err == nil {
		t.Error("expected not-confirmed error")
	}
}

func TestRelease_Success(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	ctx := context.Background()
	inst, err := h.manager.Fund(ctx, defaultFundParams())
	if err != nil {
		t.Fatalf("Fund: %v", err)
	}

	txHash, err := h.manager.Release(ctx, inst.Address, ReleaseParams{
		ReceiptHashes: [][]byte{[]byte("r1")},
		Memo:          "thanks",
	})
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if txHash == "" {
		t.Error("release tx hash empty")
	}
	if atomic.LoadInt32(&h.adapter.releaseCalls) != 1 {
		t.Error("expected ReleaseEscrow called once")
	}
	h.wallet.mu.Lock()
	if h.wallet.settlementCalls != 1 {
		t.Errorf("settlement calls: got %d, want 1", h.wallet.settlementCalls)
	}
	// Fee calculator must have been invoked with a positive maintainer fee.
	if h.wallet.lastFees.MaintainerFee == nil || h.wallet.lastFees.MaintainerFee.Sign() <= 0 {
		t.Errorf("expected positive maintainer fee, got %v", h.wallet.lastFees.MaintainerFee)
	}
	h.wallet.mu.Unlock()
}

func TestRelease_UnknownAddress(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	if _, err := h.manager.Release(context.Background(), "0xUNKNOWN", ReleaseParams{}); err == nil {
		t.Error("expected unknown address error")
	}
}

func TestRelease_FeeCalcNotConfigured(t *testing.T) {
	t.Parallel()
	// Build a manager without fee calculator — Release must refuse.
	adapter := newFakeAdapter("ethereum", "USDC")
	resolver := newFakeAdapterResolver(adapter)
	wallet := newFakeWallet()
	verifier := newFakeMeshVerifier()
	mgr := NewEscrowManager(resolver, wallet, verifier) // no fee calc
	inst, err := mgr.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatalf("Fund: %v", err)
	}
	if _, err := mgr.Release(context.Background(), inst.Address, ReleaseParams{}); err == nil {
		t.Error("expected fee-calc-missing error")
	}
}

func TestRelease_FeeCalcError(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	h.feeCalc.err = errors.New("fee calc broken")
	if _, err := h.manager.Release(context.Background(), inst.Address, ReleaseParams{}); err == nil {
		t.Error("expected fee calc error")
	}
}

func TestRelease_WalletRejectsSettlement(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	h.wallet.failSettlement = true
	if _, err := h.manager.Release(context.Background(), inst.Address, ReleaseParams{}); err == nil {
		t.Error("expected wallet rejection error")
	}
}

func TestRelease_DisputedEscrowRejected(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	h.verifier.snapshot = &EscrowSnapshot{
		ChainID:    "ethereum",
		EscrowAddr: inst.Address,
		State:      OnChainEscrowState{Funded: true, Disputed: true, Amount: big.NewInt(1000)},
		Quorum:     true,
	}
	if _, err := h.manager.Release(context.Background(), inst.Address, ReleaseParams{}); err == nil {
		t.Error("expected disputed rejection")
	}
}

func TestRelease_NoQuorumRejected(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	h.verifier.snapshot = &EscrowSnapshot{
		ChainID:    "ethereum",
		EscrowAddr: inst.Address,
		State:      OnChainEscrowState{Funded: true, Amount: big.NewInt(1000)},
		Quorum:     false,
	}
	if _, err := h.manager.Release(context.Background(), inst.Address, ReleaseParams{}); err == nil {
		t.Error("expected quorum rejection")
	}
}

func TestDispute_Success(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	txHash, err := h.manager.Dispute(context.Background(), inst.Address, DisputeParams{
		Evidence: []byte("evidence bytes"),
	})
	if err != nil {
		t.Fatalf("Dispute: %v", err)
	}
	if txHash == "" {
		t.Error("dispute tx hash empty")
	}
	if atomic.LoadInt32(&h.adapter.disputeCalls) != 1 {
		t.Error("expected DisputeEscrow called")
	}
	h.wallet.mu.Lock()
	if h.wallet.disputeCalls != 1 {
		t.Errorf("wallet dispute calls: got %d, want 1", h.wallet.disputeCalls)
	}
	h.wallet.mu.Unlock()
}

func TestDispute_PreHashedEvidence(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Dispute(context.Background(), inst.Address, DisputeParams{
		EvidenceHash: []byte("pre-hashed-evidence-32-bytes....."),
	}); err != nil {
		t.Fatalf("Dispute with pre-hashed: %v", err)
	}
}

func TestDispute_NoEvidence(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.manager.Dispute(context.Background(), inst.Address, DisputeParams{}); err == nil {
		t.Error("expected evidence-required error")
	}
}

func TestDispute_AlreadyDisputed(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	h.verifier.snapshot = &EscrowSnapshot{
		State:  OnChainEscrowState{Funded: true, Disputed: true, Amount: big.NewInt(1000)},
		Quorum: true,
	}
	if _, err := h.manager.Dispute(context.Background(), inst.Address, DisputeParams{Evidence: []byte("e")}); err == nil {
		t.Error("expected already-disputed error")
	}
}

func TestSettleWithRuling_Success(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	// Move escrow to disputed state.
	h.verifier.snapshot = &EscrowSnapshot{
		ChainID:    "ethereum",
		EscrowAddr: inst.Address,
		State:      OnChainEscrowState{Funded: true, Disputed: true, Amount: big.NewInt(1000)},
		Quorum:     true,
	}
	ruling := Ruling{
		Outcome:       "seller-wins",
		BuyerPercent:  30,
		SellerPercent: 70,
		ArbitratorSig: []byte("arb-sig"),
	}
	txHash, err := h.manager.SettleWithRuling(context.Background(), inst.Address, ruling)
	if err != nil {
		t.Fatalf("SettleWithRuling: %v", err)
	}
	if txHash == "" {
		t.Error("settle tx hash empty")
	}
	if atomic.LoadInt32(&h.adapter.settleCalls) != 1 {
		t.Error("expected SettleWithRuling called once")
	}
}

func TestSettleWithRuling_InvalidRuling(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	h.verifier.snapshot = &EscrowSnapshot{
		State:  OnChainEscrowState{Funded: true, Disputed: true, Amount: big.NewInt(1000)},
		Quorum: true,
	}
	// Percentages don't sum to 100.
	bad := Ruling{BuyerPercent: 40, SellerPercent: 40, ArbitratorSig: []byte("s")}
	if _, err := h.manager.SettleWithRuling(context.Background(), inst.Address, bad); err == nil {
		t.Error("expected invalid percentages error")
	}
	// Missing arbitrator signature.
	noSig := Ruling{BuyerPercent: 50, SellerPercent: 50}
	if _, err := h.manager.SettleWithRuling(context.Background(), inst.Address, noSig); err == nil {
		t.Error("expected missing-sig error")
	}
}

func TestSettleWithRuling_NotDisputed(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	// snapshot defaults to funded but not disputed.
	ruling := Ruling{BuyerPercent: 50, SellerPercent: 50, ArbitratorSig: []byte("s")}
	if _, err := h.manager.SettleWithRuling(context.Background(), inst.Address, ruling); err == nil {
		t.Error("expected can-only-settle-disputed error")
	}
}

func TestRefundAfterTimeout_Success(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	h.verifier.snapshot = &EscrowSnapshot{
		State:  OnChainEscrowState{Funded: true, TimedOut: true, Amount: big.NewInt(1000)},
		Quorum: true,
	}
	txHash, err := h.manager.RefundAfterTimeout(context.Background(), inst.Address)
	if err != nil {
		t.Fatalf("RefundAfterTimeout: %v", err)
	}
	if txHash == "" {
		t.Error("refund tx hash empty")
	}
	if atomic.LoadInt32(&h.adapter.refundCalls) != 1 {
		t.Error("expected RefundAfterTimeout called once")
	}
}

func TestRefundAfterTimeout_NotTimedOut(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	// Default snapshot shows funded but not timed-out; timeout block in future.
	h.verifier.snapshot = &EscrowSnapshot{
		State:  OnChainEscrowState{Funded: true, Amount: big.NewInt(1000), CurrentBlock: 10, TimeoutBlock: 100},
		Quorum: true,
	}
	if _, err := h.manager.RefundAfterTimeout(context.Background(), inst.Address); err == nil {
		t.Error("expected not-timed-out error")
	}
}

func TestRefundAfterTimeout_UnknownAddress(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	if _, err := h.manager.RefundAfterTimeout(context.Background(), "0xNope"); err == nil {
		t.Error("expected unknown address error")
	}
}

func TestState_Lookup(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	st, err := h.manager.State(context.Background(), inst.Address)
	if err != nil {
		t.Fatalf("State: %v", err)
	}
	if st.Status != StatusFunded {
		t.Errorf("state status: got %s, want funded", st.Status)
	}
}

func TestState_UnknownAddress(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	if _, err := h.manager.State(context.Background(), "0xUnknown"); err == nil {
		t.Error("expected unknown address error")
	}
}

func TestState_AttestError(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	h.verifier.attestErr = errors.New("attest failed")
	if _, err := h.manager.State(context.Background(), inst.Address); err == nil {
		t.Error("expected attest error")
	}
}

func TestConcurrent_ReleaseAndDispute_Serializes(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = h.manager.Release(context.Background(), inst.Address, ReleaseParams{
			ReceiptHashes: [][]byte{[]byte("r")},
		})
	}()
	go func() {
		defer wg.Done()
		_, _ = h.manager.Dispute(context.Background(), inst.Address, DisputeParams{
			Evidence: []byte("e"),
		})
	}()
	wg.Wait()
	// Whichever finished first should have been allowed, but the other path
	// should also have run its orchestration without panicking under -race.
	if atomic.LoadInt32(&h.adapter.releaseCalls)+atomic.LoadInt32(&h.adapter.disputeCalls) < 1 {
		t.Error("expected at least one adapter call under concurrency")
	}
}

func TestWatch_EmitsInitialEvents(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	inst, err := h.manager.Fund(context.Background(), defaultFundParams())
	if err != nil {
		t.Fatal(err)
	}
	// Pre-set a disputed snapshot so watcher fires disputed event on first poll.
	h.verifier.snapshot = &EscrowSnapshot{
		State:  OnChainEscrowState{Funded: true, Disputed: true, Amount: big.NewInt(1000)},
		Quorum: true,
	}

	events := make(chan EscrowEvent, 10)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	cancelWatch := h.manager.Watch(ctx, inst.Address, func(e EscrowEvent) {
		events <- e
	})
	defer cancelWatch()

	// Wait briefly for initial poll.
	deadline := time.After(400 * time.Millisecond)
	var got []string
	for len(got) < 2 {
		select {
		case e := <-events:
			got = append(got, e.Type)
		case <-deadline:
			goto done
		}
	}
done:
	// We expect at least the Funded and Disputed events on the initial poll.
	hasFunded := false
	hasDisputed := false
	for _, tName := range got {
		if tName == EventFunded {
			hasFunded = true
		}
		if tName == EventDisputed {
			hasDisputed = true
		}
	}
	if !hasFunded || !hasDisputed {
		t.Errorf("watcher events: got %v, want at least funded+disputed", got)
	}
}

func TestWatch_UnknownAddressEmitsError(t *testing.T) {
	t.Parallel()
	h := newTestHarness()
	events := make(chan EscrowEvent, 4)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cancelWatch := h.manager.Watch(ctx, "0xUnknown", func(e EscrowEvent) {
		events <- e
	})
	defer cancelWatch()
	select {
	case e := <-events:
		if e.Type != EventError {
			t.Errorf("expected error event, got %q", e.Type)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("timeout waiting for error event")
	}
}

func TestHashEvidence_Deterministic(t *testing.T) {
	t.Parallel()
	h1 := hashEvidence([]byte("same"))
	h2 := hashEvidence([]byte("same"))
	if string(h1) != string(h2) {
		t.Error("hashEvidence must be deterministic")
	}
	if string(hashEvidence([]byte("a"))) == string(hashEvidence([]byte("b"))) {
		t.Error("different inputs must produce different hashes")
	}
}
