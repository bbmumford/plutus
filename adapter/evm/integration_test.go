/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package evm

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"

	"github.com/bbmumford/plutus/adapter"
)

// fakeTransport implements MeshTransport by returning canned JSON responses
// based on the RPC method. Individual methods can be overridden via the
// responses map; unknown methods return a generic stub hex value.
type fakeTransport struct {
	mu        sync.Mutex
	calls     []fakeCall
	responses map[string]json.RawMessage
	errFor    map[string]error
	// blockNumber returned by eth_blockNumber (defaults to 0x64 = 100).
	blockNumber string
}

type fakeCall struct {
	ChainID string
	Method  string
	Params  json.RawMessage
}

func newFakeTransport() *fakeTransport {
	return &fakeTransport{
		responses:   make(map[string]json.RawMessage),
		errFor:      make(map[string]error),
		blockNumber: "\"0x64\"",
	}
}

func (f *fakeTransport) SendRPC(ctx context.Context, chainID, method string, params []byte) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls = append(f.calls, fakeCall{ChainID: chainID, Method: method, Params: params})
	if err, ok := f.errFor[method]; ok {
		return nil, err
	}
	if r, ok := f.responses[method]; ok {
		return r, nil
	}

	// Defaults per method for reasonable happy paths.
	switch method {
	case "eth_blockNumber":
		return json.RawMessage(f.blockNumber), nil
	case "eth_estimateGas":
		return json.RawMessage(`"0x5208"`), nil // 21000
	case "eth_gasPrice":
		return json.RawMessage(`"0x3b9aca00"`), nil // 1 gwei
	case "eth_maxPriorityFeePerGas":
		return json.RawMessage(`"0x59682f00"`), nil // 1.5 gwei
	case "eth_getBlockByNumber":
		return json.RawMessage(`{"baseFeePerGas":"0x4a817c800"}`), nil // 20 gwei
	case "eth_getTransactionCount":
		return json.RawMessage(`"0x1"`), nil
	case "eth_getBalance":
		return json.RawMessage(`"0x56bc75e2d63100000"`), nil // 100 ETH in wei
	case "eth_call":
		// Default: 32-byte word of zeros for generic queries. Specific tests
		// override this via f.responses.
		zero := strings.Repeat("0", 64)
		return json.RawMessage("\"0x" + zero + "\""), nil
	case "eth_sendRawTransaction":
		return json.RawMessage(`"0xTXHASH123"`), nil
	case "eth_getTransactionReceipt":
		return json.RawMessage(`{"status":"0x1","blockNumber":"0x64","transactionHash":"0xabc"}`), nil
	}
	return nil, fmt.Errorf("fakeTransport: unexpected method %q", method)
}

// pad returns a JSON-wrapped hex string of `n` padded to 32 bytes.
func padHex32(n *big.Int) json.RawMessage {
	b := padUint256(n)
	return json.RawMessage("\"0x" + hex.EncodeToString(b) + "\"")
}

// addrHex returns a JSON-wrapped 32-byte left-padded hex address.
func addrHex(addr string) json.RawMessage {
	b := padAddress(addr)
	return json.RawMessage("\"0x" + hex.EncodeToString(b) + "\"")
}

// --- EVMClient tests ---

func TestNewEVMClient_Validation(t *testing.T) {
	t.Parallel()
	if _, err := NewEVMClient(nil, "ethereum"); err == nil {
		t.Error("expected nil transport error")
	}
	ft := newFakeTransport()
	if _, err := NewEVMClient(ft, ""); err == nil {
		t.Error("expected empty chainID error")
	}
	c, err := NewEVMClient(ft, "ethereum")
	if err != nil {
		t.Fatal(err)
	}
	if c.ChainID() != "ethereum" {
		t.Errorf("ChainID: got %s, want ethereum", c.ChainID())
	}
}

func TestEVMClient_BlockNumber(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	bn, err := c.BlockNumber(context.Background())
	if err != nil {
		t.Fatalf("BlockNumber: %v", err)
	}
	if bn != 0x64 {
		t.Errorf("got %d, want 100", bn)
	}
}

func TestEVMClient_Call_ReturnsDecodedHex(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	ft.responses["eth_call"] = json.RawMessage(`"0xdeadbeef"`)
	got, err := c.Call(context.Background(), "0xTo", []byte{0x01}, "latest")
	if err != nil {
		t.Fatalf("Call: %v", err)
	}
	want, _ := hex.DecodeString("deadbeef")
	if !bytesEq(got, want) {
		t.Errorf("Call result: got %x, want %x", got, want)
	}
}

func TestEVMClient_Call_Validation(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	if _, err := c.Call(context.Background(), "", []byte{0x01}, "latest"); err == nil {
		t.Error("expected empty-to error")
	}
}

func TestEVMClient_GetBalance(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	bal, err := c.GetBalance(context.Background(), "0xA")
	if err != nil {
		t.Fatalf("GetBalance: %v", err)
	}
	if bal.Sign() <= 0 {
		t.Error("expected positive balance")
	}
	if _, err := c.GetBalance(context.Background(), ""); err == nil {
		t.Error("expected empty-address error")
	}
}

func TestEVMClient_GetTransactionCount(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	n, err := c.GetTransactionCount(context.Background(), "0xA")
	if err != nil {
		t.Fatalf("GetTransactionCount: %v", err)
	}
	if n != 1 {
		t.Errorf("nonce: got %d, want 1", n)
	}
	if _, err := c.GetTransactionCount(context.Background(), ""); err == nil {
		t.Error("expected empty address error")
	}
}

func TestEVMClient_SendTx(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	h, err := c.SendTx(context.Background(), "0xabc")
	if err != nil {
		t.Fatalf("SendTx: %v", err)
	}
	if h != "0xTXHASH123" {
		t.Errorf("got %s, want 0xTXHASH123", h)
	}
	// Without 0x prefix: should auto-prepend.
	if _, err := c.SendTx(context.Background(), "abc"); err != nil {
		t.Errorf("should accept no-prefix: %v", err)
	}
	if _, err := c.SendTx(context.Background(), ""); err == nil {
		t.Error("expected empty-tx error")
	}
}

func TestEVMClient_GetTransactionReceipt(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	r, err := c.GetTransactionReceipt(context.Background(), "0xabc")
	if err != nil {
		t.Fatalf("receipt: %v", err)
	}
	if !r.Success() {
		t.Error("expected success")
	}
	// Null receipt.
	ft.responses["eth_getTransactionReceipt"] = json.RawMessage("null")
	r, err = c.GetTransactionReceipt(context.Background(), "0xabc")
	if err != nil {
		t.Fatalf("null receipt: %v", err)
	}
	if r != nil {
		t.Error("null should produce nil receipt")
	}
	if _, err := c.GetTransactionReceipt(context.Background(), ""); err == nil {
		t.Error("expected empty-tx error")
	}
}

func TestEVMClient_EstimateGas(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	n, err := c.EstimateGas(context.Background(), "0xFrom", "0xTo", []byte{0x01}, big.NewInt(100))
	if err != nil {
		t.Fatalf("EstimateGas: %v", err)
	}
	if n != 21000 {
		t.Errorf("got %d, want 21000", n)
	}
}

func TestEVMClient_ErrorPropagation(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	ft.errFor["eth_blockNumber"] = errors.New("rpc down")
	c, _ := NewEVMClient(ft, "ethereum")
	if _, err := c.BlockNumber(context.Background()); err == nil {
		t.Error("expected rpc error to propagate")
	}
}

// --- ERC20 tests ---

func TestERC20_Validation(t *testing.T) {
	t.Parallel()
	if _, err := NewERC20(nil, "0xT"); err == nil {
		t.Error("expected nil client error")
	}
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	if _, err := NewERC20(c, ""); err == nil {
		t.Error("expected empty address")
	}
}

func TestERC20_CalldataEncoding(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")

	if data, err := token.Transfer("0xTo", big.NewInt(100)); err != nil || len(data) != 4+32+32 {
		t.Errorf("Transfer calldata: %v, len=%d", err, len(data))
	}
	if data, err := token.Approve("0xSp", big.NewInt(50)); err != nil || len(data) != 4+32+32 {
		t.Errorf("Approve calldata: %v, len=%d", err, len(data))
	}
	if data, err := token.TransferFrom("0xA", "0xB", big.NewInt(1)); err != nil || len(data) != 4+32+32+32 {
		t.Errorf("TransferFrom calldata: %v, len=%d", err, len(data))
	}
	// Zero/nil amount rejections.
	if _, err := token.Transfer("0xTo", nil); err == nil {
		t.Error("nil amount must be rejected")
	}
	if _, err := token.Transfer("0xTo", big.NewInt(0)); err == nil {
		t.Error("zero amount must be rejected")
	}
	if _, err := token.Transfer("", big.NewInt(1)); err == nil {
		t.Error("empty recipient must be rejected")
	}
	if _, err := token.Approve("", big.NewInt(1)); err == nil {
		t.Error("empty spender must be rejected")
	}
	// Approve with negative amount.
	if _, err := token.Approve("0xSp", big.NewInt(-1)); err == nil {
		t.Error("negative approval must be rejected")
	}
	// Allowance validation.
	if _, err := token.Allowance(context.Background(), "", "0xSp"); err == nil {
		t.Error("empty owner must be rejected")
	}
	// TransferFrom validation.
	if _, err := token.TransferFrom("", "0xB", big.NewInt(1)); err == nil {
		t.Error("empty from must be rejected")
	}
	if _, err := token.TransferFrom("0xA", "0xB", big.NewInt(0)); err == nil {
		t.Error("zero transferFrom amount must be rejected")
	}
}

func TestERC20_BalanceOf(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	ft.responses["eth_call"] = padHex32(big.NewInt(7777))
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	bal, err := token.BalanceOf(context.Background(), "0xOwner")
	if err != nil {
		t.Fatalf("BalanceOf: %v", err)
	}
	if bal.Int64() != 7777 {
		t.Errorf("got %s, want 7777", bal)
	}
	if _, err := token.BalanceOf(context.Background(), ""); err == nil {
		t.Error("expected empty owner error")
	}
}

func TestERC20_Allowance(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	ft.responses["eth_call"] = padHex32(big.NewInt(42))
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	a, err := token.Allowance(context.Background(), "0xOwner", "0xSpender")
	if err != nil {
		t.Fatalf("Allowance: %v", err)
	}
	if a.Int64() != 42 {
		t.Errorf("got %s, want 42", a)
	}
}

func TestERC20_Decimals(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	ft.responses["eth_call"] = padHex32(big.NewInt(6))
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	d, err := token.Decimals(context.Background())
	if err != nil {
		t.Fatalf("Decimals: %v", err)
	}
	if d != 6 {
		t.Errorf("got %d, want 6", d)
	}
}

func TestERC20_TotalSupply(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	ft.responses["eth_call"] = padHex32(big.NewInt(1_000_000))
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	ts, err := token.TotalSupply(context.Background())
	if err != nil {
		t.Fatalf("TotalSupply: %v", err)
	}
	if ts.Int64() != 1_000_000 {
		t.Errorf("got %s, want 1000000", ts)
	}
}

// --- EscrowBinding tests ---

func TestEscrowBinding_Validation(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	if _, err := NewEscrowBinding(nil, token, "0xPRC"); err == nil {
		t.Error("expected nil client error")
	}
	if _, err := NewEscrowBinding(c, nil, "0xPRC"); err == nil {
		t.Error("expected nil token error")
	}
	if _, err := NewEscrowBinding(c, token, ""); err == nil {
		t.Error("expected empty PRC error")
	}
}

func TestEscrowBinding_ConstructEscrow(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	eb, _ := NewEscrowBinding(c, token, "0xPRC")

	tx, err := eb.ConstructEscrow(adapter.EscrowParams{
		Buyer:          "0xB",
		Seller:         "0xS",
		Amount:         big.NewInt(1000),
		PRCAddress:     "0xPRC",
		TimeoutSeconds: 60,
		WitnessHashes:  [][]byte{make([]byte, 32)},
	})
	if err != nil {
		t.Fatalf("ConstructEscrow: %v", err)
	}
	if tx.To != "" {
		t.Error("contract creation: To must be empty")
	}
	if len(tx.Payload) < 11*32 {
		t.Errorf("payload too short: %d", len(tx.Payload))
	}
}

func TestEscrowBinding_ConstructEscrow_Validation(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	eb, _ := NewEscrowBinding(c, token, "0xPRC")

	base := adapter.EscrowParams{
		Buyer:      "0xB",
		Seller:     "0xS",
		Amount:     big.NewInt(1),
		PRCAddress: "0xPRC",
	}
	// Empty buyer.
	p := base
	p.Buyer = ""
	if _, err := eb.ConstructEscrow(p); err == nil {
		t.Error("expected empty buyer")
	}
	// Empty seller.
	p = base
	p.Seller = ""
	if _, err := eb.ConstructEscrow(p); err == nil {
		t.Error("expected empty seller")
	}
	// Nil amount.
	p = base
	p.Amount = nil
	if _, err := eb.ConstructEscrow(p); err == nil {
		t.Error("expected nil amount")
	}
	// Zero amount.
	p = base
	p.Amount = big.NewInt(0)
	if _, err := eb.ConstructEscrow(p); err == nil {
		t.Error("expected zero amount")
	}
	// Empty PRC.
	p = base
	p.PRCAddress = ""
	if _, err := eb.ConstructEscrow(p); err == nil {
		t.Error("expected empty PRC")
	}
}

func TestEscrowBinding_ConstructEscrow_BlockNumberError(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	ft.errFor["eth_blockNumber"] = errors.New("down")
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	eb, _ := NewEscrowBinding(c, token, "0xPRC")
	_, err := eb.ConstructEscrow(adapter.EscrowParams{
		Buyer: "0xB", Seller: "0xS", Amount: big.NewInt(1), PRCAddress: "0xPRC",
	})
	if err == nil {
		t.Error("expected block-number error propagation")
	}
}

func TestEscrowBinding_FundEscrow(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	eb, _ := NewEscrowBinding(c, token, "0xPRC")
	tx, err := eb.FundEscrow("0xEscrow", big.NewInt(1000))
	if err != nil {
		t.Fatalf("FundEscrow: %v", err)
	}
	if tx.To != "0xEscrow" {
		t.Errorf("To: got %s, want 0xEscrow", tx.To)
	}
	if len(tx.Payload) != 4 {
		t.Errorf("payload length: got %d, want 4 (selector only)", len(tx.Payload))
	}
	// Validation.
	if _, err := eb.FundEscrow("", big.NewInt(1)); err == nil {
		t.Error("expected empty escrow")
	}
	if _, err := eb.FundEscrow("0xE", big.NewInt(0)); err == nil {
		t.Error("expected positive amount")
	}
	if _, err := eb.FundEscrow("0xE", nil); err == nil {
		t.Error("expected non-nil amount")
	}
}

func TestEscrowBinding_ReleaseEscrow(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	eb, _ := NewEscrowBinding(c, token, "0xPRC")
	tx, err := eb.ReleaseEscrow("0xEscrow", adapter.ReleaseParams{})
	if err != nil {
		t.Fatalf("ReleaseEscrow: %v", err)
	}
	if tx.To != "0xEscrow" {
		t.Errorf("To: got %s", tx.To)
	}
	if _, err := eb.ReleaseEscrow("", adapter.ReleaseParams{}); err == nil {
		t.Error("expected empty escrow")
	}
}

func TestEscrowBinding_DisputeEscrow(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	eb, _ := NewEscrowBinding(c, token, "0xPRC")
	tx, err := eb.DisputeEscrow("0xEscrow", adapter.DisputeParams{DisputerAddr: "0xDis"})
	if err != nil {
		t.Fatalf("DisputeEscrow: %v", err)
	}
	if len(tx.Payload) != 4+32 {
		t.Errorf("dispute payload len: got %d, want 36", len(tx.Payload))
	}
	if _, err := eb.DisputeEscrow("", adapter.DisputeParams{DisputerAddr: "0xD"}); err == nil {
		t.Error("expected empty escrow")
	}
	if _, err := eb.DisputeEscrow("0xE", adapter.DisputeParams{}); err == nil {
		t.Error("expected empty disputer error")
	}
}

func TestEscrowBinding_SettleWithRuling(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	eb, _ := NewEscrowBinding(c, token, "0xPRC")
	tx, err := eb.SettleWithRuling("0xEscrow", adapter.Ruling{BuyerPercent: 40, SellerPercent: 60})
	if err != nil {
		t.Fatalf("SettleWithRuling: %v", err)
	}
	if len(tx.Payload) != 4+32+32 {
		t.Errorf("settle payload len: got %d, want 68", len(tx.Payload))
	}
	if _, err := eb.SettleWithRuling("", adapter.Ruling{}); err == nil {
		t.Error("expected empty escrow")
	}
	if _, err := eb.SettleWithRuling("0xE", adapter.Ruling{BuyerPercent: 40, SellerPercent: 40}); err == nil {
		t.Error("expected percentage-sum error")
	}
}

func TestEscrowBinding_RefundAfterTimeout(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	eb, _ := NewEscrowBinding(c, token, "0xPRC")
	tx, err := eb.RefundAfterTimeout("0xEscrow")
	if err != nil {
		t.Fatalf("RefundAfterTimeout: %v", err)
	}
	if tx.To != "0xEscrow" {
		t.Errorf("To: got %s", tx.To)
	}
	if _, err := eb.RefundAfterTimeout(""); err == nil {
		t.Error("expected empty escrow")
	}
}

func TestEscrowBinding_EscrowState(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	// Use the test hook to override eth_call responses by selector prefix.
	// Our fakeTransport uses a single eth_call response, so test with default
	// zeroed responses and just assert we get a valid EscrowState back.
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	eb, _ := NewEscrowBinding(c, token, "0xPRC")
	state, err := eb.EscrowState(context.Background(), "0xEscrow")
	if err != nil {
		t.Fatalf("EscrowState: %v", err)
	}
	if state.Address != "0xEscrow" {
		t.Errorf("address: got %s", state.Address)
	}
}

func TestEscrowBinding_EscrowState_Validation(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	eb, _ := NewEscrowBinding(c, token, "0xPRC")
	if _, err := eb.EscrowState(context.Background(), ""); err == nil {
		t.Error("expected empty escrow error")
	}
}

func TestEscrowBinding_ApproveCallData(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	token, _ := NewERC20(c, "0xToken")
	eb, _ := NewEscrowBinding(c, token, "0xPRC")
	data, err := eb.ApproveCallData("0xEscrow", big.NewInt(1000))
	if err != nil {
		t.Fatalf("ApproveCallData: %v", err)
	}
	if len(data) != 4+32+32 {
		t.Errorf("approve length: got %d, want 68", len(data))
	}
}

func TestDecodeEscrowStatus(t *testing.T) {
	t.Parallel()
	cases := map[uint64]adapter.EscrowStatus{
		0: adapter.EscrowStatusPending,
		1: adapter.EscrowStatusFunded,
		2: adapter.EscrowStatusReleased,
		3: adapter.EscrowStatusDisputed,
		4: adapter.EscrowStatusSettled,
		5: adapter.EscrowStatusRefunded,
		6: adapter.EscrowStatusCancelled,
	}
	for n, want := range cases {
		got := decodeEscrowStatus(big.NewInt(int64(n)))
		if got != want {
			t.Errorf("decodeEscrowStatus(%d): got %v, want %v", n, got, want)
		}
	}
	// Nil input defaults to pending.
	if decodeEscrowStatus(nil) != adapter.EscrowStatusPending {
		t.Error("nil should be pending")
	}
	// Unknown value defaults to pending.
	if decodeEscrowStatus(big.NewInt(42)) != adapter.EscrowStatusPending {
		t.Error("unknown should be pending")
	}
}

func TestDynamicArgsSize(t *testing.T) {
	t.Parallel()
	if dynamicArgsSize([][]byte{{1}, {2}}) != 32+2*32 {
		t.Error("byte-array size wrong")
	}
	if dynamicArgsSize([]byte{1, 2, 3}) != 32 {
		t.Error("bytes size wrong")
	}
	if dynamicArgsSize([]byte{}) != 32 {
		t.Error("empty bytes size wrong")
	}
	if dynamicArgsSize(42) != 32 {
		t.Error("unknown type size wrong")
	}
}

// --- GasEstimator ---

func TestGasEstimator_EstimateGas_WithMultiplier(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	g, _ := NewGasEstimator(c)
	g.GasLimitMultiplier = 1.5
	n, err := g.EstimateGas(context.Background(), "0xFrom", "0xTo", []byte{0x1}, nil)
	if err != nil {
		t.Fatalf("EstimateGas: %v", err)
	}
	// 21000 * 1.5 = 31500
	if n != 31500 {
		t.Errorf("got %d, want 31500", n)
	}
}

func TestGasEstimator_SuggestGasPrice_EIP1559(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	g, _ := NewGasEstimator(c)
	s, err := g.SuggestGasPrice(context.Background())
	if err != nil {
		t.Fatalf("SuggestGasPrice: %v", err)
	}
	if !s.EIP1559 {
		t.Error("expected EIP-1559 detection")
	}
	if s.BaseFee == nil || s.BaseFee.Sign() <= 0 {
		t.Error("base fee must be positive")
	}
	if s.MaxFeePerGas == nil || s.MaxFeePerGas.Sign() <= 0 {
		t.Error("maxFee must be positive")
	}
	// Expected: 2*base + priority = 2*20gwei + 1.5gwei = 41.5 gwei
	expected := big.NewInt(41_500_000_000)
	if s.MaxFeePerGas.Cmp(expected) != 0 {
		t.Errorf("maxFee: got %s, want %s", s.MaxFeePerGas, expected)
	}
}

func TestGasEstimator_SuggestGasPrice_CappedAtMax(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	// Huge base fee pushes max above cap.
	ft.responses["eth_getBlockByNumber"] = json.RawMessage(`{"baseFeePerGas":"0x200000000000000000"}`)
	c, _ := NewEVMClient(ft, "ethereum")
	g, _ := NewGasEstimator(c)
	g.MaxGasPrice = big.NewInt(100_000_000_000) // 100 gwei cap
	s, err := g.SuggestGasPrice(context.Background())
	if err != nil {
		t.Fatalf("SuggestGasPrice: %v", err)
	}
	if s.MaxFeePerGas.Cmp(g.MaxGasPrice) > 0 {
		t.Errorf("maxFee %s exceeds cap %s", s.MaxFeePerGas, g.MaxGasPrice)
	}
}

func TestGasEstimator_SuggestGasPrice_LegacyFallback(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	// Block without baseFee -> legacy path.
	ft.responses["eth_getBlockByNumber"] = json.RawMessage(`{}`)
	c, _ := NewEVMClient(ft, "ethereum")
	g, _ := NewGasEstimator(c)
	s, err := g.SuggestGasPrice(context.Background())
	if err != nil {
		t.Fatalf("SuggestGasPrice: %v", err)
	}
	if s.EIP1559 {
		t.Error("expected legacy path (no baseFee)")
	}
	if s.GasPrice == nil || s.GasPrice.Sign() <= 0 {
		t.Error("expected positive legacy gas price")
	}
}

func TestGasEstimator_SuggestGasPrice_LegacyError(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	ft.responses["eth_getBlockByNumber"] = json.RawMessage(`{}`)
	ft.errFor["eth_gasPrice"] = errors.New("rpc down")
	c, _ := NewEVMClient(ft, "ethereum")
	g, _ := NewGasEstimator(c)
	if _, err := g.SuggestGasPrice(context.Background()); err == nil {
		t.Error("expected legacy rpc error")
	}
}

func TestGasEstimator_SuggestWithEstimate(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	c, _ := NewEVMClient(ft, "ethereum")
	g, _ := NewGasEstimator(c)
	s, err := g.SuggestGasPriceWithEstimate(context.Background(), "0xF", "0xT", []byte{0x1}, nil)
	if err != nil {
		t.Fatalf("SuggestGasPriceWithEstimate: %v", err)
	}
	if s.GasLimit == 0 {
		t.Error("gas limit must be set")
	}
}

// --- Chain adapter constructor tests ---

func TestNewEthereumUSDCAdapter(t *testing.T) {
	t.Parallel()
	if _, err := NewEthereumUSDCAdapter(nil, "0xPRC"); err == nil {
		t.Error("nil transport: expected error from client creation")
	}
	ft := newFakeTransport()
	if _, err := NewEthereumUSDCAdapter(ft, ""); err == nil {
		t.Error("empty PRC: expected error")
	}
	a, err := NewEthereumUSDCAdapter(ft, "0xPRC")
	if err != nil {
		t.Fatalf("NewEthereumUSDCAdapter: %v", err)
	}
	if a.ChainID() != "ethereum" || a.Currency() != "USDC" || a.Symbol() != "USDC" {
		t.Errorf("identity: got %s/%s/%s", a.ChainID(), a.Currency(), a.Symbol())
	}
}

func TestNewPolygonUSDCAdapter(t *testing.T) {
	t.Parallel()
	if _, err := NewPolygonUSDCAdapter(newFakeTransport(), ""); err == nil {
		t.Error("empty PRC should fail")
	}
	a, err := NewPolygonUSDCAdapter(newFakeTransport(), "0xPRC")
	if err != nil {
		t.Fatalf("NewPolygonUSDCAdapter: %v", err)
	}
	if a.ChainID() != "polygon" {
		t.Errorf("chainID: got %s, want polygon", a.ChainID())
	}
}

func TestNewArbitrumUSDCAdapter(t *testing.T) {
	t.Parallel()
	if _, err := NewArbitrumUSDCAdapter(newFakeTransport(), ""); err == nil {
		t.Error("empty PRC should fail")
	}
	a, err := NewArbitrumUSDCAdapter(newFakeTransport(), "0xPRC")
	if err != nil {
		t.Fatalf("NewArbitrumUSDCAdapter: %v", err)
	}
	if a.ChainID() != "arbitrum" {
		t.Errorf("chainID: got %s, want arbitrum", a.ChainID())
	}
}

func TestNewBSCBUSDAdapter(t *testing.T) {
	t.Parallel()
	if _, err := NewBSCBUSDAdapter(newFakeTransport(), ""); err == nil {
		t.Error("empty PRC should fail")
	}
	a, err := NewBSCBUSDAdapter(newFakeTransport(), "0xPRC")
	if err != nil {
		t.Fatalf("NewBSCBUSDAdapter: %v", err)
	}
	if a.ChainID() != "bsc" {
		t.Errorf("chainID: got %s", a.ChainID())
	}
}

func TestEthereumUSDCAdapter_LifecycleCalls(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	a, _ := NewEthereumUSDCAdapter(ft, "0xPRC")

	if _, err := a.ConstructEscrow(adapter.EscrowParams{
		Buyer: "0xB", Seller: "0xS", Amount: big.NewInt(1),
	}); err != nil {
		t.Errorf("ConstructEscrow: %v", err)
	}
	if _, err := a.FundEscrow("0xE", big.NewInt(1)); err != nil {
		t.Errorf("FundEscrow: %v", err)
	}
	if _, err := a.ReleaseEscrow("0xE", adapter.ReleaseParams{}); err != nil {
		t.Errorf("ReleaseEscrow: %v", err)
	}
	if _, err := a.DisputeEscrow("0xE", adapter.DisputeParams{DisputerAddr: "0xD"}); err != nil {
		t.Errorf("DisputeEscrow: %v", err)
	}
	if _, err := a.SettleWithRuling("0xE", adapter.Ruling{BuyerPercent: 50, SellerPercent: 50}); err != nil {
		t.Errorf("SettleWithRuling: %v", err)
	}
	if _, err := a.RefundAfterTimeout("0xE"); err != nil {
		t.Errorf("RefundAfterTimeout: %v", err)
	}
	if _, err := a.EscrowState("0xE"); err != nil {
		t.Errorf("EscrowState: %v", err)
	}
	if _, err := a.Balance("0xAddr"); err != nil {
		t.Errorf("Balance: %v", err)
	}
	fees, err := a.CalculateFees(big.NewInt(10000), adapter.FeeOptions{
		MaintainerBPS: 100, HasServiceProvider: true, ServiceProviderBPS: 50,
	})
	if err != nil {
		t.Fatalf("CalculateFees: %v", err)
	}
	if fees.MaintainerFee == nil || fees.MaintainerFee.Int64() != 100 {
		t.Errorf("maintainer fee: got %v, want 100", fees.MaintainerFee)
	}
}

func TestPolygonUSDCAdapter_LifecycleCalls(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	a, _ := NewPolygonUSDCAdapter(ft, "0xPRC")
	if _, err := a.ConstructEscrow(adapter.EscrowParams{Buyer: "0xB", Seller: "0xS", Amount: big.NewInt(1)}); err != nil {
		t.Error(err)
	}
	if _, err := a.FundEscrow("0xE", big.NewInt(1)); err != nil {
		t.Error(err)
	}
	if _, err := a.ReleaseEscrow("0xE", adapter.ReleaseParams{}); err != nil {
		t.Error(err)
	}
	if _, err := a.DisputeEscrow("0xE", adapter.DisputeParams{DisputerAddr: "0xD"}); err != nil {
		t.Error(err)
	}
	if _, err := a.SettleWithRuling("0xE", adapter.Ruling{BuyerPercent: 50, SellerPercent: 50}); err != nil {
		t.Error(err)
	}
	if _, err := a.RefundAfterTimeout("0xE"); err != nil {
		t.Error(err)
	}
	if _, err := a.EscrowState("0xE"); err != nil {
		t.Error(err)
	}
	if _, err := a.Balance("0xAddr"); err != nil {
		t.Error(err)
	}
	fees, err := a.CalculateFees(big.NewInt(1000), adapter.FeeOptions{MaintainerBPS: 100})
	if err != nil {
		t.Fatalf("CalculateFees: %v", err)
	}
	if fees.Total.Int64() != 1000 {
		t.Error("total fee mismatch")
	}
}

func TestArbitrumUSDCAdapter_LifecycleCalls(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	a, _ := NewArbitrumUSDCAdapter(ft, "0xPRC")
	if _, err := a.ConstructEscrow(adapter.EscrowParams{Buyer: "0xB", Seller: "0xS", Amount: big.NewInt(1)}); err != nil {
		t.Error(err)
	}
	if _, err := a.FundEscrow("0xE", big.NewInt(1)); err != nil {
		t.Error(err)
	}
	if _, err := a.ReleaseEscrow("0xE", adapter.ReleaseParams{}); err != nil {
		t.Error(err)
	}
	if _, err := a.DisputeEscrow("0xE", adapter.DisputeParams{DisputerAddr: "0xD"}); err != nil {
		t.Error(err)
	}
	if _, err := a.SettleWithRuling("0xE", adapter.Ruling{BuyerPercent: 50, SellerPercent: 50}); err != nil {
		t.Error(err)
	}
	if _, err := a.RefundAfterTimeout("0xE"); err != nil {
		t.Error(err)
	}
	if _, err := a.EscrowState("0xE"); err != nil {
		t.Error(err)
	}
	if _, err := a.Balance("0xAddr"); err != nil {
		t.Error(err)
	}
	if _, err := a.CalculateFees(big.NewInt(1000), adapter.FeeOptions{MaintainerBPS: 100}); err != nil {
		t.Errorf("CalculateFees: %v", err)
	}
}

func TestBSCBUSDAdapter_LifecycleCalls(t *testing.T) {
	t.Parallel()
	ft := newFakeTransport()
	a, _ := NewBSCBUSDAdapter(ft, "0xPRC")
	if _, err := a.ConstructEscrow(adapter.EscrowParams{Buyer: "0xB", Seller: "0xS", Amount: big.NewInt(1)}); err != nil {
		t.Error(err)
	}
	if _, err := a.FundEscrow("0xE", big.NewInt(1)); err != nil {
		t.Error(err)
	}
	if _, err := a.ReleaseEscrow("0xE", adapter.ReleaseParams{}); err != nil {
		t.Error(err)
	}
	if _, err := a.DisputeEscrow("0xE", adapter.DisputeParams{DisputerAddr: "0xD"}); err != nil {
		t.Error(err)
	}
	if _, err := a.SettleWithRuling("0xE", adapter.Ruling{BuyerPercent: 50, SellerPercent: 50}); err != nil {
		t.Error(err)
	}
	if _, err := a.RefundAfterTimeout("0xE"); err != nil {
		t.Error(err)
	}
	if _, err := a.EscrowState("0xE"); err != nil {
		t.Error(err)
	}
	if _, err := a.Balance("0xAddr"); err != nil {
		t.Error(err)
	}
	if _, err := a.CalculateFees(big.NewInt(1000), adapter.FeeOptions{MaintainerBPS: 100}); err != nil {
		t.Errorf("CalculateFees: %v", err)
	}
}

// --- CalculateFees tests ---

func TestCalculateFees_NonPositiveAmountRefused(t *testing.T) {
	t.Parallel()
	a, _ := NewPolygonUSDCAdapter(newFakeTransport(), "0xPRC")
	for _, amount := range []*big.Int{nil, big.NewInt(0), big.NewInt(-1)} {
		if _, err := a.CalculateFees(amount, adapter.FeeOptions{MaintainerBPS: 100}); err == nil {
			t.Errorf("amount %v: a breakdown was answered, want a refusal", amount)
		}
	}
}

func TestCalculateFees_FullBreakdown(t *testing.T) {
	t.Parallel()
	a, _ := NewPolygonUSDCAdapter(newFakeTransport(), "0xPRC")
	amount := big.NewInt(10_000)
	fees, err := a.CalculateFees(amount, adapter.FeeOptions{
		MaintainerBPS:      100, // 1%
		HasServiceProvider: true,
		ServiceProviderBPS: 50, // 0.5%
		HasDispute:         true,
		ArbitratorBPS:      200, // 2%
		HasWitness:         true,
		WitnessBPS:         25, // 0.25%
	})
	if err != nil {
		t.Fatalf("CalculateFees: %v", err)
	}
	// 10000 * 100/10000 = 100
	if fees.MaintainerFee.Int64() != 100 {
		t.Errorf("maintainer: got %s, want 100", fees.MaintainerFee)
	}
	if fees.ServiceProviderFee.Int64() != 50 {
		t.Errorf("service provider: got %s, want 50", fees.ServiceProviderFee)
	}
	if fees.ArbitratorFee.Int64() != 200 {
		t.Errorf("arbitrator: got %s, want 200", fees.ArbitratorFee)
	}
	if fees.WitnessFee.Int64() != 25 {
		t.Errorf("witness: got %s, want 25", fees.WitnessFee)
	}
	// Total fees = 100+50+200+25 = 375. Seller = 10000-375 = 9625.
	if fees.SellerProceeds.Int64() != 9625 {
		t.Errorf("seller: got %s, want 9625", fees.SellerProceeds)
	}
	if fees.Total.Cmp(amount) != 0 {
		t.Errorf("total: got %s, want %s", fees.Total, amount)
	}
}

// Fee options past a role's cap, or past the combined cap, are refused, so an
// adapter never reports a breakdown whose parts exceed the amount.
func TestCalculateFees_CapsRefused(t *testing.T) {
	t.Parallel()
	a, _ := NewPolygonUSDCAdapter(newFakeTransport(), "0xPRC")
	for name, opts := range map[string]adapter.FeeOptions{
		"maintainer over 500":  {MaintainerBPS: 501},
		"witness over 100":     {HasWitness: true, WitnessBPS: 101},
		"service over 200":     {HasServiceProvider: true, ServiceProviderBPS: 201},
		"arbitrator over 300":  {HasDispute: true, ArbitratorBPS: 301},
		"combined over 1000":   {MaintainerBPS: 500, HasWitness: true, WitnessBPS: 100, HasServiceProvider: true, ServiceProviderBPS: 200, HasDispute: true, ArbitratorBPS: 300},
		"more than the amount": {MaintainerBPS: 20000},
	} {
		if fees, err := a.CalculateFees(big.NewInt(10_000), opts); err == nil {
			t.Errorf("%s: answered %+v, want a refusal", name, fees)
		}
	}
}

// --- CREATE2 derivation determinism cross-check (not in original) ---

func TestDeployEscrowAddress_DifferentInitHash(t *testing.T) {
	t.Parallel()
	factory := "0x4e59b44847b379578588920cA78FbF26c0B4956C"
	var salt [32]byte
	copy(salt[:], []byte("same-salt"))
	var ih1, ih2 [32]byte
	copy(ih1[:], []byte("init-1"))
	copy(ih2[:], []byte("init-2"))
	if DeployEscrowAddress(factory, salt, ih1) == DeployEscrowAddress(factory, salt, ih2) {
		t.Error("different init hashes must produce different addresses")
	}
}

// --- misc helpers ---

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
