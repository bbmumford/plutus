/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// controllableTransport is a MeshTransport whose GetBalance / BlockNumber
// responses are configured per-instance, so multiple instances in one test
// can disagree. Built on top of fakeTransport (defined in integration_test.go)
// because its defaults already answer the full EVM JSON-RPC surface — we
// only need to override eth_getBalance and eth_blockNumber per endpoint.
type controllableTransport struct {
	inner       *fakeTransport
	balance     *big.Int
	blockNumber uint64
	delay       time.Duration // delay injected before responding
	// callCount records how many RPC calls hit this transport — used to assert
	// early-exit behaviour doesn't wait on slow providers.
	callCount atomic.Int64
	failWith  error // if non-nil, every SendRPC returns this error
}

func newControllableTransport(balance *big.Int, blockNumber uint64) *controllableTransport {
	ct := &controllableTransport{
		inner:       newFakeTransport(),
		balance:     new(big.Int).Set(balance),
		blockNumber: blockNumber,
	}
	// Prime the underlying fake with balance/block responses.
	ct.applyToInner()
	return ct
}

func (c *controllableTransport) applyToInner() {
	// eth_getBalance: serialise balance as hex (no leading zeros, "0x" prefix).
	hex := "0x" + c.balance.Text(16)
	if c.balance.Sign() == 0 {
		hex = "0x0"
	}
	c.inner.responses["eth_getBalance"] = json.RawMessage("\"" + hex + "\"")
	c.inner.blockNumber = "\"0x" + strings.TrimLeft(fmt.Sprintf("%x", c.blockNumber), "0") + "\""
	if c.blockNumber == 0 {
		c.inner.blockNumber = "\"0x0\""
	}
}

func (c *controllableTransport) SendRPC(ctx context.Context, chainID, method string, params []byte) (json.RawMessage, error) {
	c.callCount.Add(1)
	if c.failWith != nil {
		return nil, c.failWith
	}
	if c.delay > 0 {
		select {
		case <-time.After(c.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return c.inner.SendRPC(ctx, chainID, method, params)
}

// buildMulti assembles a MultiRPCBalanceProvider from the given transports,
// using the supplied quorum + timeout.
func buildMulti(t *testing.T, transports []*controllableTransport, quorum int, timeout time.Duration) *MultiRPCBalanceProvider {
	t.Helper()
	endpoints := make([]RPCEndpoint, len(transports))
	for i, tr := range transports {
		endpoints[i] = RPCEndpoint{
			Name:           fmt.Sprintf("prov%d", i),
			Transport:      tr,
			ChainID:        "polygon",
			NativeDecimals: 18,
		}
	}
	m, err := NewMultiRPCBalanceProvider(endpoints, quorum, timeout, "test")
	if err != nil {
		t.Fatalf("build multi: %v", err)
	}
	return m
}

func TestMultiRPC_Validation(t *testing.T) {
	t.Parallel()

	if _, err := NewMultiRPCBalanceProvider(nil, 1, time.Second, ""); err == nil {
		t.Error("expected error on empty endpoints")
	}
	tr := newControllableTransport(big.NewInt(1), 1)
	if _, err := NewMultiRPCBalanceProvider([]RPCEndpoint{{Name: "a", Transport: tr, ChainID: "polygon"}}, 2, time.Second, ""); err == nil {
		t.Error("expected error when quorum > N")
	}
	if _, err := NewMultiRPCBalanceProvider([]RPCEndpoint{{Name: "a", Transport: tr, ChainID: "polygon"}}, 0, time.Second, ""); err == nil {
		t.Error("expected error when quorum < 1")
	}
	if _, err := NewMultiRPCBalanceProvider([]RPCEndpoint{{Name: "a", Transport: nil, ChainID: "polygon"}}, 1, time.Second, ""); err == nil {
		t.Error("expected error when transport is nil")
	}
	if _, err := NewMultiRPCBalanceProvider([]RPCEndpoint{{Name: "a", Transport: tr, ChainID: ""}}, 1, time.Second, ""); err == nil {
		t.Error("expected error when chainID is empty")
	}
	if _, err := NewMultiRPCBalanceProvider([]RPCEndpoint{
		{Name: "dup", Transport: tr, ChainID: "polygon"},
		{Name: "dup", Transport: tr, ChainID: "polygon"},
	}, 1, time.Second, ""); err == nil {
		t.Error("expected error on duplicate names")
	}
}

func TestMultiRPC_AllAgree(t *testing.T) {
	t.Parallel()

	balance := big.NewInt(1000)
	transports := []*controllableTransport{
		newControllableTransport(balance, 100),
		newControllableTransport(balance, 100),
		newControllableTransport(balance, 100),
		newControllableTransport(balance, 100),
		newControllableTransport(balance, 100),
	}
	m := buildMulti(t, transports, 3, time.Second)

	snap, err := m.QueryBalance(context.Background(), "0xabc", "")
	if err != nil {
		t.Fatalf("QueryBalance: %v", err)
	}
	if snap.Balance.Cmp(balance) != 0 {
		t.Errorf("balance: got %s, want %s", snap.Balance, balance)
	}
	if snap.BlockNumber != 100 {
		t.Errorf("block: got %d, want 100", snap.BlockNumber)
	}
}

func TestMultiRPC_MajorityWins(t *testing.T) {
	t.Parallel()

	truth := big.NewInt(1000)
	lie := big.NewInt(999)
	transports := []*controllableTransport{
		newControllableTransport(truth, 100),
		newControllableTransport(truth, 100),
		newControllableTransport(truth, 100),
		newControllableTransport(lie, 100),
		newControllableTransport(lie, 100),
	}
	m := buildMulti(t, transports, 3, time.Second)

	snap, err := m.QueryBalance(context.Background(), "0xabc", "")
	if err != nil {
		t.Fatalf("QueryBalance: %v", err)
	}
	if snap.Balance.Cmp(truth) != 0 {
		t.Errorf("balance: got %s, want %s (majority)", snap.Balance, truth)
	}
}

func TestMultiRPC_NoQuorum_Split(t *testing.T) {
	t.Parallel()

	a := big.NewInt(1000)
	b := big.NewInt(2000)
	t1 := newControllableTransport(a, 100)
	t2 := newControllableTransport(a, 100)
	t3 := newControllableTransport(b, 100)
	t4 := newControllableTransport(b, 100)
	t5 := newControllableTransport(big.NewInt(0), 0)
	t5.failWith = errors.New("simulated timeout")
	m := buildMulti(t, []*controllableTransport{t1, t2, t3, t4, t5}, 3, time.Second)

	_, err := m.QueryBalance(context.Background(), "0xabc", "")
	if err == nil {
		t.Fatal("expected no-quorum error")
	}
	if !strings.Contains(err.Error(), "no quorum") {
		t.Errorf("error does not mention no-quorum: %v", err)
	}
	if !strings.Contains(err.Error(), "simulated timeout") {
		t.Errorf("error does not include per-provider failure: %v", err)
	}
}

func TestMultiRPC_AllDifferent(t *testing.T) {
	t.Parallel()

	transports := []*controllableTransport{
		newControllableTransport(big.NewInt(1), 100),
		newControllableTransport(big.NewInt(2), 100),
		newControllableTransport(big.NewInt(3), 100),
		newControllableTransport(big.NewInt(4), 100),
		newControllableTransport(big.NewInt(5), 100),
	}
	m := buildMulti(t, transports, 3, time.Second)

	_, err := m.QueryBalance(context.Background(), "0xabc", "")
	if err == nil {
		t.Fatal("expected no-quorum error when all values differ")
	}
}

func TestMultiRPC_DifferentBlockNumbers(t *testing.T) {
	t.Parallel()

	// Same balance value, different block numbers — these should NOT bucket
	// together. Three agree on (value=1000, block=100); two on block=101.
	transports := []*controllableTransport{
		newControllableTransport(big.NewInt(1000), 100),
		newControllableTransport(big.NewInt(1000), 100),
		newControllableTransport(big.NewInt(1000), 100),
		newControllableTransport(big.NewInt(1000), 101),
		newControllableTransport(big.NewInt(1000), 101),
	}
	m := buildMulti(t, transports, 3, time.Second)

	snap, err := m.QueryBalance(context.Background(), "0xabc", "")
	if err != nil {
		t.Fatalf("QueryBalance: %v", err)
	}
	if snap.BlockNumber != 100 {
		t.Errorf("block: got %d, want 100 (the majority bucket)", snap.BlockNumber)
	}
}

func TestMultiRPC_EarlyExit_SlowProviders(t *testing.T) {
	t.Parallel()

	balance := big.NewInt(1000)
	t1 := newControllableTransport(balance, 100)
	t2 := newControllableTransport(balance, 100)
	t3 := newControllableTransport(balance, 100)
	// These two take longer than the whole test timeout — if the multi-RPC
	// provider fails to early-exit, the overall query will exceed the
	// provider-level timeout and the assertion on elapsed time will fail.
	slow1 := newControllableTransport(balance, 100)
	slow1.delay = 2 * time.Second
	slow2 := newControllableTransport(balance, 100)
	slow2.delay = 2 * time.Second

	m := buildMulti(t, []*controllableTransport{t1, t2, t3, slow1, slow2}, 3, 5*time.Second)

	start := time.Now()
	snap, err := m.QueryBalance(context.Background(), "0xabc", "")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("QueryBalance: %v", err)
	}
	if snap.Balance.Cmp(balance) != 0 {
		t.Errorf("balance mismatch: %s vs %s", snap.Balance, balance)
	}
	// Should early-exit well before the 2s delay — 1s is conservative.
	if elapsed > time.Second {
		t.Errorf("early-exit failed: took %v (slow providers blocked the result)", elapsed)
	}
}

func TestMultiRPC_ContextCancellation(t *testing.T) {
	t.Parallel()

	balance := big.NewInt(1000)
	transports := []*controllableTransport{
		newControllableTransport(balance, 100),
		newControllableTransport(balance, 100),
		newControllableTransport(balance, 100),
	}
	// Large delay so that the only way this query ever returns is cancellation.
	for _, tr := range transports {
		tr.delay = 5 * time.Second
	}
	m := buildMulti(t, transports, 3, 30*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel asynchronously while the workers are mid-flight.
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err := m.QueryBalance(ctx, "0xabc", "")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error on cancellation")
	}
	if elapsed > 2*time.Second {
		t.Errorf("cancellation took too long: %v", elapsed)
	}
}

func TestMultiRPC_ProviderErrorsStillAllowQuorum(t *testing.T) {
	t.Parallel()

	balance := big.NewInt(1000)
	t1 := newControllableTransport(balance, 100)
	t2 := newControllableTransport(balance, 100)
	t3 := newControllableTransport(balance, 100)
	tErr1 := newControllableTransport(big.NewInt(0), 0)
	tErr1.failWith = errors.New("network error")
	tErr2 := newControllableTransport(big.NewInt(0), 0)
	tErr2.failWith = errors.New("503 gateway")

	m := buildMulti(t, []*controllableTransport{t1, t2, t3, tErr1, tErr2}, 3, time.Second)

	snap, err := m.QueryBalance(context.Background(), "0xabc", "")
	if err != nil {
		t.Fatalf("expected quorum to succeed despite 2 provider failures: %v", err)
	}
	if snap.Balance.Cmp(balance) != 0 {
		t.Errorf("balance: %s vs %s", snap.Balance, balance)
	}
}

func TestMultiRPC_EmptyAddress(t *testing.T) {
	t.Parallel()

	tr := newControllableTransport(big.NewInt(0), 0)
	m := buildMulti(t, []*controllableTransport{tr}, 1, time.Second)
	if _, err := m.QueryBalance(context.Background(), "", ""); err == nil {
		t.Error("expected error on empty address")
	}
}

func TestMultiRPC_Accessors(t *testing.T) {
	t.Parallel()

	tr := newControllableTransport(big.NewInt(0), 0)
	m := buildMulti(t, []*controllableTransport{tr, tr, tr}, 2, time.Second)
	if m.Quorum() != 2 {
		t.Errorf("Quorum: got %d, want 2", m.Quorum())
	}
	if m.EndpointCount() != 3 {
		t.Errorf("EndpointCount: got %d, want 3", m.EndpointCount())
	}
}

func TestDefaultEndpoints(t *testing.T) {
	t.Parallel()

	cases := []struct {
		chain string
		min   int
	}{
		{"polygon", 5},
		{"ethereum", 5},
		{"arbitrum", 5},
		{"bsc", 5},
	}
	for _, c := range cases {
		got := DefaultEndpointsFor(c.chain)
		if len(got) < c.min {
			t.Errorf("%s: got %d endpoints, want >= %d", c.chain, len(got), c.min)
		}
		for _, ep := range got {
			if ep.Name == "" || ep.RPCURL == "" || ep.ChainID != c.chain {
				t.Errorf("%s: malformed endpoint %+v", c.chain, ep)
			}
			if !strings.HasPrefix(ep.RPCURL, "https://") {
				t.Errorf("%s: endpoint %q not HTTPS: %s", c.chain, ep.Name, ep.RPCURL)
			}
		}
	}
	if got := DefaultEndpointsFor("unknown-chain"); got != nil {
		t.Errorf("unknown chain: expected nil, got %v", got)
	}
}
