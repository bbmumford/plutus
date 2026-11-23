/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
)

// stubNeutrino is a minimal NeutrinoClient for tests.
type stubNeutrino struct {
	bal   *big.Int
	err   error
	calls int
	last  string
}

func (s *stubNeutrino) Balance(_ context.Context, addr string) (*big.Int, error) {
	s.calls++
	s.last = addr
	if s.err != nil {
		return nil, s.err
	}
	return new(big.Int).Set(s.bal), nil
}

func TestChainPoolBalanceProvider_BTC(t *testing.T) {
	stub := &stubNeutrino{bal: big.NewInt(123456)}
	p := NewChainPoolBalanceProvider(ChainPoolBalanceProviderConfig{
		Neutrino: stub,
		PoolAddresses: map[string]string{
			"bitcoin": "bc1qpoolpooluuu",
		},
	})
	got, err := p.PoolBalance(context.Background(), "bitcoin", "BTC")
	if err != nil {
		t.Fatalf("PoolBalance: %v", err)
	}
	if got.Cmp(big.NewInt(123456)) != 0 {
		t.Errorf("balance=%s want 123456", got)
	}
	if stub.calls != 1 {
		t.Errorf("neutrino calls=%d want 1", stub.calls)
	}
	if stub.last != "bc1qpoolpooluuu" {
		t.Errorf("called with %q want pool address", stub.last)
	}
}

func TestChainPoolBalanceProvider_BTCTestnet(t *testing.T) {
	stub := &stubNeutrino{bal: big.NewInt(42)}
	p := NewChainPoolBalanceProvider(ChainPoolBalanceProviderConfig{
		Neutrino: stub,
		PoolAddresses: map[string]string{
			"bitcoin-testnet": "tb1qtest",
		},
	})
	got, err := p.PoolBalance(context.Background(), "bitcoin-testnet", "BTC")
	if err != nil {
		t.Fatalf("PoolBalance: %v", err)
	}
	if got.Int64() != 42 {
		t.Errorf("balance=%s want 42", got)
	}
}

func TestChainPoolBalanceProvider_BTC_NoNeutrino(t *testing.T) {
	p := NewChainPoolBalanceProvider(ChainPoolBalanceProviderConfig{
		PoolAddresses: map[string]string{
			"bitcoin": "bc1qanything",
		},
	})
	_, err := p.PoolBalance(context.Background(), "bitcoin", "BTC")
	if err == nil || !strings.Contains(err.Error(), "Neutrino") {
		t.Fatalf("want neutrino-missing error, got %v", err)
	}
}

func TestChainPoolBalanceProvider_BTC_NoAddress(t *testing.T) {
	stub := &stubNeutrino{bal: big.NewInt(100)}
	p := NewChainPoolBalanceProvider(ChainPoolBalanceProviderConfig{
		Neutrino: stub,
		// Missing bitcoin mapping.
	})
	_, err := p.PoolBalance(context.Background(), "bitcoin", "BTC")
	if err == nil || !strings.Contains(err.Error(), "no pool address") {
		t.Fatalf("want missing-address error, got %v", err)
	}
}

func TestChainPoolBalanceProvider_BTC_NeutrinoError(t *testing.T) {
	stub := &stubNeutrino{err: errors.New("SPV not synced")}
	p := NewChainPoolBalanceProvider(ChainPoolBalanceProviderConfig{
		Neutrino: stub,
		PoolAddresses: map[string]string{
			"bitcoin": "bc1q",
		},
	})
	_, err := p.PoolBalance(context.Background(), "bitcoin", "BTC")
	if err == nil || !strings.Contains(err.Error(), "SPV not synced") {
		t.Fatalf("want wrapped neutrino error, got %v", err)
	}
}

func TestChainPoolBalanceProvider_EVM_PortalPending(t *testing.T) {
	p := NewChainPoolBalanceProvider(ChainPoolBalanceProviderConfig{})
	_, err := p.PoolBalance(context.Background(), "ethereum", "ETH")
	if !errors.Is(err, ErrPortalNetworkPending) {
		t.Fatalf("want ErrPortalNetworkPending, got %v", err)
	}

	_, err = p.PoolBalance(context.Background(), "polygon", "POL")
	if !errors.Is(err, ErrPortalNetworkPending) {
		t.Fatalf("want ErrPortalNetworkPending for polygon, got %v", err)
	}
}

func TestChainPoolBalanceProvider_NilReceiver(t *testing.T) {
	var p *ChainPoolBalanceProvider
	_, err := p.PoolBalance(context.Background(), "bitcoin", "BTC")
	if err == nil {
		t.Fatal("want nil-receiver error")
	}
}
