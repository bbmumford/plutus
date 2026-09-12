/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package witness

import (
	"math/big"
	"testing"
	"time"
)

func TestBalanceCacheHitMiss(t *testing.T) {
	c := newBalanceCache(100 * time.Millisecond)
	if got := c.Get("eth", "0xabc", ""); got != nil {
		t.Fatalf("expected nil on empty cache, got %+v", got)
	}

	result := &BalanceResult{ChainID: "eth", Address: "0xabc", Balance: big.NewInt(42), Decimals: 18}
	c.Put("eth", "0xabc", "", result)

	got := c.Get("eth", "0xabc", "")
	if got == nil || got.Balance.Int64() != 42 {
		t.Fatalf("cache hit expected 42, got %+v", got)
	}
}

func TestBalanceCacheExpiry(t *testing.T) {
	c := newBalanceCache(20 * time.Millisecond)
	c.Put("btc", "bc1q", "", &BalanceResult{Balance: big.NewInt(100)})

	if c.Get("btc", "bc1q", "") == nil {
		t.Fatal("expected fresh hit")
	}
	time.Sleep(40 * time.Millisecond)
	if got := c.Get("btc", "bc1q", ""); got != nil {
		t.Fatalf("expected expired miss, got %+v", got)
	}
}

func TestBalanceCacheKeysIndependent(t *testing.T) {
	c := newBalanceCache(time.Second)
	c.Put("eth", "0xA", "", &BalanceResult{Balance: big.NewInt(1)})
	c.Put("eth", "0xA", "0xToken", &BalanceResult{Balance: big.NewInt(2)})
	c.Put("polygon", "0xA", "", &BalanceResult{Balance: big.NewInt(3)})

	if got := c.Get("eth", "0xA", ""); got == nil || got.Balance.Int64() != 1 {
		t.Fatalf("native eth expected 1, got %+v", got)
	}
	if got := c.Get("eth", "0xA", "0xToken"); got == nil || got.Balance.Int64() != 2 {
		t.Fatalf("erc20 expected 2, got %+v", got)
	}
	if got := c.Get("polygon", "0xA", ""); got == nil || got.Balance.Int64() != 3 {
		t.Fatalf("polygon expected 3, got %+v", got)
	}
}

func TestBalanceCachePurge(t *testing.T) {
	c := newBalanceCache(10 * time.Millisecond)
	c.Put("a", "a", "", &BalanceResult{Balance: big.NewInt(1)})
	c.Put("b", "b", "", &BalanceResult{Balance: big.NewInt(2)})
	if c.Size() != 2 {
		t.Fatalf("expected 2, got %d", c.Size())
	}
	time.Sleep(30 * time.Millisecond)
	if n := c.Purge(); n != 2 {
		t.Fatalf("expected purge to remove 2, got %d", n)
	}
	if c.Size() != 0 {
		t.Fatalf("expected empty after purge, got %d", c.Size())
	}
}
