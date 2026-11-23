/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

//go:build !js

package btc

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
)

// TestNeutrinoNetParams covers the network-string → chaincfg.Params switch.
// All supported aliases must round-trip; unknown names must error.
func TestNeutrinoNetParams(t *testing.T) {
	cases := []struct {
		in   string
		want *chaincfg.Params
		err  bool
	}{
		{"bitcoin", &chaincfg.MainNetParams, false},
		{"mainnet", &chaincfg.MainNetParams, false},
		{"testnet", &chaincfg.TestNet3Params, false},
		{"testnet3", &chaincfg.TestNet3Params, false},
		{"regtest", &chaincfg.RegressionNetParams, false},
		{"signet", &chaincfg.SigNetParams, false},
		{"", nil, true},
		{"litecoin", nil, true},
	}
	for _, tc := range cases {
		got, err := neutrinoNetParams(tc.in)
		if tc.err {
			if err == nil {
				t.Errorf("neutrinoNetParams(%q) expected error, got nil", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("neutrinoNetParams(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if got.Name != tc.want.Name {
			t.Errorf("neutrinoNetParams(%q) = %s, want %s", tc.in, got.Name, tc.want.Name)
		}
	}
}

// TestAddressToPkScriptRoundTrip verifies that DecodeAddress → PayToAddrScript
// produces non-empty pkScripts for each of Bitcoin's standard address types.
// We don't assert exact byte values (those come from BIP38/BIP173 test vectors
// that would need to be replicated verbatim); instead we verify the pipeline
// a witness actually executes at query time never errors for common address
// families.
func TestAddressToPkScriptRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		addr string
	}{
		// Known mainnet addresses for each standard script type. These are
		// public, well-known addresses and carry no secrets.
		{"p2pkh", "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2"},   // Satoshi-era legacy
		{"p2sh", "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"},    // legacy P2SH
		{"p2wpkh", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"}, // BIP173
		{"p2wsh", "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := btcutil.DecodeAddress(tc.addr, &chaincfg.MainNetParams)
			if err != nil {
				t.Fatalf("DecodeAddress(%s): %v", tc.addr, err)
			}
			if !a.IsForNet(&chaincfg.MainNetParams) {
				t.Fatalf("address %s not for mainnet", tc.addr)
			}
			script, err := txscript.PayToAddrScript(a)
			if err != nil {
				t.Fatalf("PayToAddrScript(%s): %v", tc.addr, err)
			}
			if len(script) == 0 {
				t.Fatalf("PayToAddrScript(%s) returned empty script", tc.addr)
			}
		})
	}
}

// TestPkScriptEqual pins the byte-compare helper's semantics: equal length +
// equal content only, nil-safe.
func TestPkScriptEqual(t *testing.T) {
	if !pkScriptEqual(nil, nil) {
		t.Error("pkScriptEqual(nil, nil) = false, want true")
	}
	if !pkScriptEqual([]byte{}, []byte{}) {
		t.Error("pkScriptEqual([]byte{}, []byte{}) = false, want true")
	}
	if !pkScriptEqual([]byte{1, 2, 3}, []byte{1, 2, 3}) {
		t.Error("pkScriptEqual equal = false")
	}
	if pkScriptEqual([]byte{1, 2, 3}, []byte{1, 2, 4}) {
		t.Error("pkScriptEqual different = true")
	}
	if pkScriptEqual([]byte{1, 2, 3}, []byte{1, 2}) {
		t.Error("pkScriptEqual different lengths = true")
	}
	if pkScriptEqual(nil, []byte{1}) {
		t.Error("pkScriptEqual(nil, [1]) = true")
	}
}

// TestOpenOrCreateNeutrinoDB verifies the create-then-open-on-reopen path of
// the bdb walletdb driver. Uses t.TempDir so cleanup is automatic.
func TestOpenOrCreateNeutrinoDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping bdb I/O test in -short mode")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "neutrino.db")

	db, err := openOrCreateNeutrinoDB(path)
	if err != nil {
		t.Fatalf("first open (create): %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close after create: %v", err)
	}

	db2, err := openOrCreateNeutrinoDB(path)
	if err != nil {
		t.Fatalf("second open (existing): %v", err)
	}
	if err := db2.Close(); err != nil {
		t.Fatalf("close after reopen: %v", err)
	}
}

// TestNewNeutrinoBalanceProvider_ValidationOnly exercises the constructor's
// input-validation path without spinning up any P2P sync. We build a
// regtest-params provider in a temp dir, then immediately Stop it. A
// successful Stop implies the DB opened, the ChainService constructed, and
// resources released cleanly.
func TestNewNeutrinoBalanceProvider_ValidationOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping constructor smoke test in -short mode")
	}
	if runtime.GOOS == "windows" {
		// Neutrino/headerfs mmaps block_headers.bin in NewChainService and
		// never exposes a way to close it short of ChainService.Stop() —
		// which itself requires a prior Start(). On Windows, mmap'd files
		// can't be removed until process exit, so t.TempDir cleanup fails.
		// Skip here; real witnesses run on Linux.
		t.Skip("skipping on Windows: Neutrino mmap prevents TempDir cleanup")
	}
	dir := t.TempDir()
	p, err := NewNeutrinoBalanceProvider(dir, "regtest", nil, 0)
	if err != nil {
		t.Fatalf("NewNeutrinoBalanceProvider: %v", err)
	}
	if p.netParams.Name != chaincfg.RegressionNetParams.Name {
		t.Errorf("netParams = %s, want %s", p.netParams.Name, chaincfg.RegressionNetParams.Name)
	}
	if p.birthHeight != 0 {
		t.Errorf("birthHeight = %d, want 0", p.birthHeight)
	}
	if p.started {
		t.Error("provider should not be started before Start()")
	}
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop (before Start) should be idempotent: %v", err)
	}
}

// TestNewNeutrinoBalanceProvider_RejectsEmptyDir locks down the empty-dataDir
// guard.
func TestNewNeutrinoBalanceProvider_RejectsEmptyDir(t *testing.T) {
	if _, err := NewNeutrinoBalanceProvider("", "regtest", nil, 0); err == nil {
		t.Fatal("expected error for empty dataDir, got nil")
	}
}

// TestNewNeutrinoBalanceProvider_RejectsUnknownNet confirms unknown network
// names error before any filesystem work happens.
func TestNewNeutrinoBalanceProvider_RejectsUnknownNet(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewNeutrinoBalanceProvider(dir, "dogecoin", nil, 0); err == nil {
		t.Fatal("expected error for unknown network, got nil")
	}
}
