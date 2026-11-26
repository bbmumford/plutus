/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package btc

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/bbmumford/plutus/adapter"
	"github.com/bbmumford/plutus/witness"
)

// newTestAdapterRegistry returns a freshly-constructed adapter registry for
// tests that exercise the registry → payout-builder path.
func newTestAdapterRegistry(t *testing.T) *adapter.Registry {
	t.Helper()
	return adapter.NewRegistry()
}

// testPoolAddr is the pool (source) P2WPKH address used by the builder
// tests. Derived at init time from a deterministic hash160 so the bech32
// checksum is always current.
var (
	testPoolAddr       = mustEncodeP2WPKH("bc", hashBytes("pool-owner"))
	testPayoutSeller   = mustEncodeP2WPKH("bc", hashBytes("payout-seller"))
	testPayoutBuyer    = mustEncodeP2WPKH("bc", hashBytes("payout-buyer"))
	testPayoutWitness  = mustEncodeP2WPKH("bc", hashBytes("payout-witness"))
	testPayoutService  = mustEncodeP2WPKH("bc", hashBytes("payout-service"))
	testPayoutArbitrat = mustEncodeP2WPKH("bc", hashBytes("payout-arb"))
)

// mustEncodeP2WPKH synthesises a v0 P2WPKH bech32 address for the given HRP
// and 20-byte hash160. Panics on failure — intended for test constants.
func mustEncodeP2WPKH(hrp string, h20 [20]byte) string {
	addr, err := EncodeSegWitAddress(hrp, 0, h20[:])
	if err != nil {
		panic(err)
	}
	return addr
}

// hashBytes returns the first 20 bytes of sha256(label) — suitable as a
// stand-in HASH160 in test fixtures. The value is deterministic per label.
func hashBytes(label string) [20]byte {
	sum := sha256.Sum256([]byte(label))
	var out [20]byte
	copy(out[:], sum[:20])
	return out
}

// mustHash160 decodes a bech32 P2WPKH address into its 20-byte program (the
// HASH160 of the owner pubkey). Used to seed PoolUTXO fixtures.
func mustHash160(t *testing.T, addr string) [20]byte {
	t.Helper()
	sw, err := DecodeSegWitAddress(addr)
	if err != nil {
		t.Fatalf("decode %s: %v", addr, err)
	}
	if sw.Version != 0 || len(sw.Program) != 20 {
		t.Fatalf("address %s is not P2WPKH", addr)
	}
	var out [20]byte
	copy(out[:], sw.Program)
	return out
}

// deterministicTxID returns a canned 64-char txid suitable for a PoolUTXO.
// Using a fixed value keeps sighash outputs deterministic across runs.
func deterministicTxID(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])
}

// newTestPayoutBuilder returns a mainnet builder seeded with `utxos` for
// testPoolAddr. Fee rate is pinned to 20 sat/vbyte so fee math is
// predictable.
func newTestPayoutBuilder(t *testing.T, utxos []PoolUTXO) *BTCPayoutBuilder {
	t.Helper()
	src := &StaticPoolUTXOSource{
		ByAddr: map[string][]PoolUTXO{testPoolAddr: utxos},
	}
	b, err := NewBTCPayoutBuilder(BTCPayoutBuilderConfig{
		Network:            "mainnet",
		UTXOSource:         src,
		FeeRateSatPerVByte: 20.0,
	})
	if err != nil {
		t.Fatalf("new builder: %v", err)
	}
	return b
}

// newPayout is a tiny helper that builds a witness.Payout with the fields
// the builder actually inspects.
func newPayout(addr string, sat int64) witness.Payout {
	return witness.Payout{
		WitnessAddr: addr,
		ChainID:     "bitcoin",
		Currency:    "BTC",
		Amount:      big.NewInt(sat),
	}
}

// --- Single-payout test -----------------------------------------------------

func TestBTCPayoutBuilder_SinglePayout(t *testing.T) {
	poolHash := mustHash160(t, testPoolAddr)
	utxos := []PoolUTXO{{
		TxID:          deterministicTxID("single-payout-input-0"),
		Vout:          0,
		AmountSat:     1_000_000, // 0.01 BTC
		PubKeyHash160: poolHash,
	}}
	b := newTestPayoutBuilder(t, utxos)

	batch, err := b.BuildBatchPayout(testPoolAddr, []witness.Payout{
		newPayout(testPayoutSeller, 500_000),
	}, false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if batch.ChainID != "bitcoin" {
		t.Errorf("ChainID=%q want bitcoin", batch.ChainID)
	}
	if batch.Currency != "BTC" {
		t.Errorf("Currency=%q want BTC", batch.Currency)
	}
	if batch.Kind != witness.BatchKindBTCMultiOutput {
		t.Errorf("Kind=%d want BatchKindBTCMultiOutput", batch.Kind)
	}
	if len(batch.Sighashes) != 1 {
		t.Fatalf("Sighashes=%d want 1", len(batch.Sighashes))
	}
	if len(batch.Sighashes[0]) != 32 {
		t.Errorf("sighash[0] len=%d want 32", len(batch.Sighashes[0]))
	}
	if len(batch.Payload) == 0 {
		t.Error("Payload is empty")
	}

	// Round-trip through the minimal decoder to confirm the tx structure.
	tx := decodeMinimalSegwitTx(t, batch.Payload)
	if len(tx.TxIn) != 1 {
		t.Errorf("TxIn=%d want 1", len(tx.TxIn))
	}
	// 1 payout + 1 change = 2 outputs.
	if len(tx.TxOut) != 2 {
		t.Errorf("TxOut=%d want 2 (payout + change)", len(tx.TxOut))
	}
	if tx.TxOut[0].Value != 500_000 {
		t.Errorf("payout value=%d want 500000", tx.TxOut[0].Value)
	}
}

// --- Multi-payout test ------------------------------------------------------

func TestBTCPayoutBuilder_MultiPayout(t *testing.T) {
	poolHash := mustHash160(t, testPoolAddr)
	utxos := []PoolUTXO{
		{TxID: deterministicTxID("multi-in-0"), Vout: 0, AmountSat: 3_000_000, PubKeyHash160: poolHash},
		{TxID: deterministicTxID("multi-in-1"), Vout: 1, AmountSat: 2_000_000, PubKeyHash160: poolHash},
	}
	b := newTestPayoutBuilder(t, utxos)

	// 5 recipients; use five distinct mainnet P2WPKH bech32 addresses.
	recipients := []struct {
		addr string
		sat  int64
	}{
		{testPayoutSeller, 1_000_000},
		{testPayoutBuyer, 500_000},
		{testPayoutWitness, 300_000},
		{testPayoutService, 200_000},
		{testPayoutArbitrat, 100_000},
	}
	payouts := make([]witness.Payout, 0, len(recipients))
	for _, r := range recipients {
		payouts = append(payouts, newPayout(r.addr, r.sat))
	}
	batch, err := b.BuildBatchPayout(testPoolAddr, payouts, false)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if len(batch.Sighashes) != 2 {
		t.Fatalf("Sighashes=%d want 2 (one per input)", len(batch.Sighashes))
	}
	if len(batch.InputScripts) != 2 {
		t.Fatalf("InputScripts=%d want 2", len(batch.InputScripts))
	}
	if len(batch.InputValues) != 2 {
		t.Fatalf("InputValues=%d want 2", len(batch.InputValues))
	}
	// Every scriptCode must be 25 bytes and end in 0x88 0xac.
	for i, s := range batch.InputScripts {
		if len(s) != 25 {
			t.Errorf("InputScripts[%d] len=%d want 25", i, len(s))
		}
		if s[23] != 0x88 || s[24] != 0xac {
			t.Errorf("InputScripts[%d] suffix=%x%x want 88ac", i, s[23], s[24])
		}
	}
	if batch.InputValues[0] != 3_000_000 || batch.InputValues[1] != 2_000_000 {
		t.Errorf("InputValues=%v want [3000000 2000000]", batch.InputValues)
	}

	// Decode the tx we produced to sanity-check output count + amounts.
	tx := decodeMinimalSegwitTx(t, batch.Payload)
	// 5 recipients + 1 change = 6 outputs (change > dust since
	// inputs 5_000_000 - outputs 2_100_000 - fee ~≈ 24k sat).
	if len(tx.TxOut) < 5 || len(tx.TxOut) > 6 {
		t.Fatalf("len(TxOut)=%d want 5 or 6", len(tx.TxOut))
	}

	// Payouts are sorted by WitnessAddr; verify the first output actually
	// pays the lexicographically-smallest recipient.
	sortedAddrs := make([]string, len(recipients))
	for i, r := range recipients {
		sortedAddrs[i] = r.addr
	}
	// Find the lex-smallest address.
	minAddr := sortedAddrs[0]
	for _, a := range sortedAddrs[1:] {
		if a < minAddr {
			minAddr = a
		}
	}
	wantFirstScript, err := PkScriptForAddress(minAddr)
	if err != nil {
		t.Fatalf("pkscript %s: %v", minAddr, err)
	}
	if !bytes.Equal(tx.TxOut[0].PkScript, wantFirstScript) {
		t.Errorf("first output pkscript mismatch: got %x want %x", tx.TxOut[0].PkScript, wantFirstScript)
	}
}

// --- Dust rejection ---------------------------------------------------------

func TestBTCPayoutBuilder_DustRejection(t *testing.T) {
	poolHash := mustHash160(t, testPoolAddr)
	utxos := []PoolUTXO{{
		TxID:          deterministicTxID("dust"),
		Vout:          0,
		AmountSat:     1_000_000,
		PubKeyHash160: poolHash,
	}}
	b := newTestPayoutBuilder(t, utxos)

	_, err := b.BuildBatchPayout(testPoolAddr, []witness.Payout{
		newPayout(testPayoutSeller, 500), // below 546 sat dust
	}, false)
	if err == nil {
		t.Fatal("expected dust error, got nil")
	}
	if !strings.Contains(err.Error(), "dust") {
		t.Errorf("error mentions %q want 'dust': %v", err, err)
	}
}

// --- Insufficient balance ---------------------------------------------------

func TestBTCPayoutBuilder_InsufficientBalance(t *testing.T) {
	poolHash := mustHash160(t, testPoolAddr)
	// Pool has 100k sat; paying out 200k should fail.
	utxos := []PoolUTXO{{
		TxID:          deterministicTxID("insufficient"),
		Vout:          0,
		AmountSat:     100_000,
		PubKeyHash160: poolHash,
	}}
	b := newTestPayoutBuilder(t, utxos)

	_, err := b.BuildBatchPayout(testPoolAddr, []witness.Payout{
		newPayout(testPayoutSeller, 200_000),
	}, false)
	if err == nil {
		t.Fatal("expected insufficient-balance error, got nil")
	}
	if !strings.Contains(err.Error(), "insufficient balance") {
		t.Errorf("unexpected error: %v", err)
	}
}

// --- Deterministic sighash --------------------------------------------------

func TestBTCPayoutBuilder_SighashDeterministic(t *testing.T) {
	poolHash := mustHash160(t, testPoolAddr)
	utxos := []PoolUTXO{{
		TxID:          "0000000000000000000000000000000000000000000000000000000000000001",
		Vout:          0,
		AmountSat:     1_000_000,
		PubKeyHash160: poolHash,
	}}
	b1 := newTestPayoutBuilder(t, utxos)
	b2 := newTestPayoutBuilder(t, utxos)

	payouts := []witness.Payout{newPayout(testPayoutSeller, 500_000)}

	batch1, err := b1.BuildBatchPayout(testPoolAddr, payouts, false)
	if err != nil {
		t.Fatalf("build 1: %v", err)
	}
	batch2, err := b2.BuildBatchPayout(testPoolAddr, payouts, false)
	if err != nil {
		t.Fatalf("build 2: %v", err)
	}

	if !bytes.Equal(batch1.Sighashes[0], batch2.Sighashes[0]) {
		t.Errorf(
			"sighashes differ across builds:\n  %x\n  %x",
			batch1.Sighashes[0], batch2.Sighashes[0],
		)
	}
	if !bytes.Equal(batch1.Payload, batch2.Payload) {
		t.Errorf("payload differs across builds")
	}
}

// --- Network param respected (testnet address rejected on mainnet) ----------

func TestBTCPayoutBuilder_MainnetRejectsTestnetAddress(t *testing.T) {
	poolHash := mustHash160(t, testPoolAddr)
	utxos := []PoolUTXO{{
		TxID: deterministicTxID("network-check"), Vout: 0, AmountSat: 1_000_000, PubKeyHash160: poolHash,
	}}
	b := newTestPayoutBuilder(t, utxos)

	// A valid testnet P2WPKH (HRP "tb") derived deterministically.
	testnetAddr := mustEncodeP2WPKH("tb", hashBytes("testnet-recipient"))
	_, err := b.BuildBatchPayout(testPoolAddr, []witness.Payout{
		newPayout(testnetAddr, 500_000),
	}, false)
	if err == nil {
		t.Fatal("expected HRP-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "HRP") {
		t.Errorf("error should mention HRP mismatch: %v", err)
	}
}

// --- Network param respected (mainnet address rejected on testnet) ----------

func TestBTCPayoutBuilder_TestnetRejectsMainnetAddress(t *testing.T) {
	// Construct a testnet builder. Derive a valid testnet pool address
	// from a deterministic hash so we don't rely on an externally-baked
	// checksum.
	testnetPool := mustEncodeP2WPKH("tb", hashBytes("testnet-pool"))
	poolHash := mustHash160(t, testnetPool)
	utxos := []PoolUTXO{{
		TxID: deterministicTxID("testnet"), Vout: 0, AmountSat: 1_000_000, PubKeyHash160: poolHash,
	}}
	src := &StaticPoolUTXOSource{ByAddr: map[string][]PoolUTXO{testnetPool: utxos}}
	b, err := NewBTCPayoutBuilder(BTCPayoutBuilderConfig{
		Network:            "testnet",
		UTXOSource:         src,
		FeeRateSatPerVByte: 20.0,
	})
	if err != nil {
		t.Fatalf("new builder: %v", err)
	}

	_, err = b.BuildBatchPayout(testnetPool, []witness.Payout{
		newPayout(testPayoutSeller, 500_000), // mainnet address
	}, false)
	if err == nil {
		t.Fatal("expected HRP-mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "HRP") {
		t.Errorf("error should mention HRP mismatch: %v", err)
	}
}

// --- Registry integration ---------------------------------------------------

// --- Registry round-trip ---------------------------------------------------

func TestBTCPayoutBuilder_RegistryRoundTrip(t *testing.T) {
	poolHash := mustHash160(t, testPoolAddr)
	src := &StaticPoolUTXOSource{
		ByAddr: map[string][]PoolUTXO{testPoolAddr: {{
			TxID: deterministicTxID("registry"), Vout: 0, AmountSat: 1_000_000, PubKeyHash160: poolHash,
		}}},
	}

	// Use RegisterBitcoinPayoutBuilder to exercise the full registry
	// integration path used by fleet nodes.
	// Build a fresh adapter.Registry via the public constructor (no
	// cross-package helper) so this test stays within package btc.
	reg := newTestAdapterRegistry(t)
	if err := RegisterBitcoinPayoutBuilder(reg, "mainnet", src, 20.0); err != nil {
		t.Fatalf("register payout builder: %v", err)
	}
	got, err := reg.ResolvePayoutBuilder("bitcoin", "BTC")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	builder, ok := got.(witness.PayoutBuilder)
	if !ok {
		t.Fatalf("resolved builder does not satisfy witness.PayoutBuilder (got %T)", got)
	}
	batch, err := builder.BuildBatchPayout(testPoolAddr, []witness.Payout{
		newPayout(testPayoutSeller, 500_000),
	}, false)
	if err != nil {
		t.Fatalf("build via resolver: %v", err)
	}
	if batch.Kind != witness.BatchKindBTCMultiOutput {
		t.Errorf("Kind=%v want BatchKindBTCMultiOutput", batch.Kind)
	}
	if len(batch.Sighashes) != 1 {
		t.Errorf("Sighashes=%d want 1", len(batch.Sighashes))
	}
}

func TestBTCPayoutBuilder_ImplementsWitnessPayoutBuilder(t *testing.T) {
	poolHash := mustHash160(t, testPoolAddr)
	utxos := []PoolUTXO{{
		TxID: deterministicTxID("iface"), Vout: 0, AmountSat: 1_000_000, PubKeyHash160: poolHash,
	}}
	b := newTestPayoutBuilder(t, utxos)

	// The registry stores builders as witness.PayoutBuilder; build through
	// that interface so the interface path is exercised.
	var iface witness.PayoutBuilder = b
	batch, err := iface.BuildBatchPayout(testPoolAddr, []witness.Payout{
		newPayout(testPayoutSeller, 500_000),
	}, false)
	if err != nil {
		t.Fatalf("iface build: %v", err)
	}
	if batch.Kind != witness.BatchKindBTCMultiOutput {
		t.Errorf("Kind=%v want BatchKindBTCMultiOutput", batch.Kind)
	}
}

// decodeMinimalSegwitTx is a tiny test helper that parses just enough of a
// Bitcoin tx (legacy or BIP141 segwit form) to recover its TxOut list. We
// cannot depend on the package's Serialize having an inverse (it doesn't),
// so we walk the bytes by hand. Handles only single-byte varints for count
// fields since our tests never produce >252 outputs.
func decodeMinimalSegwitTx(t *testing.T, raw []byte) *MsgTx {
	t.Helper()
	if len(raw) < 10 {
		t.Fatalf("tx bytes too short: %d", len(raw))
	}
	tx := NewMsgTx(2)
	pos := 4 // skip version
	// Optional segwit marker(0x00) + flag(0x01). Absent when no input has
	// witness data (unsigned tx path).
	if raw[pos] == 0x00 && raw[pos+1] == 0x01 {
		pos += 2
	}

	// input count (varint, single byte for our tests).
	inCount := int(raw[pos])
	pos++
	for i := 0; i < inCount; i++ {
		if pos+32+4 > len(raw) {
			t.Fatalf("input %d outpoint out of bounds", i)
		}
		pos += 32 // hash
		pos += 4  // index
		// signatureScript (should be 0 bytes for segwit).
		if pos >= len(raw) {
			t.Fatalf("input %d sigscript out of bounds", i)
		}
		sigLen := int(raw[pos])
		pos++
		pos += sigLen
		// sequence.
		pos += 4
		tx.AddTxIn(&TxIn{})
	}

	// output count (varint, single byte for our tests).
	if pos >= len(raw) {
		t.Fatalf("output count out of bounds")
	}
	outCount := int(raw[pos])
	pos++
	for i := 0; i < outCount; i++ {
		if pos+8 > len(raw) {
			t.Fatalf("output %d value out of bounds", i)
		}
		value := int64(raw[pos]) | int64(raw[pos+1])<<8 | int64(raw[pos+2])<<16 | int64(raw[pos+3])<<24 |
			int64(raw[pos+4])<<32 | int64(raw[pos+5])<<40 | int64(raw[pos+6])<<48 | int64(raw[pos+7])<<56
		pos += 8
		if pos >= len(raw) {
			t.Fatalf("output %d script len out of bounds", i)
		}
		scriptLen := int(raw[pos])
		pos++
		if pos+scriptLen > len(raw) {
			t.Fatalf("output %d script out of bounds", i)
		}
		tx.AddTxOut(&TxOut{Value: value, PkScript: append([]byte(nil), raw[pos:pos+scriptLen]...)})
		pos += scriptLen
	}
	return tx
}
