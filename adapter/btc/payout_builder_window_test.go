/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package btc

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/bbmumford/plutus/witness"
)

// TestBTCPayoutBuilder_EmbedsWindowMetadata confirms that calling the
// window-aware builder entry point with non-zero (windowID, root) produces
// a serialized tx whose final OP_RETURN output contains exactly the 44-byte
// DESIGN §17 payload:
//
//	"WWDW" (4) || windowID BE (8) || attestationLogRoot (32) = 44 bytes
//
// scriptPubKey shape: OP_RETURN (0x6a) + push-44 (0x2c) + payload = 46 bytes.
func TestBTCPayoutBuilder_EmbedsWindowMetadata(t *testing.T) {
	poolAddr := mustEncodeP2WPKH("bc", hashBytes("win-pool"))
	recipient := mustEncodeP2WPKH("bc", hashBytes("win-recipient"))

	poolHash := mustHash160(t, poolAddr)
	utxo := PoolUTXO{
		TxID:          deterministicTxID("win-meta-utxo-0"),
		Vout:          0,
		AmountSat:     1_000_000,
		PubKeyHash160: poolHash,
	}
	bld, err := NewBTCPayoutBuilder(BTCPayoutBuilderConfig{
		Network: "mainnet",
		UTXOSource: &StaticPoolUTXOSource{
			ByAddr: map[string][]PoolUTXO{poolAddr: {utxo}},
		},
		FeeRateSatPerVByte: 5,
	})
	if err != nil {
		t.Fatalf("NewBTCPayoutBuilder: %v", err)
	}

	payouts := []witness.Payout{
		{
			WitnessAddr: recipient,
			Amount:      big.NewInt(10_000),
			ChainID:     "bitcoin",
			Currency:    "BTC",
		},
	}

	var root [32]byte
	copy(root[:], bytes.Repeat([]byte{0xAB}, 32))
	const windowID uint64 = 0x0123456789ABCDEF

	batch, err := bld.BuildWindowedBatchPayout(poolAddr, payouts, false, windowID, root)
	if err != nil {
		t.Fatalf("BuildWindowedBatchPayout: %v", err)
	}
	if batch.Kind != witness.BatchKindBTCMultiOutput {
		t.Fatalf("batch kind = %v, want BatchKindBTCMultiOutput", batch.Kind)
	}

	raw := batch.Payload
	// Locate the 4-byte magic "WWDW" inside the serialized tx. Its shape is
	// stable: OP_RETURN (0x6a) + push 44 (0x2c) + magic + 8 + 32.
	idx := bytes.Index(raw, WitnessWindowOpReturnMagic)
	if idx < 0 {
		t.Fatalf("OP_RETURN magic not found in serialized tx (len=%d): %x",
			len(raw), raw)
	}
	// Before the magic: expect OP_RETURN + OP_PUSHBYTES_44.
	if idx < 2 || raw[idx-2] != 0x6a || raw[idx-1] != 0x2c {
		t.Fatalf("scriptPubKey prefix at idx-2 = %x %x, want 6a 2c (OP_RETURN + push 44)",
			raw[idx-2], raw[idx-1])
	}
	gotWindowID := binary.BigEndian.Uint64(raw[idx+4 : idx+12])
	if gotWindowID != windowID {
		t.Fatalf("embedded windowID = 0x%x, want 0x%x", gotWindowID, windowID)
	}
	if !bytes.Equal(raw[idx+12:idx+44], root[:]) {
		t.Fatalf("embedded root = %x, want %x", raw[idx+12:idx+44], root[:])
	}
}

// TestBTCPayoutBuilder_NoMetadataWhenWindowZero confirms that when windowID
// or root is zero, NO OP_RETURN output is emitted. This matches the
// backward-compat contract with the plain PayoutBuilder interface.
func TestBTCPayoutBuilder_NoMetadataWhenWindowZero(t *testing.T) {
	poolAddr := mustEncodeP2WPKH("bc", hashBytes("no-meta-pool"))
	recipient := mustEncodeP2WPKH("bc", hashBytes("no-meta-recipient"))

	poolHash := mustHash160(t, poolAddr)
	utxo := PoolUTXO{
		TxID:          deterministicTxID("no-meta-utxo-0"),
		Vout:          0,
		AmountSat:     1_000_000,
		PubKeyHash160: poolHash,
	}
	bld, err := NewBTCPayoutBuilder(BTCPayoutBuilderConfig{
		Network: "mainnet",
		UTXOSource: &StaticPoolUTXOSource{
			ByAddr: map[string][]PoolUTXO{poolAddr: {utxo}},
		},
		FeeRateSatPerVByte: 5,
	})
	if err != nil {
		t.Fatalf("NewBTCPayoutBuilder: %v", err)
	}

	payouts := []witness.Payout{
		{
			WitnessAddr: recipient,
			Amount:      big.NewInt(10_000),
			ChainID:     "bitcoin",
			Currency:    "BTC",
		},
	}

	// Plain BuildBatchPayout: no metadata → no OP_RETURN.
	batch, err := bld.BuildBatchPayout(poolAddr, payouts, false)
	if err != nil {
		t.Fatalf("BuildBatchPayout: %v", err)
	}
	if bytes.Contains(batch.Payload, WitnessWindowOpReturnMagic) {
		t.Fatalf("plain path emitted OP_RETURN magic unexpectedly: %x", batch.Payload)
	}

	// Windowed entry point with zero metadata → still no OP_RETURN.
	batch2, err := bld.BuildWindowedBatchPayout(poolAddr, payouts, false, 0, [32]byte{})
	if err != nil {
		t.Fatalf("BuildWindowedBatchPayout: %v", err)
	}
	if bytes.Contains(batch2.Payload, WitnessWindowOpReturnMagic) {
		t.Fatalf("zero-metadata windowed path emitted OP_RETURN magic: %x", batch2.Payload)
	}
}
