/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package btc

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"testing"

	"github.com/bbmumford/plutus/adapter"
)

// fakePubKey returns a deterministic 33-byte compressed "pubkey" for test
// fixtures. It is NOT a valid curve point; the escrow script builder only
// checks length, and these tests never verify the script against a chain.
func fakePubKey(seed byte) []byte {
	b := make([]byte, 33)
	b[0] = 0x02 // even-y marker
	for i := 1; i < 33; i++ {
		b[i] = seed + byte(i)
	}
	return b
}

const (
	// Known-good mainnet P2WPKH addresses for test payouts. bech32-valid,
	// point at unrelated hash160 values — fine for fee-enforcement checks
	// that never broadcast.
	testMaintainerAddr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	testSellerAddr     = "bc1q0xcqpzrky6eff2g52qdye53xkk9jxkvrh6yhyw"
	testBuyerAddr      = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0g"
	testWitnessAddr    = "bc1qpg9scrgwpugpzysnzs23v9ccrydpk8qavs28mk"
	testServiceAddr    = "bc1qpvxq6rs0zqg3yyc5z5tpwxqergd3c8g784y56y"
	testArbitratorAddr = "bc1qpsxsurcszyfpx9q4zct3sxg6rvwp68sl74dp3e"
)

func newTestEscrowState(t *testing.T) BTCEscrowState {
	t.Helper()
	script, err := CreateEscrowScript(fakePubKey(1), fakePubKey(2), fakePubKey(3), 144)
	if err != nil {
		t.Fatalf("build escrow script: %v", err)
	}
	// Deterministic fake funding txid.
	var txHash [32]byte
	if _, err := rand.Read(txHash[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}

	return BTCEscrowState{
		Address:          "bc1q" + "unused" + "addressplaceholder", // not used by tx builder directly
		WitnessScript:    script.Script,
		BuyerPubKey:      fakePubKey(1),
		SellerPubKey:     fakePubKey(2),
		ArbitratorPubKey: fakePubKey(3),
		TimeoutBlocks:    144,
		FundingTxID:      hexString(txHash[:]),
		FundingVout:      0,
		FundingAmount:    big.NewInt(1_000_000), // 0.01 BTC = 1,000,000 sat
		Status:           adapter.EscrowStatusFunded,
		BuyerPayoutAddr:  testBuyerAddr,
		SellerPayoutAddr: testSellerAddr,
		TimeoutAt:        144,
	}
}

// hexString encodes bytes to lowercase hex.
func hexString(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}

// standardFees returns a fee breakdown for a 1,000,000 sat escrow:
//   - maintainer 3% = 30,000 sat
//   - seller 97%    = 970,000 sat
func standardFees() adapter.FeeBreakdown {
	return adapter.FeeBreakdown{
		MaintainerFee:      big.NewInt(30_000),
		ServiceProviderFee: big.NewInt(0),
		ArbitratorFee:      big.NewInt(0),
		WitnessFee:         big.NewInt(0),
		SellerProceeds:     big.NewInt(970_000),
		Total:              big.NewInt(1_000_000),
	}
}

func TestBuildReleaseTx_IncludesMaintainerOutput(t *testing.T) {
	escrow := newTestEscrowState(t)
	fees := standardFees()

	tx, err := BuildReleaseTx(BuildReleaseTxParams{
		Escrow: escrow,
		Fees:   fees,
		Payouts: ReleasePayouts{
			RecipientAddr:  testSellerAddr,
			MaintainerAddr: testMaintainerAddr,
		},
		FeeRateSatPerVByte: 10.0,
	})
	if err != nil {
		t.Fatalf("BuildReleaseTx: %v", err)
	}

	if len(tx.TxIn) != 1 {
		t.Fatalf("expected 1 input, got %d", len(tx.TxIn))
	}
	if len(tx.TxOut) != 2 {
		t.Fatalf("expected 2 outputs (recipient + maintainer), got %d", len(tx.TxOut))
	}

	// Output 0 pays the seller; output 1 pays the maintainer.
	idx, val, err := FindOutputForAddress(tx, testMaintainerAddr)
	if err != nil {
		t.Fatalf("FindOutputForAddress: %v", err)
	}
	if idx != 1 {
		t.Fatalf("maintainer output at wrong index: got %d want 1", idx)
	}
	if val != 30_000 {
		t.Fatalf("maintainer value wrong: got %d want 30000", val)
	}

	idx, _, err = FindOutputForAddress(tx, testSellerAddr)
	if err != nil {
		t.Fatalf("FindOutputForAddress seller: %v", err)
	}
	if idx != 0 {
		t.Fatalf("seller output at wrong index: got %d want 0", idx)
	}

	// Sanity: tx serializes without error.
	if _, err := tx.Serialize(); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
}

func TestBuildReleaseTx_MismatchedFeesFail(t *testing.T) {
	escrow := newTestEscrowState(t)
	fees := standardFees()
	// Corrupt: seller proceeds too low so components no longer sum to total.
	fees.SellerProceeds = big.NewInt(900_000)

	_, err := BuildReleaseTx(BuildReleaseTxParams{
		Escrow: escrow,
		Fees:   fees,
		Payouts: ReleasePayouts{
			RecipientAddr:  testSellerAddr,
			MaintainerAddr: testMaintainerAddr,
		},
		FeeRateSatPerVByte: 10.0,
	})
	if err == nil {
		t.Fatalf("expected fee mismatch error, got nil")
	}
}

func TestPkScriptForAddress_P2WPKH(t *testing.T) {
	script, err := PkScriptForAddress(testMaintainerAddr)
	if err != nil {
		t.Fatalf("PkScriptForAddress: %v", err)
	}
	// P2WPKH scriptPubKey is always 22 bytes: OP_0 (0x00) || 0x14 || 20-byte hash.
	if len(script) != 22 {
		t.Fatalf("P2WPKH script length: got %d want 22", len(script))
	}
	if script[0] != 0x00 || script[1] != 0x14 {
		t.Fatalf("P2WPKH script prefix wrong: %x", script[:2])
	}
}

func TestBIP143Sighash_Deterministic(t *testing.T) {
	escrow := newTestEscrowState(t)
	fees := standardFees()

	tx, err := BuildReleaseTx(BuildReleaseTxParams{
		Escrow: escrow,
		Fees:   fees,
		Payouts: ReleasePayouts{
			RecipientAddr:  testSellerAddr,
			MaintainerAddr: testMaintainerAddr,
		},
		FeeRateSatPerVByte: 10.0,
	})
	if err != nil {
		t.Fatalf("BuildReleaseTx: %v", err)
	}

	hash1, err := tx.ComputeBIP143SighashP2WSH(0, SighashAll)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}
	hash2, err := tx.ComputeBIP143SighashP2WSH(0, SighashAll)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}
	if hash1 != hash2 {
		t.Fatalf("BIP143 sighash is non-deterministic")
	}

	// Mutating an output must change the sighash.
	tx.TxOut[1].Value--
	hash3, err := tx.ComputeBIP143SighashP2WSH(0, SighashAll)
	if err != nil {
		t.Fatalf("sighash: %v", err)
	}
	if hash1 == hash3 {
		t.Fatalf("BIP143 sighash unchanged after tx mutation — hashOutputs is broken")
	}
}

// fullSplitFees returns a fee breakdown for a 1,000,000 sat escrow with all
// four fee parties paid out: maintainer 3% (30000), witness 1% (10000),
// service 2% (20000), arbitrator 3% (30000), seller 91% (910000).
func fullSplitFees() adapter.FeeBreakdown {
	return adapter.FeeBreakdown{
		MaintainerFee:      big.NewInt(30_000),
		WitnessFee:         big.NewInt(10_000),
		ServiceProviderFee: big.NewInt(20_000),
		ArbitratorFee:      big.NewInt(30_000),
		SellerProceeds:     big.NewInt(910_000),
		Total:              big.NewInt(1_000_000),
	}
}

func TestBuildReleaseTx_FullSixOutputSplit(t *testing.T) {
	escrow := newTestEscrowState(t)
	escrow.WitnessPayoutAddr = testWitnessAddr
	escrow.ServicePayoutAddr = testServiceAddr
	escrow.ArbitratorPayoutAddr = testArbitratorAddr

	fees := fullSplitFees()

	tx, err := BuildReleaseTx(BuildReleaseTxParams{
		Escrow: escrow,
		Fees:   fees,
		Payouts: ReleasePayouts{
			RecipientAddr:  testSellerAddr,
			MaintainerAddr: testMaintainerAddr,
			WitnessAddr:    testWitnessAddr,
			ServiceAddr:    testServiceAddr,
			ArbitratorAddr: testArbitratorAddr,
		},
		FeeRateSatPerVByte: 10.0,
	})
	if err != nil {
		t.Fatalf("BuildReleaseTx: %v", err)
	}
	// Recipient + maintainer + witness + service + arbitrator = 5 outputs.
	if len(tx.TxOut) != 5 {
		t.Fatalf("expected 5 outputs (recipient + 4 fees), got %d", len(tx.TxOut))
	}

	// Each non-recipient output pays its declared address with the exact fee.
	expected := map[string]int64{
		testMaintainerAddr: 30_000,
		testWitnessAddr:    10_000,
		testServiceAddr:    20_000,
		testArbitratorAddr: 30_000,
	}
	for addr, want := range expected {
		idx, got, err := FindOutputForAddress(tx, addr)
		if err != nil {
			t.Fatalf("FindOutputForAddress(%s): %v", addr, err)
		}
		if idx < 0 {
			t.Fatalf("missing output for %s", addr)
		}
		if got != want {
			t.Fatalf("output for %s: got %d, want %d", addr, got, want)
		}
	}

	// Seller (recipient) absorbs the mining fee but no fee-portion absorbs
	// since all destinations were set.
	_, sellerVal, err := FindOutputForAddress(tx, testSellerAddr)
	if err != nil {
		t.Fatalf("FindOutputForAddress(seller): %v", err)
	}
	if sellerVal <= 0 || sellerVal > 910_000 {
		t.Fatalf("seller value out of range: got %d, want (0, 910000]", sellerVal)
	}
}

func TestBuildReleaseTx_PartialSplit_MaintainerAndArbitrator(t *testing.T) {
	// Only maintainer + arbitrator destinations declared. Witness/service
	// fees should be absorbed into the seller (recipient) output.
	escrow := newTestEscrowState(t)
	escrow.ArbitratorPayoutAddr = testArbitratorAddr
	// Witness/Service intentionally left empty.

	fees := fullSplitFees()

	tx, err := BuildReleaseTx(BuildReleaseTxParams{
		Escrow: escrow,
		Fees:   fees,
		Payouts: ReleasePayouts{
			RecipientAddr:  testSellerAddr,
			MaintainerAddr: testMaintainerAddr,
			ArbitratorAddr: testArbitratorAddr,
			// WitnessAddr / ServiceAddr left empty — fees absorbed.
		},
		FeeRateSatPerVByte: 10.0,
	})
	if err != nil {
		t.Fatalf("BuildReleaseTx: %v", err)
	}
	// 3 outputs: seller + maintainer + arbitrator.
	if len(tx.TxOut) != 3 {
		t.Fatalf("expected 3 outputs (recipient + maintainer + arbitrator), got %d", len(tx.TxOut))
	}
	idx, got, _ := FindOutputForAddress(tx, testArbitratorAddr)
	if idx < 0 || got != 30_000 {
		t.Fatalf("arbitrator output: idx=%d val=%d", idx, got)
	}
	idx, _, _ = FindOutputForAddress(tx, testWitnessAddr)
	if idx >= 0 {
		t.Fatalf("witness output should be absent (absorbed into recipient)")
	}
	idx, _, _ = FindOutputForAddress(tx, testServiceAddr)
	if idx >= 0 {
		t.Fatalf("service output should be absent (absorbed into recipient)")
	}
}

func TestConstructEscrow_PlumbsAllPayoutAddresses(t *testing.T) {
	// Verify the adapter end-to-end picks up all payout addresses from
	// EscrowParams and stores them on BTCEscrowState — so a later
	// ReleaseEscrow call routes fees correctly.
	a, err := NewBTCAdapter(BTCAdapterConfig{
		Transport:      &nopTransport{},
		Network:        "mainnet",
		MaintainerAddr: testMaintainerAddr,
	})
	if err != nil {
		t.Fatalf("NewBTCAdapter: %v", err)
	}
	tx, err := a.ConstructEscrow(adapter.EscrowParams{
		Buyer:                 testBuyerAddr,
		Seller:                testSellerAddr,
		Amount:                big.NewInt(1_000_000),
		Currency:              "BTC",
		TimeoutSeconds:        86400, // 1 day
		WitnessHashes:         [][]byte{fakePubKey(1), fakePubKey(2), fakePubKey(3)},
		ServiceProviderPayout: testServiceAddr,
		ArbitratorPayout:      testArbitratorAddr,
		WitnessPayout:         testWitnessAddr,
	})
	if err != nil {
		t.Fatalf("ConstructEscrow: %v", err)
	}
	state := a.GetEscrow(tx.EscrowAddr)
	if state == nil {
		t.Fatalf("escrow not registered")
	}
	if state.WitnessPayoutAddr != testWitnessAddr {
		t.Fatalf("witness payout: got %q want %q", state.WitnessPayoutAddr, testWitnessAddr)
	}
	if state.ServicePayoutAddr != testServiceAddr {
		t.Fatalf("service payout: got %q want %q", state.ServicePayoutAddr, testServiceAddr)
	}
	if state.ArbitratorPayoutAddr != testArbitratorAddr {
		t.Fatalf("arbitrator payout: got %q want %q", state.ArbitratorPayoutAddr, testArbitratorAddr)
	}
}

// nopTransport is a no-op MeshTransport used by tests that don't broadcast.
type nopTransport struct{}

func (nopTransport) SendRPC(_ context.Context, _ string, _ string, _ []byte) (json.RawMessage, error) {
	return nil, nil
}

func TestEscrowStatus_Release_UnsignedRoundTrip(t *testing.T) {
	// End-to-end: escrow state → release tx → serialize → parse outputs.
	escrow := newTestEscrowState(t)
	fees := standardFees()

	tx, err := BuildReleaseTx(BuildReleaseTxParams{
		Escrow: escrow,
		Fees:   fees,
		Payouts: ReleasePayouts{
			RecipientAddr:  testSellerAddr,
			MaintainerAddr: testMaintainerAddr,
		},
		FeeRateSatPerVByte: 10.0,
	})
	if err != nil {
		t.Fatalf("BuildReleaseTx: %v", err)
	}
	raw, err := tx.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(raw) < 60 {
		t.Fatalf("serialized tx too short: %d bytes", len(raw))
	}
	// Unsigned release: no witness stack yet, so no segwit marker.
	if raw[4] == 0x00 && raw[5] == 0x01 {
		t.Fatalf("unsigned tx should not have segwit marker+flag")
	}
}
