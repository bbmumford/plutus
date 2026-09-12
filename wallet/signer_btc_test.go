/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package wallet

import (
	"crypto/rand"
	"math/big"
	"strings"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/bbmumford/plutus/adapter"
	"github.com/bbmumford/plutus/adapter/btc"
)

const (
	testMaintainerAddr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	testSellerAddr     = "bc1q0xcqpzrky6eff2g52qdye53xkk9jxkvrh6yhyw"
	testBuyerAddr      = "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0g"
)

// makeTestKey returns a secp256k1 private key with a random scalar. We
// bypass the BIP32 derivation path because Go's stdlib `elliptic` rejects
// ScalarBaseMult on generic CurveParams for secp256k1 on recent Go versions;
// direct scalar construction is sufficient for the signer tests, which only
// exercise fee-enforcement logic and DER encoding, not on-chain verification.
func makeTestKey(t *testing.T) *ECDSAPrivateKey {
	t.Helper()
	d := make([]byte, 32)
	if _, err := rand.Read(d); err != nil {
		t.Fatalf("rand: %v", err)
	}
	// Force the scalar into a safe range far from zero and well below N.
	d[0] = 0x01
	curve := secp256k1.S256()
	params := curve.Params()
	dInt := new(big.Int).SetBytes(d)
	// We cannot use curve.ScalarBaseMult (stdlib rejects it on secp256k1
	// CurveParams), so we stub X/Y with G's coordinates — adequate for the
	// signer path which only uses D for ecdsa.Sign. DER output is still
	// valid; on-chain verification isn't exercised here.
	return &ECDSAPrivateKey{
		D:     dInt,
		X:     new(big.Int).Set(params.Gx),
		Y:     new(big.Int).Set(params.Gy),
		Curve: curve,
	}
}

func makeTestEscrowAndTx(t *testing.T, feeBps uint32) (btc.BTCEscrowState, *btc.MsgTx, adapter.FeeBreakdown) {
	t.Helper()

	pub := func(seed byte) []byte {
		b := make([]byte, 33)
		b[0] = 0x02
		for i := 1; i < 33; i++ {
			b[i] = seed + byte(i)
		}
		return b
	}
	script, err := btc.CreateEscrowScript(pub(1), pub(2), pub(3), 144)
	if err != nil {
		t.Fatalf("escrow script: %v", err)
	}

	var txHash [32]byte
	if _, err := rand.Read(txHash[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	fundingTxID := hexBytes(txHash[:])

	amount := int64(1_000_000)
	escrow := btc.BTCEscrowState{
		WitnessScript:    script.Script,
		BuyerPubKey:      pub(1),
		SellerPubKey:     pub(2),
		ArbitratorPubKey: pub(3),
		TimeoutBlocks:    144,
		FundingTxID:      fundingTxID,
		FundingVout:      0,
		FundingAmount:    big.NewInt(amount),
		Status:           adapter.EscrowStatusFunded,
		BuyerPayoutAddr:  testBuyerAddr,
		SellerPayoutAddr: testSellerAddr,
		TimeoutAt:        144,
	}

	maintainerSat := amount * int64(feeBps) / 10000
	fees := adapter.FeeBreakdown{
		MaintainerFee:      big.NewInt(maintainerSat),
		ServiceProviderFee: big.NewInt(0),
		ArbitratorFee:      big.NewInt(0),
		WitnessFee:         big.NewInt(0),
		SellerProceeds:     big.NewInt(amount - maintainerSat),
		Total:              big.NewInt(amount),
	}

	tx, err := btc.BuildReleaseTx(btc.BuildReleaseTxParams{
		Escrow: escrow,
		Fees:   fees,
		Payouts: btc.ReleasePayouts{
			RecipientAddr:  testSellerAddr,
			MaintainerAddr: testMaintainerAddr,
		},
		FeeRateSatPerVByte: 10.0,
	})
	if err != nil {
		t.Fatalf("BuildReleaseTx: %v", err)
	}
	return escrow, tx, fees
}

func hexBytes(b []byte) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hex[v>>4]
		out[i*2+1] = hex[v&0x0f]
	}
	return string(out)
}

// TestSignBTCSettlement_ValidTxSigns: a well-formed tx passes every check
// and returns a non-empty DER signature with the SIGHASH_ALL byte appended.
func TestSignBTCSettlement_ValidTxSigns(t *testing.T) {
	escrow, tx, fees := makeTestEscrowAndTx(t, 300) // 3% maintainer
	signer := NewSigner(nil, nil)
	key := makeTestKey(t)

	sig, err := signer.SignBTCSettlement(BTCSettlementRequest{
		Tx:             tx,
		Fees:           fees,
		Escrow:         escrow,
		MaintainerAddr: testMaintainerAddr,
		InputIndex:     0,
		PrivateKey:     key,
	})
	if err != nil {
		t.Fatalf("expected signature, got error: %v", err)
	}
	if len(sig) < 10 {
		t.Fatalf("signature too short: %d bytes", len(sig))
	}
	// Final byte must be SIGHASH_ALL (0x01).
	if sig[len(sig)-1] != 0x01 {
		t.Fatalf("sighash flag byte missing: got 0x%x", sig[len(sig)-1])
	}
	// DER prefix: 0x30 length.
	if sig[0] != 0x30 {
		t.Fatalf("signature not DER-encoded: leading byte 0x%x", sig[0])
	}
}

// TestSignBTCSettlement_MissingMaintainerOutputFails: a tx that pays the
// seller but not the maintainer MUST be rejected.
func TestSignBTCSettlement_MissingMaintainerOutputFails(t *testing.T) {
	escrow, _, fees := makeTestEscrowAndTx(t, 300)

	// Build a malicious tx that pays the seller and omits the maintainer.
	fundingHash, err := btc.TxIDFromDisplayHex(escrow.FundingTxID)
	if err != nil {
		t.Fatalf("funding hash: %v", err)
	}
	sellerScript, err := btc.PkScriptForAddress(testSellerAddr)
	if err != nil {
		t.Fatalf("seller script: %v", err)
	}
	bad := btc.NewMsgTx(2)
	bad.AddTxIn(&btc.TxIn{
		PreviousOutPoint: btc.OutPoint{Hash: fundingHash, Index: 0},
		Sequence:         0xFFFFFFFE,
		InputValue:       escrow.FundingAmount.Int64(),
		WitnessScript:    escrow.WitnessScript,
	})
	// All 1,000,000 sat minus a token mining fee goes to the seller.
	bad.AddTxOut(&btc.TxOut{Value: 999_000, PkScript: sellerScript})

	signer := NewSigner(nil, nil)
	key := makeTestKey(t)

	_, err = signer.SignBTCSettlement(BTCSettlementRequest{
		Tx:             bad,
		Fees:           fees,
		Escrow:         escrow,
		MaintainerAddr: testMaintainerAddr,
		InputIndex:     0,
		PrivateKey:     key,
	})
	if err == nil {
		t.Fatalf("signer must refuse tx without maintainer output, but signed it")
	}
	if !strings.Contains(err.Error(), "omits maintainer fee output") {
		t.Fatalf("unexpected error: %v (wanted 'omits maintainer fee output')", err)
	}
}

// TestSignBTCSettlement_WrongMaintainerAmountFails: the correct maintainer
// output is present but under-paid.
func TestSignBTCSettlement_WrongMaintainerAmountFails(t *testing.T) {
	escrow, tx, fees := makeTestEscrowAndTx(t, 300)

	// Tamper: shave 10,000 sat off the maintainer output.
	_, origVal, err := btc.FindOutputForAddress(tx, testMaintainerAddr)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	idx, _, _ := btc.FindOutputForAddress(tx, testMaintainerAddr)
	tx.TxOut[idx].Value = origVal - 10_000

	signer := NewSigner(nil, nil)
	key := makeTestKey(t)

	_, err = signer.SignBTCSettlement(BTCSettlementRequest{
		Tx:             tx,
		Fees:           fees,
		Escrow:         escrow,
		MaintainerAddr: testMaintainerAddr,
		InputIndex:     0,
		PrivateKey:     key,
	})
	if err == nil {
		t.Fatalf("signer must refuse under-paid maintainer fee, but signed it")
	}
	if !strings.Contains(err.Error(), "maintainer fee") {
		t.Fatalf("unexpected error: %v (wanted mention of maintainer fee)", err)
	}
}

// TestSignBTCSettlement_EmptyMaintainerAddrFails: canonical anchor missing.
func TestSignBTCSettlement_EmptyMaintainerAddrFails(t *testing.T) {
	escrow, tx, fees := makeTestEscrowAndTx(t, 300)
	signer := NewSigner(nil, nil)
	key := makeTestKey(t)

	_, err := signer.SignBTCSettlement(BTCSettlementRequest{
		Tx:             tx,
		Fees:           fees,
		Escrow:         escrow,
		MaintainerAddr: "", // signer MUST refuse without canonical anchor
		InputIndex:     0,
		PrivateKey:     key,
	})
	if err == nil {
		t.Fatalf("signer must refuse with empty maintainer address, but signed")
	}
}
