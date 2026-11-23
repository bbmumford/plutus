/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"github.com/bbmumford/plutus/witness"
)

// --- selector sanity ----------------------------------------------------
//
// Known-good selectors from the Multicall3 source:
//   aggregate3((address,bool,bytes)[])           => 0x82ad56cb
//   aggregate3Value((address,bool,uint256,bytes)[]) => 0x174dea71
// These are independently verifiable via cast sig-event or keccak-256 of
// the canonical signature.

func TestAggregate3SelectorMatchesKnownValue(t *testing.T) {
	got := hex.EncodeToString(selectorAggregate3)
	if got != "82ad56cb" {
		t.Fatalf("aggregate3 selector = %s, want 82ad56cb", got)
	}
}

func TestAggregate3ValueSelectorMatchesKnownValue(t *testing.T) {
	got := hex.EncodeToString(selectorAggregate3Value)
	if got != "174dea71" {
		t.Fatalf("aggregate3Value selector = %s, want 174dea71", got)
	}
}

// --- config validation --------------------------------------------------

func TestNewEVMPayoutBuilder_DefaultsMulticall3Address(t *testing.T) {
	b, err := NewEVMPayoutBuilder(EVMPayoutBuilderConfig{
		ChainID:    "polygon",
		EVMChainID: 137,
		Currency:   "POL",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.EqualFold(b.Multicall3Address, DefaultMulticall3Address) {
		t.Fatalf("Multicall3Address = %s, want default %s", b.Multicall3Address, DefaultMulticall3Address)
	}
}

func TestNewEVMPayoutBuilder_ERC20RequiresTokenAddress(t *testing.T) {
	_, err := NewEVMPayoutBuilder(EVMPayoutBuilderConfig{
		ChainID:    "polygon",
		EVMChainID: 137,
		Currency:   "USDC",
		IsERC20:    true,
	})
	if err == nil {
		t.Fatalf("expected error when IsERC20 with empty token address")
	}
}

func TestNewEVMPayoutBuilder_RejectsMissingChainID(t *testing.T) {
	_, err := NewEVMPayoutBuilder(EVMPayoutBuilderConfig{
		EVMChainID: 137,
		Currency:   "POL",
	})
	if err == nil {
		t.Fatalf("expected error for missing chainID")
	}
}

func TestNewEVMPayoutBuilder_RejectsZeroEVMChainID(t *testing.T) {
	_, err := NewEVMPayoutBuilder(EVMPayoutBuilderConfig{
		ChainID:  "polygon",
		Currency: "POL",
	})
	if err == nil {
		t.Fatalf("expected error for zero EVM chain ID")
	}
}

// --- build: empty payouts ---------------------------------------------------

func TestBuildBatchPayout_EmptyPayoutsReturnsError(t *testing.T) {
	b := mustBuilder(t, "polygon", 137, "POL", false, "")
	_, err := b.BuildBatchPayout("0xpool", nil, true)
	if err == nil {
		t.Fatalf("expected error for empty payouts")
	}
}

// --- build: native single ---------------------------------------------------

func TestBuildBatchPayout_SingleNativePayout(t *testing.T) {
	b := mustBuilder(t, "polygon", 137, "POL", false, "")
	payouts := []witness.Payout{
		{
			WitnessAddr: "0x1111111111111111111111111111111111111111",
			Amount:      big.NewInt(1_000_000_000_000_000_000), // 1 POL (18 dec)
			ChainID:     "polygon",
			Currency:    "POL",
		},
	}
	batch, err := b.BuildBatchPayout("0xpool0000000000000000000000000000000000000", payouts, true)
	if err != nil {
		t.Fatalf("BuildBatchPayout: %v", err)
	}
	if batch.Kind != witness.BatchKindEVMMulticall3 {
		t.Fatalf("batch kind = %v, want BatchKindEVMMulticall3", batch.Kind)
	}
	if batch.ChainID != "polygon" {
		t.Fatalf("batch chainID = %s", batch.ChainID)
	}

	env, err := UnmarshalEVMBatchEnvelope(batch.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEVMBatchEnvelope: %v", err)
	}
	if !strings.EqualFold(env.To, DefaultMulticall3Address) {
		t.Fatalf("envelope To = %s, want %s", env.To, DefaultMulticall3Address)
	}
	// Total value must equal the sum of native payouts.
	if env.Value.Cmp(big.NewInt(1_000_000_000_000_000_000)) != 0 {
		t.Fatalf("envelope Value = %s, want 1e18", env.Value.String())
	}
	// Data must start with aggregate3Value selector.
	if !bytes.HasPrefix(env.Data, selectorAggregate3Value) {
		t.Fatalf("data does not start with aggregate3Value selector; got prefix %x", env.Data[:4])
	}
	// Decode the array and verify the one tuple encodes our recipient.
	tuples := mustDecodeAggregate3Value(t, env.Data)
	if len(tuples) != 1 {
		t.Fatalf("decoded %d tuples, want 1", len(tuples))
	}
	if !strings.EqualFold(tuples[0].target, "0x1111111111111111111111111111111111111111") {
		t.Fatalf("tuple[0] target = %s", tuples[0].target)
	}
	if tuples[0].allowFailure {
		t.Fatalf("tuple[0] allowFailure = true, want false")
	}
	if tuples[0].value.Cmp(big.NewInt(1_000_000_000_000_000_000)) != 0 {
		t.Fatalf("tuple[0] value = %s", tuples[0].value.String())
	}
	if len(tuples[0].callData) != 0 {
		t.Fatalf("tuple[0] callData len = %d, want 0", len(tuples[0].callData))
	}
}

// --- build: native multi ---------------------------------------------------

func TestBuildBatchPayout_MultiNativePayout(t *testing.T) {
	b := mustBuilder(t, "ethereum", 1, "ETH", false, "")
	payouts := []witness.Payout{
		{WitnessAddr: "0x1111111111111111111111111111111111111111", Amount: big.NewInt(100), ChainID: "ethereum", Currency: "ETH"},
		{WitnessAddr: "0x2222222222222222222222222222222222222222", Amount: big.NewInt(200), ChainID: "ethereum", Currency: "ETH"},
		{WitnessAddr: "0x3333333333333333333333333333333333333333", Amount: big.NewInt(300), ChainID: "ethereum", Currency: "ETH"},
		{WitnessAddr: "0x4444444444444444444444444444444444444444", Amount: big.NewInt(400), ChainID: "ethereum", Currency: "ETH"},
		{WitnessAddr: "0x5555555555555555555555555555555555555555", Amount: big.NewInt(500), ChainID: "ethereum", Currency: "ETH"},
	}
	batch, err := b.BuildBatchPayout("0xpool", payouts, true)
	if err != nil {
		t.Fatalf("BuildBatchPayout: %v", err)
	}
	env, err := UnmarshalEVMBatchEnvelope(batch.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEVMBatchEnvelope: %v", err)
	}
	// Sum of values should be 100+200+300+400+500 = 1500.
	wantTotal := big.NewInt(1500)
	if env.Value.Cmp(wantTotal) != 0 {
		t.Fatalf("envelope Value = %s, want %s", env.Value.String(), wantTotal.String())
	}
	tuples := mustDecodeAggregate3Value(t, env.Data)
	if len(tuples) != 5 {
		t.Fatalf("decoded %d tuples, want 5", len(tuples))
	}
	for i, want := range []int64{100, 200, 300, 400, 500} {
		if tuples[i].value.Cmp(big.NewInt(want)) != 0 {
			t.Fatalf("tuple[%d] value = %s, want %d", i, tuples[i].value.String(), want)
		}
	}
	// Gas estimate should be baseGasOverhead + multicallOverhead + 5*perRecipientGas.
	wantGas := baseGasOverhead + multicallOverhead + 5*perRecipientGas
	if env.GasLimit != wantGas {
		t.Fatalf("gasLimit = %d, want %d", env.GasLimit, wantGas)
	}
}

// --- build: ERC20 ---------------------------------------------------

func TestBuildBatchPayout_ERC20(t *testing.T) {
	tokenAddr := "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359" // Polygon USDC
	b := mustBuilder(t, "polygon", 137, "USDC", true, tokenAddr)

	recipient := "0xdeaDBEEFDEADbeefdEadBeefdeADbeEFDEADBEEF"
	amount := big.NewInt(12_500_000) // 12.5 USDC (6 dec)
	payouts := []witness.Payout{
		{WitnessAddr: recipient, Amount: amount, ChainID: "polygon", Currency: "USDC"},
	}
	batch, err := b.BuildBatchPayout("0xpool", payouts, true)
	if err != nil {
		t.Fatalf("BuildBatchPayout: %v", err)
	}
	env, err := UnmarshalEVMBatchEnvelope(batch.Payload)
	if err != nil {
		t.Fatalf("UnmarshalEVMBatchEnvelope: %v", err)
	}
	// ERC20 path: tx value must be zero.
	if env.Value.Sign() != 0 {
		t.Fatalf("ERC20 envelope Value = %s, want 0", env.Value.String())
	}
	if !bytes.HasPrefix(env.Data, selectorAggregate3) {
		t.Fatalf("ERC20 data prefix %x, want aggregate3 selector", env.Data[:4])
	}
	tuples := mustDecodeAggregate3ERC20(t, env.Data)
	if len(tuples) != 1 {
		t.Fatalf("decoded %d tuples, want 1", len(tuples))
	}
	if !strings.EqualFold(tuples[0].target, tokenAddr) {
		t.Fatalf("ERC20 tuple target = %s, want %s", tuples[0].target, tokenAddr)
	}
	// callData = transfer selector (4) + padded recipient (32) + padded amount (32) = 68 bytes
	if len(tuples[0].callData) != 68 {
		t.Fatalf("ERC20 callData len = %d, want 68", len(tuples[0].callData))
	}
	if !bytes.HasPrefix(tuples[0].callData, selectorTransfer) {
		t.Fatalf("callData prefix %x, want transfer selector %x", tuples[0].callData[:4], selectorTransfer)
	}
	// Decode the transfer args.
	toArg := tuples[0].callData[4:36]
	amtArg := tuples[0].callData[36:68]
	wantTo := strings.ToLower(strings.TrimPrefix(recipient, "0x"))
	gotTo := hex.EncodeToString(toArg[12:]) // right-aligned address
	if gotTo != wantTo {
		t.Fatalf("transfer recipient = %s, want %s", gotTo, wantTo)
	}
	gotAmt := new(big.Int).SetBytes(amtArg)
	if gotAmt.Cmp(amount) != 0 {
		t.Fatalf("transfer amount = %s, want %s", gotAmt.String(), amount.String())
	}
}

// --- build: individual mode (useMulticall3 = false) -----------------------

func TestBuildBatchPayout_Individual_NativeMulti(t *testing.T) {
	b := mustBuilder(t, "ethereum", 1, "ETH", false, "")
	poolAddr := "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
	payouts := []witness.Payout{
		{WitnessAddr: "0x1111111111111111111111111111111111111111", Amount: big.NewInt(100), ChainID: "ethereum", Currency: "ETH"},
		{WitnessAddr: "0x2222222222222222222222222222222222222222", Amount: big.NewInt(200), ChainID: "ethereum", Currency: "ETH"},
		{WitnessAddr: "0x3333333333333333333333333333333333333333", Amount: big.NewInt(300), ChainID: "ethereum", Currency: "ETH"},
	}
	batch, err := b.BuildBatchPayout(poolAddr, payouts, false)
	if err != nil {
		t.Fatalf("BuildBatchPayout: %v", err)
	}
	if batch.Kind != witness.BatchKindEVMIndividual {
		t.Fatalf("kind=%v want BatchKindEVMIndividual", batch.Kind)
	}
	if batch.Payload != nil {
		t.Errorf("Payload should be nil for individual mode, got %d bytes", len(batch.Payload))
	}
	if len(batch.ItemPayloads) != len(payouts) {
		t.Fatalf("ItemPayloads=%d want %d", len(batch.ItemPayloads), len(payouts))
	}
	if len(batch.Items) != len(payouts) {
		t.Fatalf("Items=%d want %d", len(batch.Items), len(payouts))
	}

	for i, raw := range batch.ItemPayloads {
		env, err := UnmarshalEVMBatchEnvelope(raw)
		if err != nil {
			t.Fatalf("item %d unmarshal: %v", i, err)
		}
		// Native transfer: to=recipient, value=amount, data=empty.
		if !strings.EqualFold(env.To, payouts[i].WitnessAddr) {
			t.Errorf("item %d To=%s want %s", i, env.To, payouts[i].WitnessAddr)
		}
		if env.Value.Cmp(payouts[i].Amount) != 0 {
			t.Errorf("item %d Value=%s want %s", i, env.Value, payouts[i].Amount)
		}
		if len(env.Data) != 0 {
			t.Errorf("item %d Data should be empty for native transfer, got %d bytes", i, len(env.Data))
		}
		if env.EVMChainID != 1 {
			t.Errorf("item %d EVMChainID=%d want 1", i, env.EVMChainID)
		}
		if env.From != poolAddr {
			t.Errorf("item %d From=%q want %q", i, env.From, poolAddr)
		}
		if env.NonceSet {
			t.Errorf("item %d should have unset Nonce prior to finalizer", i)
		}
		if env.GasPrice != nil && env.GasPrice.Sign() > 0 {
			t.Errorf("item %d should have unset GasPrice prior to finalizer, got %v", i, env.GasPrice)
		}
	}
}

func TestBuildBatchPayout_Individual_ERC20(t *testing.T) {
	tokenAddr := "0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359"
	b := mustBuilder(t, "polygon", 137, "USDC", true, tokenAddr)
	poolAddr := "0xAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAaAa"
	recipients := []string{
		"0x1111111111111111111111111111111111111111",
		"0x2222222222222222222222222222222222222222",
		"0x3333333333333333333333333333333333333333",
	}
	amounts := []*big.Int{
		big.NewInt(1_000_000),
		big.NewInt(2_000_000),
		big.NewInt(3_000_000),
	}
	payouts := make([]witness.Payout, len(recipients))
	for i := range recipients {
		payouts[i] = witness.Payout{
			WitnessAddr: recipients[i],
			Amount:      amounts[i],
			ChainID:     "polygon",
			Currency:    "USDC",
		}
	}
	batch, err := b.BuildBatchPayout(poolAddr, payouts, false)
	if err != nil {
		t.Fatalf("BuildBatchPayout: %v", err)
	}
	if batch.Kind != witness.BatchKindEVMIndividual {
		t.Fatalf("kind=%v want BatchKindEVMIndividual", batch.Kind)
	}
	if len(batch.ItemPayloads) != len(payouts) {
		t.Fatalf("ItemPayloads=%d want %d", len(batch.ItemPayloads), len(payouts))
	}
	for i, raw := range batch.ItemPayloads {
		env, err := UnmarshalEVMBatchEnvelope(raw)
		if err != nil {
			t.Fatalf("item %d unmarshal: %v", i, err)
		}
		// ERC20 transfer: to=token, value=0, data=transfer(recipient, amount).
		if !strings.EqualFold(env.To, tokenAddr) {
			t.Errorf("item %d To=%s want %s", i, env.To, tokenAddr)
		}
		if env.Value.Sign() != 0 {
			t.Errorf("item %d Value=%s want 0", i, env.Value)
		}
		if len(env.Data) != 68 {
			t.Fatalf("item %d Data len=%d want 68 (4 selector + 32 addr + 32 uint256)", i, len(env.Data))
		}
		if !bytes.HasPrefix(env.Data, selectorTransfer) {
			t.Errorf("item %d Data prefix=%x want %x", i, env.Data[:4], selectorTransfer)
		}
		gotRecipientHex := hex.EncodeToString(env.Data[4+12 : 4+32])
		wantRecipientHex := strings.ToLower(strings.TrimPrefix(recipients[i], "0x"))
		if gotRecipientHex != wantRecipientHex {
			t.Errorf("item %d transfer recipient=%s want %s", i, gotRecipientHex, wantRecipientHex)
		}
		gotAmount := new(big.Int).SetBytes(env.Data[4+32 : 4+64])
		if gotAmount.Cmp(amounts[i]) != 0 {
			t.Errorf("item %d transfer amount=%s want %s", i, gotAmount, amounts[i])
		}
	}
}

func TestBuildBatchPayout_Individual_EmptyPayouts(t *testing.T) {
	b := mustBuilder(t, "polygon", 137, "POL", false, "")
	if _, err := b.BuildBatchPayout("0xpool", nil, false); err == nil {
		t.Fatal("expected error for empty payouts in individual mode")
	}
}

// --- invalid inputs --------------------------------------------------------

func TestBuildBatchPayout_RejectsInvalidAddress(t *testing.T) {
	b := mustBuilder(t, "polygon", 137, "POL", false, "")
	payouts := []witness.Payout{
		{WitnessAddr: "notanaddress", Amount: big.NewInt(1), ChainID: "polygon", Currency: "POL"},
	}
	_, err := b.BuildBatchPayout("0xpool", payouts, true)
	if err == nil {
		t.Fatalf("expected error for invalid address")
	}
}

func TestBuildBatchPayout_RejectsNonPositiveAmount(t *testing.T) {
	b := mustBuilder(t, "polygon", 137, "POL", false, "")
	payouts := []witness.Payout{
		{WitnessAddr: "0x1111111111111111111111111111111111111111", Amount: big.NewInt(0), ChainID: "polygon", Currency: "POL"},
	}
	_, err := b.BuildBatchPayout("0xpool", payouts, true)
	if err == nil {
		t.Fatalf("expected error for zero amount")
	}
}

// --- registry ---------------------------------------------------------

func TestRegisterEVMPayoutBuilders_AttachesBuilders(t *testing.T) {
	reg := newPayoutBuilderRegistry()
	if err := RegisterDefaultEVMPayoutBuilders(reg); err != nil {
		t.Fatalf("RegisterDefaultEVMPayoutBuilders: %v", err)
	}
	cases := []struct {
		chain, currency string
	}{
		{"polygon", "POL"},
		{"ethereum", "ETH"},
		{"arbitrum", "ETH"},
		{"bsc", "BNB"},
		{"polygon", "USDC"},
		{"ethereum", "USDC"},
	}
	for _, tc := range cases {
		pb, err := reg.ResolvePayoutBuilder(tc.chain, tc.currency)
		if err != nil {
			t.Fatalf("ResolvePayoutBuilder(%s,%s): %v", tc.chain, tc.currency, err)
		}
		if pb == nil {
			t.Fatalf("ResolvePayoutBuilder(%s,%s) returned nil", tc.chain, tc.currency)
		}
	}
}

func TestRegisterEVMPayoutBuilders_UnknownChainReturnsError(t *testing.T) {
	reg := newPayoutBuilderRegistry()
	if err := RegisterDefaultEVMPayoutBuilders(reg); err != nil {
		t.Fatalf("RegisterDefaultEVMPayoutBuilders: %v", err)
	}
	if _, err := reg.ResolvePayoutBuilder("dogecoin-evm", "DOGE"); err == nil {
		t.Fatalf("expected error for unknown chain")
	}
}

// --- helpers ---------------------------------------------------------

func mustBuilder(t *testing.T, chainID string, evmID uint64, currency string, isERC20 bool, tokenAddr string) *EVMPayoutBuilder {
	t.Helper()
	b, err := NewEVMPayoutBuilder(EVMPayoutBuilderConfig{
		ChainID:      chainID,
		EVMChainID:   evmID,
		Currency:     currency,
		IsERC20:      isERC20,
		TokenAddress: tokenAddr,
	})
	if err != nil {
		t.Fatalf("NewEVMPayoutBuilder: %v", err)
	}
	return b
}

// newPayoutBuilderRegistry returns a fresh local registry for tests.
func newPayoutBuilderRegistry() *PayoutBuilderRegistry {
	return NewPayoutBuilderRegistry()
}

// decodedTuple3Value is the parsed form of one Call3Value tuple.
type decodedTuple3Value struct {
	target       string
	allowFailure bool
	value        *big.Int
	callData     []byte
}

// decodedTuple3 is the parsed form of one Call3 tuple.
type decodedTuple3 struct {
	target       string
	allowFailure bool
	callData     []byte
}

// mustDecodeAggregate3Value parses the ABI-encoded body of an aggregate3Value
// call into its constituent tuples. Assumes input starts with the 4-byte
// selector. Follows the Solidity ABI spec precisely:
//
//	body[0:32]   = outer offset to array (always 0x20 for our layout)
//	body[32:64]  = array length N
//	array body starts at body[64:]
//	  body[64:64+N*32]      = N head-offset words (each relative to array body start)
//	  body[64+N*32:...]     = tuple encodings
//	Within each tuple encoding:
//	  t[0:32]  = address
//	  t[32:64] = bool
//	  t[64:96] = uint256 value
//	  t[96:128]= bytes offset (relative to start of THIS tuple)
//	  (tail at bytesOffset): length word + padded data
func mustDecodeAggregate3Value(t *testing.T, data []byte) []decodedTuple3Value {
	t.Helper()
	if len(data) < 4+32+32 {
		t.Fatalf("data too short: %d bytes", len(data))
	}
	body := data[4:]
	arrayLen := new(big.Int).SetBytes(body[32:64]).Int64()
	arrayBody := body[64:]
	tuples := make([]decodedTuple3Value, 0, arrayLen)
	for i := int64(0); i < arrayLen; i++ {
		headOff := new(big.Int).SetBytes(arrayBody[i*32 : (i+1)*32]).Int64()
		tuple := arrayBody[headOff:]
		target := "0x" + hex.EncodeToString(tuple[12:32])
		allowFailure := tuple[32+31] == 1
		value := new(big.Int).SetBytes(tuple[64:96])
		bytesOff := new(big.Int).SetBytes(tuple[96:128]).Int64()
		// bytesOff is relative to the start of THIS tuple.
		cdLen := new(big.Int).SetBytes(tuple[bytesOff : bytesOff+32]).Int64()
		var cd []byte
		if cdLen > 0 {
			cd = make([]byte, cdLen)
			copy(cd, tuple[bytesOff+32:bytesOff+32+cdLen])
		}
		tuples = append(tuples, decodedTuple3Value{
			target:       target,
			allowFailure: allowFailure,
			value:        value,
			callData:     cd,
		})
	}
	return tuples
}

// mustDecodeAggregate3ERC20 parses the ABI-encoded body of an aggregate3 call
// into its constituent tuples. Follows the same two-level head/tail layout as
// mustDecodeAggregate3Value but with a 3-field tuple (no value).
func mustDecodeAggregate3ERC20(t *testing.T, data []byte) []decodedTuple3 {
	t.Helper()
	if len(data) < 4+32+32 {
		t.Fatalf("data too short: %d bytes", len(data))
	}
	body := data[4:]
	arrayLen := new(big.Int).SetBytes(body[32:64]).Int64()
	arrayBody := body[64:]
	tuples := make([]decodedTuple3, 0, arrayLen)
	for i := int64(0); i < arrayLen; i++ {
		headOff := new(big.Int).SetBytes(arrayBody[i*32 : (i+1)*32]).Int64()
		tuple := arrayBody[headOff:]
		target := "0x" + hex.EncodeToString(tuple[12:32])
		allowFailure := tuple[32+31] == 1
		bytesOff := new(big.Int).SetBytes(tuple[64:96]).Int64()
		cdLen := new(big.Int).SetBytes(tuple[bytesOff : bytesOff+32]).Int64()
		var cd []byte
		if cdLen > 0 {
			cd = make([]byte, cdLen)
			copy(cd, tuple[bytesOff+32:bytesOff+32+cdLen])
		}
		tuples = append(tuples, decodedTuple3{
			target:       target,
			allowFailure: allowFailure,
			callData:     cd,
		})
	}
	return tuples
}
