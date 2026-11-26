/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package btc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/bbmumford/plutus/adapter"
	"github.com/bbmumford/plutus/canonical"
	"github.com/bbmumford/plutus/settle"
)

// BTCAdapter implements adapter.CurrencyAdapter for Bitcoin (mainnet or testnet).
//
// DIVERGENCES FROM THE EVM MODEL:
//
//  1. Bitcoin has no smart-contract Protocol Registry. The canonical
//     maintainer payout address is embedded in canonical.MaintainerBTCAddress
//     at build time (from keys/maintainer-btc-addr.txt).
//
//  2. Bitcoin Script cannot constrain output structure (no covenants on
//     mainnet), so the maintainer-fee defence is enforced at the SIGNER
//     layer (wallet/signer_btc.go). Honesty assumption: with 2-of-3 multisig
//     (buyer, seller, arbitrator), at least one canonical-Plutus co-signer
//     will refuse to sign a release tx that omits the maintainer fee.
//
//  3. "Escrow address" in the EVM interface becomes a P2WSH bech32 address
//     in BTC, derived from (buyer, seller, arbitrator pubkeys, timeout).
//     The adapter keeps the escrow's script + funding UTXO in memory keyed
//     by that address so that later release/refund calls can rebuild the tx.
type BTCAdapter struct {
	client         *BTCClient
	feeEstimator   *BTCFeeEstimator
	utxoSelector   *UTXOSelector
	hrp            string // "bc" (mainnet) or "tb" (testnet)
	chainID        string
	maintainerAddr string

	mu      sync.RWMutex
	escrows map[string]*BTCEscrowState // key: P2WSH address
}

// BTCEscrowState tracks a single P2WSH escrow's lifecycle.
type BTCEscrowState struct {
	// Address is the P2WSH bech32 address of the escrow.
	Address string
	// WitnessScript is the compiled 2-of-3+CLTV redeem script.
	WitnessScript []byte
	// BuyerPubKey / SellerPubKey / ArbitratorPubKey are compressed 33-byte pubkeys.
	BuyerPubKey      []byte
	SellerPubKey     []byte
	ArbitratorPubKey []byte
	// TimeoutBlocks is the CLTV deadline (absolute block height).
	TimeoutBlocks uint32

	// FundingTxID / FundingVout / FundingAmount identify the funding UTXO
	// once the escrow has been funded. Zero before funding.
	FundingTxID   string
	FundingVout   uint32
	FundingAmount *big.Int // satoshis

	// Status follows adapter.EscrowStatus.
	Status adapter.EscrowStatus

	// Buyer / Seller payout addresses (for release/refund construction).
	BuyerPayoutAddr  string
	SellerPayoutAddr string

	// WitnessPayoutAddr is the bech32 destination that receives the witness
	// fee on release. Empty means "absorb witness fee into recipient".
	WitnessPayoutAddr string

	// ServicePayoutAddr is the bech32 destination that receives the service
	// provider fee on release. Empty means "absorb into recipient".
	ServicePayoutAddr string

	// ArbitratorPayoutAddr is the bech32 destination that receives the
	// arbitrator fee on disputed release / SettleWithRuling. Empty means
	// "absorb into recipient" (only valid when there is no dispute).
	ArbitratorPayoutAddr string

	// CreatedAt / TimeoutAt (block heights) mirror adapter.EscrowState.
	CreatedAt uint64
	TimeoutAt uint64
}

// BTCAdapterConfig configures a new BTCAdapter instance.
type BTCAdapterConfig struct {
	// Transport is the mesh RPC transport.
	Transport MeshTransport
	// Network is "mainnet" (HRP "bc"), "testnet" (HRP "tb"), or "regtest" ("bcrt").
	Network string
	// MaintainerAddr overrides canonical.MaintainerBTCAddress. Leave empty
	// to use the canonical embedded address. Useful for tests only.
	MaintainerAddr string
}

// NewBTCAdapter creates a new BTC adapter. If the canonical maintainer BTC
// address is empty (not set during build) and no override is supplied, this
// returns an error — the safest default, since without a maintainer address
// there is nothing to enforce in the signer.
func NewBTCAdapter(cfg BTCAdapterConfig) (*BTCAdapter, error) {
	if cfg.Transport == nil {
		return nil, errors.New("btc: transport is nil")
	}

	var hrp, chainID string
	switch cfg.Network {
	case "", "mainnet":
		hrp = "bc"
		chainID = "bitcoin"
	case "testnet":
		hrp = "tb"
		chainID = "bitcoin-testnet"
	case "regtest":
		hrp = "bcrt"
		chainID = "bitcoin-regtest"
	default:
		return nil, fmt.Errorf("btc: unknown network %q", cfg.Network)
	}

	maintainerAddr := cfg.MaintainerAddr
	if maintainerAddr == "" {
		maintainerAddr = canonical.MaintainerBTCAddress
	}
	if maintainerAddr == "" {
		return nil, errors.New(
			"btc: canonical.MaintainerBTCAddress is empty — " +
				"populate canonical/keys/maintainer-btc-addr.txt and rebuild before loading the BTC adapter",
		)
	}
	// Validate the maintainer address decodes and matches our HRP.
	sw, err := DecodeSegWitAddress(maintainerAddr)
	if err != nil {
		return nil, fmt.Errorf("btc: maintainer address invalid: %w", err)
	}
	if sw.HRP != hrp {
		return nil, fmt.Errorf(
			"btc: maintainer address HRP %q does not match network %q (expected %q)",
			sw.HRP, cfg.Network, hrp,
		)
	}

	client, err := NewBTCClient(cfg.Transport)
	if err != nil {
		return nil, fmt.Errorf("btc: create client: %w", err)
	}
	// Override chainID for testnet/regtest.
	client.chainID = chainID

	feeEst, err := NewBTCFeeEstimator(client)
	if err != nil {
		return nil, fmt.Errorf("btc: create fee estimator: %w", err)
	}

	return &BTCAdapter{
		client:         client,
		feeEstimator:   feeEst,
		utxoSelector:   NewUTXOSelector(),
		hrp:            hrp,
		chainID:        chainID,
		maintainerAddr: maintainerAddr,
		escrows:        make(map[string]*BTCEscrowState),
	}, nil
}

// Chain identification.
func (a *BTCAdapter) ChainID() string  { return a.chainID }
func (a *BTCAdapter) Currency() string { return btcCurrency }
func (a *BTCAdapter) Symbol() string   { return btcSymbol }

// MaintainerAddr returns the canonical maintainer BTC address used for fee
// enforcement on this adapter.
func (a *BTCAdapter) MaintainerAddr() string { return a.maintainerAddr }

// EscrowAddress derives the P2WSH bech32 address for a given set of escrow
// parameters (buyer/seller/arbitrator pubkeys + timeout). Exposed separately
// so the SDK can compute the funding destination before calling FundEscrow.
func (a *BTCAdapter) EscrowAddress(buyerPub, sellerPub, arbPub []byte, timeoutBlocks uint32) (string, error) {
	script, err := CreateEscrowScript(buyerPub, sellerPub, arbPub, timeoutBlocks)
	if err != nil {
		return "", err
	}
	return EncodeSegWitAddress(a.hrp, 0, script.ScriptHash[:])
}

// registerEscrow persists the P2WSH script + pubkeys keyed by address so
// later release/refund calls can rebuild the spend tx.
func (a *BTCAdapter) registerEscrow(state *BTCEscrowState) {
	a.mu.Lock()
	a.escrows[state.Address] = state
	a.mu.Unlock()
}

// GetEscrow returns the cached escrow state for an address, or nil.
func (a *BTCAdapter) GetEscrow(address string) *BTCEscrowState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	s, ok := a.escrows[address]
	if !ok {
		return nil
	}
	return s
}

// ConstructEscrow returns the P2WSH redeem script as an UnsignedTx payload.
// The caller funds the resulting bech32 address externally (from a regular
// wallet). EscrowParams must include buyer/seller/arbitrator pubkeys encoded
// into the WitnessHashes field as [buyerPub, sellerPub, arbitratorPub] —
// this is the bridge between the chain-agnostic interface and BTC's per-key
// model.
func (a *BTCAdapter) ConstructEscrow(params adapter.EscrowParams) (*adapter.UnsignedTx, error) {
	if len(params.WitnessHashes) < 3 {
		return nil, errors.New(
			"btc: ConstructEscrow requires WitnessHashes=[buyerPub, sellerPub, arbitratorPub] (3 compressed pubkeys)",
		)
	}
	buyerPub := params.WitnessHashes[0]
	sellerPub := params.WitnessHashes[1]
	arbPub := params.WitnessHashes[2]

	timeoutBlocks := uint32(params.TimeoutSeconds / 600) // ~10 min/block
	if timeoutBlocks == 0 {
		timeoutBlocks = 144 // ~1 day default
	}
	script, err := CreateEscrowScript(buyerPub, sellerPub, arbPub, timeoutBlocks)
	if err != nil {
		return nil, fmt.Errorf("btc: build escrow script: %w", err)
	}
	addr, err := EncodeSegWitAddress(a.hrp, 0, script.ScriptHash[:])
	if err != nil {
		return nil, fmt.Errorf("btc: encode P2WSH address: %w", err)
	}

	a.registerEscrow(&BTCEscrowState{
		Address:              addr,
		WitnessScript:        script.Script,
		BuyerPubKey:          buyerPub,
		SellerPubKey:         sellerPub,
		ArbitratorPubKey:     arbPub,
		TimeoutBlocks:        timeoutBlocks,
		FundingAmount:        new(big.Int),
		Status:               adapter.EscrowStatusPending,
		BuyerPayoutAddr:      params.Buyer,
		SellerPayoutAddr:     params.Seller,
		WitnessPayoutAddr:    params.WitnessPayout,
		ServicePayoutAddr:    params.ServiceProviderPayout,
		ArbitratorPayoutAddr: params.ArbitratorPayout,
		TimeoutAt:            uint64(timeoutBlocks),
	})

	return &adapter.UnsignedTx{
		ChainID:    a.chainID,
		To:         addr,
		Amount:     new(big.Int).Set(params.Amount),
		Payload:    script.Script,
		EscrowAddr: addr,
	}, nil
}

// FundEscrow returns an UnsignedTx representing the funding pay-to-P2WSH
// operation. The actual tx is built by the buyer's regular wallet (BTC
// doesn't have a fund-contract semantic like ERC-20 approve); we just return
// enough info for the wallet to spend to the escrow address.
func (a *BTCAdapter) FundEscrow(escrowAddr string, amount *big.Int) (*adapter.UnsignedTx, error) {
	if escrowAddr == "" {
		return nil, errors.New("btc: escrow address is empty")
	}
	if amount == nil || amount.Sign() <= 0 {
		return nil, errors.New("btc: fund amount must be positive")
	}
	script, err := PkScriptForAddress(escrowAddr)
	if err != nil {
		return nil, fmt.Errorf("btc: fund escrow: %w", err)
	}
	return &adapter.UnsignedTx{
		ChainID:    a.chainID,
		To:         escrowAddr,
		Amount:     new(big.Int).Set(amount),
		Payload:    script,
		EscrowAddr: escrowAddr,
	}, nil
}

// ReleaseEscrow builds the 2-of-3 release transaction that pays the seller,
// maintainer, and any other fee parties. The returned UnsignedTx carries the
// serialized tx in Payload — but it has no witness stack yet; the signer
// must produce two signatures (buyer+seller or buyer+arbitrator) and plug
// them in via EscrowScript.MultisigWitness before broadcast.
func (a *BTCAdapter) ReleaseEscrow(escrowAddr string, params adapter.ReleaseParams) (*adapter.UnsignedTx, error) {
	state := a.GetEscrow(escrowAddr)
	if state == nil {
		return nil, fmt.Errorf("btc: no cached escrow state for %s (call ConstructEscrow first)", escrowAddr)
	}
	if state.FundingTxID == "" {
		return nil, fmt.Errorf("btc: escrow %s is not yet funded", escrowAddr)
	}
	if state.SellerPayoutAddr == "" {
		return nil, fmt.Errorf("btc: escrow %s has no seller payout address", escrowAddr)
	}

	// Estimate fee rate.
	feeEst, err := a.feeEstimator.Estimate(context.Background(), FeeMedium)
	if err != nil || feeEst == nil {
		// Fall back to a conservative default if estimator fails.
		feeEst = &FeeEstimate{SatPerVByte: 10.0}
	}

	tx, err := BuildReleaseTx(BuildReleaseTxParams{
		Escrow: *state,
		Fees:   params.Fees,
		Payouts: ReleasePayouts{
			RecipientAddr:  state.SellerPayoutAddr,
			MaintainerAddr: a.maintainerAddr,
			WitnessAddr:    state.WitnessPayoutAddr,
			ServiceAddr:    state.ServicePayoutAddr,
			ArbitratorAddr: state.ArbitratorPayoutAddr,
		},
		FeeRateSatPerVByte: feeEst.SatPerVByte,
		Sequence:           0xFFFFFFFE,
	})
	if err != nil {
		return nil, fmt.Errorf("btc: build release tx: %w", err)
	}

	raw, err := tx.Serialize()
	if err != nil {
		return nil, fmt.Errorf("btc: serialize release tx: %w", err)
	}

	return &adapter.UnsignedTx{
		ChainID:    a.chainID,
		To:         state.SellerPayoutAddr,
		Amount:     new(big.Int).Set(state.FundingAmount),
		Payload:    raw,
		EscrowAddr: escrowAddr,
	}, nil
}

// DisputeEscrow marks the escrow disputed locally. Bitcoin has no on-chain
// dispute flag — the dispute is signalled off-chain via the witness mesh.
func (a *BTCAdapter) DisputeEscrow(escrowAddr string, params adapter.DisputeParams) (*adapter.UnsignedTx, error) {
	state := a.GetEscrow(escrowAddr)
	if state == nil {
		return nil, fmt.Errorf("btc: no cached escrow state for %s", escrowAddr)
	}
	a.mu.Lock()
	state.Status = adapter.EscrowStatusDisputed
	a.mu.Unlock()
	// Return an empty UnsignedTx with a hash of the dispute payload. The
	// caller broadcasts the dispute via Whisper gossip (off-chain).
	h := sha256.Sum256([]byte(params.Reason + params.DisputerAddr))
	return &adapter.UnsignedTx{
		ChainID:    a.chainID,
		To:         escrowAddr,
		Amount:     new(big.Int),
		Payload:    h[:],
		EscrowAddr: escrowAddr,
	}, nil
}

// SettleWithRuling builds a multisig tx that splits the escrow per the
// arbitrator's ruling (buyer% / seller%).
func (a *BTCAdapter) SettleWithRuling(escrowAddr string, ruling adapter.Ruling) (*adapter.UnsignedTx, error) {
	state := a.GetEscrow(escrowAddr)
	if state == nil {
		return nil, fmt.Errorf("btc: no cached escrow state for %s", escrowAddr)
	}
	if ruling.BuyerPercent+ruling.SellerPercent != 100 {
		return nil, errors.New("btc: ruling percentages must sum to 100")
	}
	if state.FundingAmount == nil || state.FundingAmount.Sign() <= 0 {
		return nil, errors.New("btc: escrow is not funded")
	}

	// Split seller proceeds per the ruling. Maintainer fee stays intact —
	// that's the non-negotiable part.
	amountSat := state.FundingAmount.Int64()
	bpsBase := big.NewInt(10000)

	// Reuse the canonical fee-calc: maintainer gets the same cut regardless.
	maintainerFee := new(big.Int).Mul(big.NewInt(amountSat), big.NewInt(500))
	maintainerFee.Div(maintainerFee, bpsBase)
	// Without a PRC call we conservatively use the cap (500 BPS = 5%).

	sellerProceeds := big.NewInt(amountSat)
	sellerProceeds.Sub(sellerProceeds, maintainerFee)
	sellerProceeds.Mul(sellerProceeds, big.NewInt(int64(ruling.SellerPercent)))
	sellerProceeds.Div(sellerProceeds, big.NewInt(100))

	fees := adapter.FeeBreakdown{
		MaintainerFee:      maintainerFee,
		ServiceProviderFee: new(big.Int),
		ArbitratorFee:      new(big.Int),
		WitnessFee:         new(big.Int),
		SellerProceeds:     sellerProceeds,
		Total:              new(big.Int).SetInt64(amountSat),
	}

	recipient := state.SellerPayoutAddr
	if ruling.BuyerPercent > ruling.SellerPercent {
		recipient = state.BuyerPayoutAddr
	}

	feeEst, err := a.feeEstimator.Estimate(context.Background(), FeeMedium)
	if err != nil || feeEst == nil {
		feeEst = &FeeEstimate{SatPerVByte: 10.0}
	}

	tx, err := BuildReleaseTx(BuildReleaseTxParams{
		Escrow: *state,
		Fees:   fees,
		Payouts: ReleasePayouts{
			RecipientAddr:  recipient,
			MaintainerAddr: a.maintainerAddr,
			WitnessAddr:    state.WitnessPayoutAddr,
			ServiceAddr:    state.ServicePayoutAddr,
			ArbitratorAddr: state.ArbitratorPayoutAddr,
		},
		FeeRateSatPerVByte: feeEst.SatPerVByte,
		Sequence:           0xFFFFFFFE,
	})
	if err != nil {
		return nil, fmt.Errorf("btc: build settle tx: %w", err)
	}
	raw, err := tx.Serialize()
	if err != nil {
		return nil, err
	}
	return &adapter.UnsignedTx{
		ChainID:    a.chainID,
		To:         recipient,
		Amount:     new(big.Int).Set(state.FundingAmount),
		Payload:    raw,
		EscrowAddr: escrowAddr,
	}, nil
}

// RefundAfterTimeout builds the CLTV-timeout refund tx (buyer-only spend).
func (a *BTCAdapter) RefundAfterTimeout(escrowAddr string) (*adapter.UnsignedTx, error) {
	state := a.GetEscrow(escrowAddr)
	if state == nil {
		return nil, fmt.Errorf("btc: no cached escrow state for %s", escrowAddr)
	}
	if state.FundingAmount == nil || state.FundingAmount.Sign() <= 0 {
		return nil, errors.New("btc: escrow is not funded")
	}
	if state.BuyerPayoutAddr == "" {
		return nil, errors.New("btc: escrow has no buyer payout address")
	}

	// Refund tx: single input → buyer output (minus mining fee).
	// No maintainer fee applies on the timeout path since the escrow never
	// successfully completed (buyer is reclaiming funds, not paying the seller).
	feeEst, err := a.feeEstimator.Estimate(context.Background(), FeeMedium)
	if err != nil || feeEst == nil {
		feeEst = &FeeEstimate{SatPerVByte: 10.0}
	}
	amountSat := state.FundingAmount.Int64()
	estVSize := EstimateTxVSize(1, 1)
	miningFee := int64(float64(estVSize) * feeEst.SatPerVByte)
	if miningFee < 1 {
		miningFee = 1
	}
	netOut := amountSat - miningFee
	if netOut < DefaultDustThreshold {
		return nil, fmt.Errorf("btc: refund %d sat below dust after %d mining fee", netOut, miningFee)
	}

	recipientScript, err := PkScriptForAddress(state.BuyerPayoutAddr)
	if err != nil {
		return nil, fmt.Errorf("btc: buyer address: %w", err)
	}
	fundingHash, err := TxIDFromDisplayHex(state.FundingTxID)
	if err != nil {
		return nil, fmt.Errorf("btc: funding txid: %w", err)
	}

	tx := NewMsgTx(2)
	tx.LockTime = state.TimeoutBlocks
	tx.AddTxIn(&TxIn{
		PreviousOutPoint: OutPoint{Hash: fundingHash, Index: state.FundingVout},
		Sequence:         0xFFFFFFFE,
		InputValue:       amountSat,
		WitnessScript:    state.WitnessScript,
	})
	tx.AddTxOut(&TxOut{Value: netOut, PkScript: recipientScript})

	raw, err := tx.Serialize()
	if err != nil {
		return nil, err
	}
	return &adapter.UnsignedTx{
		ChainID:    a.chainID,
		To:         state.BuyerPayoutAddr,
		Amount:     new(big.Int).Set(state.FundingAmount),
		Payload:    raw,
		EscrowAddr: escrowAddr,
	}, nil
}

// EscrowState returns the cached state for a P2WSH escrow.
func (a *BTCAdapter) EscrowState(escrowAddr string) (*adapter.EscrowState, error) {
	state := a.GetEscrow(escrowAddr)
	if state == nil {
		return nil, fmt.Errorf("btc: no cached escrow state for %s", escrowAddr)
	}
	return &adapter.EscrowState{
		Address:        state.Address,
		Buyer:          state.BuyerPayoutAddr,
		Seller:         state.SellerPayoutAddr,
		Amount:         new(big.Int).Set(state.FundingAmount),
		Currency:       btcCurrency,
		Status:         state.Status,
		ArbitratorAddr: "",
		CreatedAt:      state.CreatedAt,
		TimeoutAt:      state.TimeoutAt,
		PRCAddress:     "", // BTC has no PRC; canonical.MaintainerBTCAddress is the anchor.
	}, nil
}

// Balance returns the confirmed BTC balance (in satoshis) for an address.
func (a *BTCAdapter) Balance(addr string) (*big.Int, error) {
	return a.client.GetBalance(context.Background(), addr)
}

// CalculateFees answers settle.FeeCalculator's breakdown, so a fee this adapter
// reports honours the same per-role and combined BPS caps, and the same
// seller-takes-the-remainder rule, as every other settlement path.
func (a *BTCAdapter) CalculateFees(amount *big.Int, opts adapter.FeeOptions) (adapter.FeeBreakdown, error) {
	return settle.NewFeeCalculator().Calculate(amount, opts)
}

// FindFundingUTXO implements escrow.BTCMeshUTXOSource on the BTCAdapter so a
// BTCEscrowWatcher can wire it directly. It calls ListUnspent via the mesh
// transport and returns the first confirmed UTXO with at least minConf
// confirmations. The watcher iterates the result; ok=false signals "no
// qualifying UTXO yet" so it should retry.
func (a *BTCAdapter) FindFundingUTXO(ctx context.Context, address string, minConf uint32) (string, uint32, *big.Int, bool, error) {
	if address == "" {
		return "", 0, nil, false, errors.New("btc: address is empty")
	}
	utxos, err := a.client.ListUnspent(ctx, address)
	if err != nil {
		return "", 0, nil, false, err
	}
	for _, u := range utxos {
		if u.Confirmations < minConf {
			continue
		}
		if u.Value == nil || u.Value.Sign() <= 0 {
			continue
		}
		return u.TxID, u.Vout, new(big.Int).Set(u.Value), true, nil
	}
	return "", 0, nil, false, nil
}

// RecordFunding marks an escrow as funded once the mesh confirms the funding
// UTXO. Called by the SDK / witness-watch layer.
func (a *BTCAdapter) RecordFunding(address, fundingTxID string, vout uint32, amountSat *big.Int) error {
	state := a.GetEscrow(address)
	if state == nil {
		return fmt.Errorf("btc: no cached escrow state for %s", address)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	state.FundingTxID = fundingTxID
	state.FundingVout = vout
	state.FundingAmount = new(big.Int).Set(amountSat)
	state.Status = adapter.EscrowStatusFunded
	return nil
}
