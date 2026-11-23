/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/bbmumford/plutus/adapter"
	"golang.org/x/crypto/sha3"
)

// PlutusEscrow ABI function selectors (keccak256 of function signatures).
var (
	// fund() => 0xb60d4288
	selectorFund = mustDecodeHex("b60d4288")
	// release() => 0x86d1a69f
	selectorRelease = mustDecodeHex("86d1a69f")
	// dispute(address) => 0x44e18bdd
	selectorDispute = mustDecodeHex("44e18bdd")
	// settle(uint256,uint256) => 0xd0e30db0
	selectorSettle = mustDecodeHex("d0e30db0")
	// refund() => 0x590e1ae3
	selectorRefund = mustDecodeHex("590e1ae3")
	// state() => 0xc19d93fb
	selectorState = mustDecodeHex("c19d93fb")
	// buyer() => 0x7150d8ae
	selectorBuyer = mustDecodeHex("7150d8ae")
	// seller() => 0x08551a53
	selectorSeller = mustDecodeHex("08551a53")
	// amount() => 0xaa8c217c
	selectorAmount = mustDecodeHex("aa8c217c")
	// prc() => 0x966dae0e
	selectorPRC = mustDecodeHex("966dae0e")
	// arbitrator() => 0x6cc6cde1
	selectorArbitrator = mustDecodeHex("6cc6cde1")
	// funded() => 0x8d4e4083
	selectorFunded = mustDecodeHex("8d4e4083")
	// timeoutBlock() => 0x5f36e525
	selectorTimeoutBlock = mustDecodeHex("5f36e525")
)

// EscrowBinding provides Go bindings to the PlutusEscrow Solidity contract.
// All interactions go through the EVMClient (and thus the witness mesh).
type EscrowBinding struct {
	client    *EVMClient
	token     *ERC20
	prcAddr   string

	// BlockTime is the average block time in seconds for this chain.
	// Used to convert timeout durations to absolute block numbers.
	// Defaults to DefaultBlockTime (2s, suitable for Polygon).
	BlockTime uint64
}

// NewEscrowBinding creates a new escrow contract binding.
func NewEscrowBinding(client *EVMClient, token *ERC20, prcAddr string) (*EscrowBinding, error) {
	if client == nil {
		return nil, fmt.Errorf("evm/escrow: client is nil")
	}
	if token == nil {
		return nil, fmt.Errorf("evm/escrow: token is nil")
	}
	if prcAddr == "" {
		return nil, fmt.Errorf("evm/escrow: PRC address is empty")
	}
	return &EscrowBinding{
		client:    client,
		token:     token,
		prcAddr:   prcAddr,
		BlockTime: DefaultBlockTime,
	}, nil
}

// DefaultBlockTime is the default block time in seconds used when converting
// timeout durations to absolute block numbers. Polygon ~2s, Ethereum ~12s.
// Override via EscrowBinding.BlockTime for chain-specific values.
const DefaultBlockTime uint64 = 2

// ConstructEscrow builds the deployment transaction data for a new PlutusEscrow
// contract. The bytecode includes constructor arguments ABI-encoded at the end.
//
// Solidity constructor params (11 args):
//   _prc, _token, _buyer, _seller, _amount, _timeoutBlock,
//   _receiptHash, _witnessHashes[], _serviceProviderBPS,
//   _serviceProviderPayout, _arbitratorBPS
func (b *EscrowBinding) ConstructEscrow(params adapter.EscrowParams) (*adapter.UnsignedTx, error) {
	return b.ConstructEscrowCtx(context.Background(), params)
}

// ConstructEscrowCtx is like ConstructEscrow but accepts an explicit context
// for the block number query instead of using context.Background().
func (b *EscrowBinding) ConstructEscrowCtx(ctx context.Context, params adapter.EscrowParams) (*adapter.UnsignedTx, error) {
	if params.Buyer == "" {
		return nil, fmt.Errorf("evm/escrow: buyer address is empty")
	}
	if params.Seller == "" {
		return nil, fmt.Errorf("evm/escrow: seller address is empty")
	}
	if params.Amount == nil || params.Amount.Sign() <= 0 {
		return nil, fmt.Errorf("evm/escrow: amount must be positive")
	}
	if params.PRCAddress == "" {
		return nil, fmt.Errorf("evm/escrow: PRC address is empty")
	}

	// Convert timeout duration (seconds) to an absolute future block number.
	blockTime := b.BlockTime
	if blockTime == 0 {
		blockTime = DefaultBlockTime
	}
	currentBlock, err := b.client.BlockNumber(ctx)
	if err != nil {
		return nil, fmt.Errorf("evm/escrow: query current block number: %w", err)
	}
	timeoutBlock := currentBlock + (params.TimeoutSeconds / blockTime)

	// Receipt hash (single bytes32).
	receiptPadded := make([]byte, 32)
	if len(params.ReceiptHash) > 0 {
		copy(receiptPadded, params.ReceiptHash)
	}

	// Encode constructor arguments matching the Solidity constructor:
	//   constructor(address _prc, address _token, address _buyer, address _seller,
	//               uint256 _amount, uint256 _timeoutBlock, bytes32 _receiptHash,
	//               bytes32[] _witnessHashes, uint256 _serviceProviderBPS,
	//               address _serviceProviderPayout, uint256 _arbitratorBPS)
	//
	// Static params occupy slots 0-10. _witnessHashes is dynamic so its slot
	// holds an offset pointer; the actual array data follows the static area.

	// Offset to the dynamic witness hashes array data. There are 11 slots of
	// static parameters (0-10), so the dynamic data starts at byte 11*32 = 352.
	witnessOffset := big.NewInt(int64(11 * 32))

	args := make([]byte, 0, 512)
	args = append(args, padAddress(params.PRCAddress)...)                        // slot 0: _prc
	args = append(args, padAddress(b.token.Address())...)                        // slot 1: _token
	args = append(args, padAddress(params.Buyer)...)                             // slot 2: _buyer
	args = append(args, padAddress(params.Seller)...)                            // slot 3: _seller
	args = append(args, padUint256(params.Amount)...)                            // slot 4: _amount
	args = append(args, padUint256(new(big.Int).SetUint64(timeoutBlock))...)     // slot 5: _timeoutBlock
	args = append(args, receiptPadded...)                                         // slot 6: _receiptHash
	args = append(args, padUint256(witnessOffset)...)                             // slot 7: offset to _witnessHashes
	args = append(args, padUint256(big.NewInt(int64(params.ServiceProviderBPS)))...) // slot 8: _serviceProviderBPS
	if params.ServiceProviderPayout != "" {                                       // slot 9: _serviceProviderPayout
		args = append(args, padAddress(params.ServiceProviderPayout)...)
	} else {
		args = append(args, make([]byte, 32)...)
	}
	args = append(args, padUint256(big.NewInt(int64(params.ArbitratorBPS)))...)   // slot 10: _arbitratorBPS

	// Dynamic array: _witnessHashes (length + elements)
	args = append(args, padUint256(big.NewInt(int64(len(params.WitnessHashes))))...)
	for _, wh := range params.WitnessHashes {
		args = append(args, padBytes32(wh)...)
	}

	return &adapter.UnsignedTx{
		ChainID:  b.client.chainID,
		To:       "", // contract creation
		Amount:   big.NewInt(0),
		Payload:  args,
		GasLimit: 0, // caller must estimate
	}, nil
}

// FundEscrow creates a transaction to fund an escrow. This involves approving
// the escrow contract to spend the buyer's tokens, then calling fund().
func (b *EscrowBinding) FundEscrow(escrowAddr string, amount *big.Int) (*adapter.UnsignedTx, error) {
	if escrowAddr == "" {
		return nil, fmt.Errorf("evm/escrow: escrow address is empty")
	}
	if amount == nil || amount.Sign() <= 0 {
		return nil, fmt.Errorf("evm/escrow: fund amount must be positive")
	}

	// The funding call: first approve, then fund().
	// We encode the fund() call here. The caller is responsible for the
	// approve() step as a separate transaction.
	callData := encodeCall(selectorFund)

	return &adapter.UnsignedTx{
		ChainID:    b.client.chainID,
		To:         escrowAddr,
		Amount:     big.NewInt(0), // ERC20 transfer, no native value
		Payload:    callData,
		EscrowAddr: escrowAddr,
	}, nil
}

// ReleaseEscrow creates a transaction for the buyer to release funds to the seller.
func (b *EscrowBinding) ReleaseEscrow(escrowAddr string, params adapter.ReleaseParams) (*adapter.UnsignedTx, error) {
	if escrowAddr == "" {
		return nil, fmt.Errorf("evm/escrow: escrow address is empty")
	}

	callData := encodeCall(selectorRelease)

	return &adapter.UnsignedTx{
		ChainID:    b.client.chainID,
		To:         escrowAddr,
		Amount:     big.NewInt(0),
		Payload:    callData,
		EscrowAddr: escrowAddr,
	}, nil
}

// DisputeEscrow creates a transaction to flag an escrow as disputed.
func (b *EscrowBinding) DisputeEscrow(escrowAddr string, params adapter.DisputeParams) (*adapter.UnsignedTx, error) {
	if escrowAddr == "" {
		return nil, fmt.Errorf("evm/escrow: escrow address is empty")
	}

	// dispute(address arbitrator)
	arbitratorAddr := params.DisputerAddr
	if arbitratorAddr == "" {
		return nil, fmt.Errorf("evm/escrow: disputer address is empty")
	}

	callData := encodeCall(selectorDispute, padAddress(arbitratorAddr))

	return &adapter.UnsignedTx{
		ChainID:    b.client.chainID,
		To:         escrowAddr,
		Amount:     big.NewInt(0),
		Payload:    callData,
		EscrowAddr: escrowAddr,
	}, nil
}

// SettleWithRuling creates a transaction for the arbitrator to settle a dispute.
func (b *EscrowBinding) SettleWithRuling(escrowAddr string, ruling adapter.Ruling) (*adapter.UnsignedTx, error) {
	if escrowAddr == "" {
		return nil, fmt.Errorf("evm/escrow: escrow address is empty")
	}
	if ruling.BuyerPercent+ruling.SellerPercent != 100 {
		return nil, fmt.Errorf("evm/escrow: ruling percentages must sum to 100")
	}

	// settle(uint256 buyerPct, uint256 sellerPct)
	callData := encodeCall(
		selectorSettle,
		padUint256(big.NewInt(int64(ruling.BuyerPercent))),
		padUint256(big.NewInt(int64(ruling.SellerPercent))),
	)

	return &adapter.UnsignedTx{
		ChainID:    b.client.chainID,
		To:         escrowAddr,
		Amount:     big.NewInt(0),
		Payload:    callData,
		EscrowAddr: escrowAddr,
	}, nil
}

// RefundAfterTimeout creates a transaction for the buyer to reclaim funds
// after the escrow timeout has elapsed.
func (b *EscrowBinding) RefundAfterTimeout(escrowAddr string) (*adapter.UnsignedTx, error) {
	if escrowAddr == "" {
		return nil, fmt.Errorf("evm/escrow: escrow address is empty")
	}

	callData := encodeCall(selectorRefund)

	return &adapter.UnsignedTx{
		ChainID:    b.client.chainID,
		To:         escrowAddr,
		Amount:     big.NewInt(0),
		Payload:    callData,
		EscrowAddr: escrowAddr,
	}, nil
}

// EscrowState queries the full on-chain state of an escrow contract.
func (b *EscrowBinding) EscrowState(ctx context.Context, escrowAddr string) (*adapter.EscrowState, error) {
	if escrowAddr == "" {
		return nil, fmt.Errorf("evm/escrow: escrow address is empty")
	}

	// Query individual fields from the contract.
	buyerData, err := b.client.Call(ctx, escrowAddr, encodeCall(selectorBuyer), "latest")
	if err != nil {
		return nil, fmt.Errorf("evm/escrow: query buyer: %w", err)
	}

	sellerData, err := b.client.Call(ctx, escrowAddr, encodeCall(selectorSeller), "latest")
	if err != nil {
		return nil, fmt.Errorf("evm/escrow: query seller: %w", err)
	}

	amountData, err := b.client.Call(ctx, escrowAddr, encodeCall(selectorAmount), "latest")
	if err != nil {
		return nil, fmt.Errorf("evm/escrow: query amount: %w", err)
	}

	stateData, err := b.client.Call(ctx, escrowAddr, encodeCall(selectorState), "latest")
	if err != nil {
		return nil, fmt.Errorf("evm/escrow: query state: %w", err)
	}

	arbitratorData, err := b.client.Call(ctx, escrowAddr, encodeCall(selectorArbitrator), "latest")
	if err != nil {
		return nil, fmt.Errorf("evm/escrow: query arbitrator: %w", err)
	}

	timeoutData, err := b.client.Call(ctx, escrowAddr, encodeCall(selectorTimeoutBlock), "latest")
	if err != nil {
		return nil, fmt.Errorf("evm/escrow: query timeoutBlock: %w", err)
	}

	prcData, err := b.client.Call(ctx, escrowAddr, encodeCall(selectorPRC), "latest")
	if err != nil {
		return nil, fmt.Errorf("evm/escrow: query prc: %w", err)
	}

	amount, _ := decodeBigInt(amountData)
	timeoutBig, _ := decodeBigInt(timeoutData)
	var timeoutAt uint64
	if timeoutBig != nil {
		timeoutAt = timeoutBig.Uint64()
	}

	// Decode state enum from uint256.
	stateBig, _ := decodeBigInt(stateData)
	status := decodeEscrowStatus(stateBig)

	return &adapter.EscrowState{
		Address:        escrowAddr,
		Buyer:          decodeAddress(buyerData),
		Seller:         decodeAddress(sellerData),
		Amount:         amount,
		Currency:       b.token.Address(),
		Status:         status,
		ArbitratorAddr: decodeAddress(arbitratorData),
		TimeoutAt:      timeoutAt,
		PRCAddress:     decodeAddress(prcData),
	}, nil
}

// decodeEscrowStatus maps the on-chain uint256 state enum to the adapter status.
func decodeEscrowStatus(stateBig *big.Int) adapter.EscrowStatus {
	if stateBig == nil {
		return adapter.EscrowStatusPending
	}
	switch stateBig.Uint64() {
	case 0:
		return adapter.EscrowStatusPending
	case 1:
		return adapter.EscrowStatusFunded
	case 2:
		return adapter.EscrowStatusReleased
	case 3:
		return adapter.EscrowStatusDisputed
	case 4:
		return adapter.EscrowStatusSettled
	case 5:
		return adapter.EscrowStatusRefunded
	case 6:
		return adapter.EscrowStatusCancelled
	default:
		return adapter.EscrowStatusPending
	}
}

// dynamicArgsSize returns the ABI-encoded size of a dynamic bytes32 array.
func dynamicArgsSize(items interface{}) int {
	switch v := items.(type) {
	case [][]byte:
		return 32 + len(v)*32 // count word + data words
	case []byte:
		if len(v) > 0 {
			return 32
		}
		return 32
	default:
		return 32
	}
}

// ApproveCallData returns the ERC20 approve calldata for funding an escrow.
// This is a convenience method — call this before FundEscrow.
func (b *EscrowBinding) ApproveCallData(escrowAddr string, amount *big.Int) ([]byte, error) {
	return b.token.Approve(escrowAddr, amount)
}

// DeployEscrowAddress computes the CREATE2 address for a deterministic escrow
// deployment given the factory address, salt, and init code hash.
func DeployEscrowAddress(factoryAddr string, salt [32]byte, initCodeHash [32]byte) string {
	// CREATE2: keccak256(0xff ++ factory ++ salt ++ initCodeHash)[12:32]
	factoryBytes, _ := hex.DecodeString(strings.TrimPrefix(factoryAddr, "0x"))
	payload := make([]byte, 0, 1+20+32+32)
	payload = append(payload, 0xff)
	payload = append(payload, factoryBytes...)
	payload = append(payload, salt[:]...)
	payload = append(payload, initCodeHash[:]...)

	h := sha3.NewLegacyKeccak256()
	h.Write(payload)
	hash := h.Sum(nil)
	return "0x" + hex.EncodeToString(hash[12:32])
}
