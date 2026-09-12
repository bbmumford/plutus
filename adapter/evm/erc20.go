/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package evm

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// ERC20 function selectors (first 4 bytes of keccak256 hash of function signature).
// These are well-known constants from the ERC20 standard.
var (
	// balanceOf(address) => 0x70a08231
	selectorBalanceOf = mustDecodeHex("70a08231")
	// transfer(address,uint256) => 0xa9059cbb
	selectorTransfer = mustDecodeHex("a9059cbb")
	// approve(address,uint256) => 0x095ea7b3
	selectorApprove = mustDecodeHex("095ea7b3")
	// allowance(address,address) => 0xdd62ed3e
	selectorAllowance = mustDecodeHex("dd62ed3e")
	// transferFrom(address,address,uint256) => 0x23b872dd
	selectorTransferFrom = mustDecodeHex("23b872dd")
	// decimals() => 0x313ce567
	selectorDecimals = mustDecodeHex("313ce567")
	// symbol() => 0x95d89b41
	selectorSymbol = mustDecodeHex("95d89b41")
	// name() => 0x06fdde03
	selectorName = mustDecodeHex("06fdde03")
	// totalSupply() => 0x18160ddd
	selectorTotalSupply = mustDecodeHex("18160ddd")
)

// ERC20 provides typed access to ERC20 token contract functions.
// All calls go through the EVMClient which routes via the witness mesh.
type ERC20 struct {
	client       *EVMClient
	tokenAddress string
}

// NewERC20 creates an ERC20 token interface for the given contract address.
func NewERC20(client *EVMClient, tokenAddress string) (*ERC20, error) {
	if client == nil {
		return nil, fmt.Errorf("evm/erc20: client is nil")
	}
	if tokenAddress == "" {
		return nil, fmt.Errorf("evm/erc20: token address is empty")
	}
	return &ERC20{
		client:       client,
		tokenAddress: tokenAddress,
	}, nil
}

// Address returns the token contract address.
func (t *ERC20) Address() string {
	return t.tokenAddress
}

// BalanceOf returns the token balance of the given address.
func (t *ERC20) BalanceOf(ctx context.Context, owner string) (*big.Int, error) {
	if owner == "" {
		return nil, fmt.Errorf("evm/erc20: owner address is empty")
	}

	data := encodeCall(selectorBalanceOf, padAddress(owner))

	result, err := t.client.Call(ctx, t.tokenAddress, data, "latest")
	if err != nil {
		return nil, fmt.Errorf("evm/erc20: balanceOf: %w", err)
	}

	return decodeBigInt(result)
}

// Transfer constructs the ABI-encoded calldata for an ERC20 transfer.
// This returns the raw calldata — the caller is responsible for constructing
// and signing the full transaction.
func (t *ERC20) Transfer(to string, amount *big.Int) ([]byte, error) {
	if to == "" {
		return nil, fmt.Errorf("evm/erc20: transfer recipient is empty")
	}
	if amount == nil || amount.Sign() <= 0 {
		return nil, fmt.Errorf("evm/erc20: transfer amount must be positive")
	}

	return encodeCall(selectorTransfer, padAddress(to), padUint256(amount)), nil
}

// Approve constructs the ABI-encoded calldata for an ERC20 approval.
func (t *ERC20) Approve(spender string, amount *big.Int) ([]byte, error) {
	if spender == "" {
		return nil, fmt.Errorf("evm/erc20: approve spender is empty")
	}
	if amount == nil || amount.Sign() < 0 {
		return nil, fmt.Errorf("evm/erc20: approve amount must be non-negative")
	}

	return encodeCall(selectorApprove, padAddress(spender), padUint256(amount)), nil
}

// Allowance returns the amount of tokens that spender is allowed to spend
// on behalf of owner.
func (t *ERC20) Allowance(ctx context.Context, owner, spender string) (*big.Int, error) {
	if owner == "" || spender == "" {
		return nil, fmt.Errorf("evm/erc20: owner and spender addresses are required")
	}

	data := encodeCall(selectorAllowance, padAddress(owner), padAddress(spender))

	result, err := t.client.Call(ctx, t.tokenAddress, data, "latest")
	if err != nil {
		return nil, fmt.Errorf("evm/erc20: allowance: %w", err)
	}

	return decodeBigInt(result)
}

// TransferFrom constructs the ABI-encoded calldata for an ERC20 transferFrom.
func (t *ERC20) TransferFrom(from, to string, amount *big.Int) ([]byte, error) {
	if from == "" || to == "" {
		return nil, fmt.Errorf("evm/erc20: from and to addresses are required")
	}
	if amount == nil || amount.Sign() <= 0 {
		return nil, fmt.Errorf("evm/erc20: transferFrom amount must be positive")
	}

	return encodeCall(selectorTransferFrom, padAddress(from), padAddress(to), padUint256(amount)), nil
}

// Decimals returns the number of decimal places used by the token.
func (t *ERC20) Decimals(ctx context.Context) (uint8, error) {
	data := encodeCall(selectorDecimals)

	result, err := t.client.Call(ctx, t.tokenAddress, data, "latest")
	if err != nil {
		return 0, fmt.Errorf("evm/erc20: decimals: %w", err)
	}

	if len(result) < 32 {
		return 0, fmt.Errorf("evm/erc20: decimals result too short: %d bytes", len(result))
	}

	return result[31], nil
}

// TotalSupply returns the total token supply.
func (t *ERC20) TotalSupply(ctx context.Context) (*big.Int, error) {
	data := encodeCall(selectorTotalSupply)

	result, err := t.client.Call(ctx, t.tokenAddress, data, "latest")
	if err != nil {
		return nil, fmt.Errorf("evm/erc20: totalSupply: %w", err)
	}

	return decodeBigInt(result)
}

// --- ABI Encoding Helpers ---

// encodeCall concatenates the function selector with ABI-encoded arguments.
func encodeCall(selector []byte, args ...[]byte) []byte {
	size := len(selector)
	for _, a := range args {
		size += len(a)
	}
	result := make([]byte, 0, size)
	result = append(result, selector...)
	for _, a := range args {
		result = append(result, a...)
	}
	return result
}

// padAddress left-pads an Ethereum address to 32 bytes for ABI encoding.
func padAddress(addr string) []byte {
	addr = strings.TrimPrefix(addr, "0x")
	addrBytes, _ := hex.DecodeString(addr)
	padded := make([]byte, 32)
	copy(padded[32-len(addrBytes):], addrBytes)
	return padded
}

// padUint256 encodes a big.Int as a 32-byte big-endian ABI word.
func padUint256(n *big.Int) []byte {
	padded := make([]byte, 32)
	if n != nil {
		b := n.Bytes()
		copy(padded[32-len(b):], b)
	}
	return padded
}

// padBool encodes a boolean as a 32-byte ABI word.
func padBool(v bool) []byte {
	padded := make([]byte, 32)
	if v {
		padded[31] = 1
	}
	return padded
}

// padBytes32 encodes a 32-byte value as an ABI word.
func padBytes32(b []byte) []byte {
	padded := make([]byte, 32)
	copy(padded, b)
	return padded
}

// decodeBigInt decodes a 32-byte ABI-encoded uint256 into a big.Int.
func decodeBigInt(data []byte) (*big.Int, error) {
	if len(data) < 32 {
		return nil, fmt.Errorf("evm: result too short for uint256: %d bytes", len(data))
	}
	return new(big.Int).SetBytes(data[:32]), nil
}

// decodeAddress extracts an address from a 32-byte ABI-encoded word.
func decodeAddress(data []byte) string {
	if len(data) < 32 {
		return ""
	}
	return "0x" + hex.EncodeToString(data[12:32])
}

// mustDecodeHex decodes a hex string or panics (used for compile-time constants).
func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("evm: invalid hex constant: " + s)
	}
	return b
}
