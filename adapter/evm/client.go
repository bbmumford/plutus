/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package evm

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"
)

// MeshTransport is the interface for sending JSON-RPC calls through the
// witness mesh rather than direct HTTP RPC. This keeps Plutus protocol-agnostic
// and avoids direct chain dependency from browser/WASM nodes.
type MeshTransport interface {
	// SendRPC sends a JSON-RPC request via the witness mesh and returns the
	// raw JSON result. The witness mesh selects a witness with chain access,
	// forwards the call, and returns the attested result.
	SendRPC(ctx context.Context, chainID string, method string, params []byte) (json.RawMessage, error)
}

// RPCRequest is a JSON-RPC 2.0 request envelope.
type RPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	ID      uint64          `json:"id"`
}

// RPCResponse is a JSON-RPC 2.0 response envelope.
type RPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
	ID      uint64          `json:"id"`
}

// RPCError is a JSON-RPC 2.0 error.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	if e.Data != "" {
		return fmt.Sprintf("rpc error %d: %s (data: %s)", e.Code, e.Message, e.Data)
	}
	return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
}

// EVMClient wraps JSON-RPC calls via the witness mesh transport. All chain
// interactions go through the mesh — no direct HTTP/WS RPC connections.
type EVMClient struct {
	transport MeshTransport
	chainID   string

	mu    sync.Mutex
	reqID uint64
}

// NewEVMClient creates a new EVM client for the given chain, using the
// provided mesh transport for all RPC calls.
func NewEVMClient(transport MeshTransport, chainID string) (*EVMClient, error) {
	if transport == nil {
		return nil, errors.New("evm: mesh transport is nil")
	}
	if chainID == "" {
		return nil, errors.New("evm: chainID is empty")
	}
	return &EVMClient{
		transport: transport,
		chainID:   chainID,
	}, nil
}

// ChainID returns the chain identifier.
func (c *EVMClient) ChainID() string {
	return c.chainID
}

// nextID returns a monotonically increasing request ID.
func (c *EVMClient) nextID() uint64 {
	c.mu.Lock()
	c.reqID++
	id := c.reqID
	c.mu.Unlock()
	return id
}

// call executes a JSON-RPC method via the mesh transport.
func (c *EVMClient) call(ctx context.Context, method string, params ...interface{}) (json.RawMessage, error) {
	paramBytes, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("evm: marshal params: %w", err)
	}

	result, err := c.transport.SendRPC(ctx, c.chainID, method, paramBytes)
	if err != nil {
		return nil, fmt.Errorf("evm: %s: %w", method, err)
	}

	return result, nil
}

// Call executes an eth_call against a contract at the given block.
// The callData is ABI-encoded function call data. Block is "latest", "pending",
// or a hex block number.
func (c *EVMClient) Call(ctx context.Context, to string, callData []byte, block string) ([]byte, error) {
	if to == "" {
		return nil, errors.New("evm: call target address is empty")
	}
	if block == "" {
		block = "latest"
	}

	callObj := map[string]string{
		"to":   to,
		"data": "0x" + hex.EncodeToString(callData),
	}

	result, err := c.call(ctx, "eth_call", callObj, block)
	if err != nil {
		return nil, err
	}

	var hexResult string
	if err := json.Unmarshal(result, &hexResult); err != nil {
		return nil, fmt.Errorf("evm: decode eth_call result: %w", err)
	}

	return hexDecode(hexResult)
}

// SendTx sends a signed transaction to the network via the witness mesh.
// Returns the transaction hash.
func (c *EVMClient) SendTx(ctx context.Context, signedTxHex string) (string, error) {
	if signedTxHex == "" {
		return "", errors.New("evm: signed transaction is empty")
	}

	if !strings.HasPrefix(signedTxHex, "0x") {
		signedTxHex = "0x" + signedTxHex
	}

	result, err := c.call(ctx, "eth_sendRawTransaction", signedTxHex)
	if err != nil {
		return "", err
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return "", fmt.Errorf("evm: decode sendRawTransaction result: %w", err)
	}

	return txHash, nil
}

// EstimateGas estimates the gas required for a transaction.
func (c *EVMClient) EstimateGas(ctx context.Context, from, to string, data []byte, value *big.Int) (uint64, error) {
	callObj := map[string]string{
		"to": to,
	}
	if from != "" {
		callObj["from"] = from
	}
	if len(data) > 0 {
		callObj["data"] = "0x" + hex.EncodeToString(data)
	}
	if value != nil && value.Sign() > 0 {
		callObj["value"] = "0x" + value.Text(16)
	}

	result, err := c.call(ctx, "eth_estimateGas", callObj)
	if err != nil {
		return 0, err
	}

	return decodeHexUint64(result)
}

// BlockNumber returns the latest block number.
func (c *EVMClient) BlockNumber(ctx context.Context) (uint64, error) {
	result, err := c.call(ctx, "eth_blockNumber")
	if err != nil {
		return 0, err
	}

	return decodeHexUint64(result)
}

// GetBalance returns the native token balance of an address at the latest block.
func (c *EVMClient) GetBalance(ctx context.Context, addr string) (*big.Int, error) {
	if addr == "" {
		return nil, errors.New("evm: address is empty")
	}

	result, err := c.call(ctx, "eth_getBalance", addr, "latest")
	if err != nil {
		return nil, err
	}

	return decodeHexBigInt(result)
}

// GetTransactionCount returns the nonce for an address.
func (c *EVMClient) GetTransactionCount(ctx context.Context, addr string) (uint64, error) {
	if addr == "" {
		return 0, errors.New("evm: address is empty")
	}

	result, err := c.call(ctx, "eth_getTransactionCount", addr, "pending")
	if err != nil {
		return 0, err
	}

	return decodeHexUint64(result)
}

// GetTransactionReceipt returns the receipt for a mined transaction.
func (c *EVMClient) GetTransactionReceipt(ctx context.Context, txHash string) (*TransactionReceipt, error) {
	if txHash == "" {
		return nil, errors.New("evm: txHash is empty")
	}

	result, err := c.call(ctx, "eth_getTransactionReceipt", txHash)
	if err != nil {
		return nil, err
	}

	// null result means TX not yet mined.
	if string(result) == "null" {
		return nil, nil
	}

	var receipt TransactionReceipt
	if err := json.Unmarshal(result, &receipt); err != nil {
		return nil, fmt.Errorf("evm: decode receipt: %w", err)
	}

	return &receipt, nil
}

// WaitForReceipt polls for a transaction receipt until it appears or the
// context is cancelled. Polls every pollInterval.
func (c *EVMClient) WaitForReceipt(ctx context.Context, txHash string, pollInterval time.Duration) (*TransactionReceipt, error) {
	if pollInterval == 0 {
		pollInterval = 2 * time.Second
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		receipt, err := c.GetTransactionReceipt(ctx, txHash)
		if err != nil {
			return nil, err
		}
		if receipt != nil {
			return receipt, nil
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// TransactionReceipt represents a mined transaction receipt.
type TransactionReceipt struct {
	TransactionHash   string `json:"transactionHash"`
	BlockNumber       string `json:"blockNumber"`
	BlockHash         string `json:"blockHash"`
	Status            string `json:"status"` // "0x1" success, "0x0" revert
	GasUsed           string `json:"gasUsed"`
	ContractAddress   string `json:"contractAddress,omitempty"`
	CumulativeGasUsed string `json:"cumulativeGasUsed"`
}

// Success returns true if the transaction was successful.
func (r *TransactionReceipt) Success() bool {
	return r.Status == "0x1"
}

// hexDecode strips the 0x prefix and decodes hex to bytes.
func hexDecode(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if len(s)%2 != 0 {
		s = "0" + s
	}
	return hex.DecodeString(s)
}

// decodeHexUint64 decodes a JSON-encoded hex string to uint64.
func decodeHexUint64(raw json.RawMessage) (uint64, error) {
	var hexStr string
	if err := json.Unmarshal(raw, &hexStr); err != nil {
		return 0, fmt.Errorf("evm: decode hex uint64: %w", err)
	}
	hexStr = strings.TrimPrefix(hexStr, "0x")
	if len(hexStr) == 0 {
		return 0, nil
	}
	// Pad to 16 chars for uint64 parsing.
	if len(hexStr) > 16 {
		return 0, fmt.Errorf("evm: hex value too large for uint64: %s", hexStr)
	}
	b, err := hex.DecodeString(strings.Repeat("0", 16-len(hexStr)) + hexStr)
	if err != nil {
		return 0, fmt.Errorf("evm: decode hex: %w", err)
	}
	return binary.BigEndian.Uint64(b), nil
}

// decodeHexBigInt decodes a JSON-encoded hex string to big.Int.
func decodeHexBigInt(raw json.RawMessage) (*big.Int, error) {
	var hexStr string
	if err := json.Unmarshal(raw, &hexStr); err != nil {
		return nil, fmt.Errorf("evm: decode hex big int: %w", err)
	}
	hexStr = strings.TrimPrefix(hexStr, "0x")
	n := new(big.Int)
	if hexStr == "" || hexStr == "0" {
		return n, nil
	}
	if _, ok := n.SetString(hexStr, 16); !ok {
		return nil, fmt.Errorf("evm: invalid hex big int: %s", hexStr)
	}
	return n, nil
}
