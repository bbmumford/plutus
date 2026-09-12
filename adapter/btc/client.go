/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package btc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

const (
	btcChainID  = "bitcoin"
	btcCurrency = "BTC"
	btcSymbol   = "BTC"
	// Satoshis per BTC.
	satoshiPerBTC = 100_000_000
)

// MeshTransport is the interface for sending Bitcoin JSON-RPC calls through
// the witness mesh. Mirrors the EVM pattern.
type MeshTransport interface {
	SendRPC(ctx context.Context, chainID string, method string, params []byte) (json.RawMessage, error)
}

// BTCClient provides Bitcoin RPC access via the witness mesh.
// All chain interactions go through the mesh — no direct RPC connections.
type BTCClient struct {
	transport MeshTransport
	chainID   string
}

// NewBTCClient creates a new Bitcoin client using the witness mesh transport.
func NewBTCClient(transport MeshTransport) (*BTCClient, error) {
	if transport == nil {
		return nil, errors.New("btc: mesh transport is nil")
	}
	return &BTCClient{
		transport: transport,
		chainID:   btcChainID,
	}, nil
}

// ChainID returns "bitcoin".
func (c *BTCClient) ChainID() string {
	return c.chainID
}

// call executes a Bitcoin JSON-RPC method via the mesh transport.
func (c *BTCClient) call(ctx context.Context, method string, params ...interface{}) (json.RawMessage, error) {
	paramBytes, err := json.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("btc: marshal params: %w", err)
	}

	result, err := c.transport.SendRPC(ctx, c.chainID, method, paramBytes)
	if err != nil {
		return nil, fmt.Errorf("btc: %s: %w", method, err)
	}

	return result, nil
}

// GetBlockCount returns the current block height.
func (c *BTCClient) GetBlockCount(ctx context.Context) (uint64, error) {
	result, err := c.call(ctx, "getblockcount")
	if err != nil {
		return 0, err
	}

	var height uint64
	if err := json.Unmarshal(result, &height); err != nil {
		return 0, fmt.Errorf("btc: decode blockcount: %w", err)
	}

	return height, nil
}

// GetBlockHash returns the block hash at the given height.
func (c *BTCClient) GetBlockHash(ctx context.Context, height uint64) (string, error) {
	result, err := c.call(ctx, "getblockhash", height)
	if err != nil {
		return "", err
	}

	var hash string
	if err := json.Unmarshal(result, &hash); err != nil {
		return "", fmt.Errorf("btc: decode blockhash: %w", err)
	}

	return hash, nil
}

// GetBalance returns the wallet balance in satoshis.
func (c *BTCClient) GetBalance(ctx context.Context, addr string) (*big.Int, error) {
	if addr == "" {
		return nil, errors.New("btc: address is empty")
	}

	// Use listunspent to get the balance for a specific address.
	utxos, err := c.ListUnspent(ctx, addr)
	if err != nil {
		return nil, fmt.Errorf("btc: get balance: %w", err)
	}

	total := new(big.Int)
	for _, utxo := range utxos {
		total.Add(total, utxo.Value)
	}

	return total, nil
}

// ListUnspent returns all unspent transaction outputs for the given address.
func (c *BTCClient) ListUnspent(ctx context.Context, addr string) ([]UTXO, error) {
	if addr == "" {
		return nil, errors.New("btc: address is empty")
	}

	// Bitcoin Core listunspent: minconf, maxconf, addresses
	result, err := c.call(ctx, "listunspent", 1, 9999999, []string{addr})
	if err != nil {
		return nil, err
	}

	var rawUTXOs []struct {
		TxID          string  `json:"txid"`
		Vout          uint32  `json:"vout"`
		Address       string  `json:"address"`
		Amount        float64 `json:"amount"`
		Confirmations uint32  `json:"confirmations"`
		ScriptPubKey  string  `json:"scriptPubKey"`
	}
	if err := json.Unmarshal(result, &rawUTXOs); err != nil {
		return nil, fmt.Errorf("btc: decode listunspent: %w", err)
	}

	utxos := make([]UTXO, len(rawUTXOs))
	for i, raw := range rawUTXOs {
		// Convert BTC amount to satoshis.
		satoshis := new(big.Int).SetInt64(int64(raw.Amount * satoshiPerBTC))
		utxos[i] = UTXO{
			TxID:          raw.TxID,
			Vout:          raw.Vout,
			Address:       raw.Address,
			Value:         satoshis,
			Confirmations: raw.Confirmations,
			ScriptPubKey:  raw.ScriptPubKey,
		}
	}

	return utxos, nil
}

// SendRawTransaction broadcasts a signed transaction to the Bitcoin network
// via the witness mesh.
func (c *BTCClient) SendRawTransaction(ctx context.Context, txHex string) (string, error) {
	if txHex == "" {
		return "", errors.New("btc: raw transaction is empty")
	}

	result, err := c.call(ctx, "sendrawtransaction", txHex)
	if err != nil {
		return "", err
	}

	var txHash string
	if err := json.Unmarshal(result, &txHash); err != nil {
		return "", fmt.Errorf("btc: decode sendrawtransaction: %w", err)
	}

	return txHash, nil
}

// GetRawTransaction returns the raw transaction data for the given txid.
func (c *BTCClient) GetRawTransaction(ctx context.Context, txHash string) (*RawTransaction, error) {
	if txHash == "" {
		return nil, errors.New("btc: txHash is empty")
	}

	result, err := c.call(ctx, "getrawtransaction", txHash, true)
	if err != nil {
		return nil, err
	}

	var tx RawTransaction
	if err := json.Unmarshal(result, &tx); err != nil {
		return nil, fmt.Errorf("btc: decode raw transaction: %w", err)
	}

	return &tx, nil
}

// EstimateSmartFee returns the estimated fee rate in satoshis per vbyte
// for confirmation within the given number of blocks.
func (c *BTCClient) EstimateSmartFee(ctx context.Context, confTarget uint32) (float64, error) {
	if confTarget == 0 {
		confTarget = 6
	}

	result, err := c.call(ctx, "estimatesmartfee", confTarget)
	if err != nil {
		return 0, err
	}

	var feeResult struct {
		FeeRate float64 `json:"feerate"` // BTC per kB
		Blocks  int     `json:"blocks"`
		Errors  []string `json:"errors,omitempty"`
	}
	if err := json.Unmarshal(result, &feeResult); err != nil {
		return 0, fmt.Errorf("btc: decode estimatesmartfee: %w", err)
	}

	if len(feeResult.Errors) > 0 {
		return 0, fmt.Errorf("btc: estimatesmartfee error: %s", feeResult.Errors[0])
	}

	if feeResult.FeeRate <= 0 {
		// Fallback: 10 sat/vbyte minimum.
		return 10.0, nil
	}

	// Convert BTC/kB to sat/vbyte: feeRate * 100000000 / 1000.
	satPerVByte := feeResult.FeeRate * satoshiPerBTC / 1000

	return satPerVByte, nil
}

// UTXO represents an unspent transaction output.
type UTXO struct {
	TxID          string   // transaction hash
	Vout          uint32   // output index
	Address       string   // owning address
	Value         *big.Int // value in satoshis
	Confirmations uint32   // number of confirmations
	ScriptPubKey  string   // output script (hex)
}

// RawTransaction represents a decoded Bitcoin transaction.
type RawTransaction struct {
	TxID          string `json:"txid"`
	Hash          string `json:"hash"`
	Size          int    `json:"size"`
	VSize         int    `json:"vsize"`
	Version       int    `json:"version"`
	Confirmations uint32 `json:"confirmations"`
	BlockHash     string `json:"blockhash,omitempty"`
	Hex           string `json:"hex"`
}
