/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package btc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/bbmumford/plutus/witness"
)

// DefaultEsploraBaseURL is the public Blockstream Esplora endpoint. Witnesses
// can point at their own Esplora instance via NewEsploraBalanceProvider's
// baseURL parameter (recommended for production: avoids depending on a single
// provider's availability and rate-limiting).
const DefaultEsploraBaseURL = "https://blockstream.info/api"

// btcDecimals is the number of decimals Bitcoin uses (satoshis). Fixed at 8.
const btcDecimals uint64 = 8

// EsploraBalanceProvider implements witness.ChainBalanceProvider for Bitcoin
// by talking to an Esplora HTTP backend. Esplora is the indexer Blockstream
// and many block explorers use; the API is well-documented and public.
//
// This is an additive, new file — it does NOT touch any other adapter/btc/*
// file, per the implementation constraint.
type EsploraBalanceProvider struct {
	baseURL    string
	httpClient *http.Client
}

// NewEsploraBalanceProvider constructs a provider. If baseURL is empty, the
// public Blockstream endpoint is used. Callers running their own node should
// pass a custom baseURL.
func NewEsploraBalanceProvider(baseURL string, httpClient *http.Client) *EsploraBalanceProvider {
	if baseURL == "" {
		baseURL = DefaultEsploraBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &EsploraBalanceProvider{baseURL: baseURL, httpClient: httpClient}
}

// esploraAddressResponse matches the /address/{addr} JSON shape Esplora returns.
// See https://github.com/Blockstream/esplora/blob/master/API.md#get-addressaddress
type esploraAddressResponse struct {
	Address    string `json:"address"`
	ChainStats struct {
		FundedTxoSum uint64 `json:"funded_txo_sum"`
		SpentTxoSum  uint64 `json:"spent_txo_sum"`
	} `json:"chain_stats"`
}

// QueryBalance reads the confirmed on-chain balance for the given bech32 or
// legacy BTC address. token must be empty — BTC has no ERC20-style tokens on
// L1 (Omni/Liquid are out of scope for v1).
func (p *EsploraBalanceProvider) QueryBalance(ctx context.Context, addr, token string) (witness.BalanceSnapshot, error) {
	if addr == "" {
		return witness.BalanceSnapshot{}, errors.New("btc/balance: address is empty")
	}
	if token != "" {
		return witness.BalanceSnapshot{}, errors.New("btc/balance: tokens not supported on BTC L1")
	}

	addrURL := fmt.Sprintf("%s/address/%s", p.baseURL, addr)
	addrResp, err := p.getJSON(ctx, addrURL)
	if err != nil {
		return witness.BalanceSnapshot{}, fmt.Errorf("btc/balance: fetch address: %w", err)
	}
	var ar esploraAddressResponse
	if err := json.Unmarshal(addrResp, &ar); err != nil {
		return witness.BalanceSnapshot{}, fmt.Errorf("btc/balance: decode address: %w", err)
	}
	sats := int64(ar.ChainStats.FundedTxoSum) - int64(ar.ChainStats.SpentTxoSum)
	if sats < 0 {
		sats = 0
	}

	// Tip hash + height; both cheap endpoints.
	tipHashBytes, err := p.getRaw(ctx, p.baseURL+"/blocks/tip/hash")
	if err != nil {
		return witness.BalanceSnapshot{}, fmt.Errorf("btc/balance: fetch tip hash: %w", err)
	}
	tipHeightBytes, err := p.getRaw(ctx, p.baseURL+"/blocks/tip/height")
	if err != nil {
		return witness.BalanceSnapshot{}, fmt.Errorf("btc/balance: fetch tip height: %w", err)
	}
	var tipHeight uint64
	if _, err := fmt.Sscanf(strings.TrimSpace(string(tipHeightBytes)), "%d", &tipHeight); err != nil {
		return witness.BalanceSnapshot{}, fmt.Errorf("btc/balance: parse tip height: %w", err)
	}

	return witness.BalanceSnapshot{
		Balance:     big.NewInt(sats),
		Decimals:    btcDecimals,
		BlockHash:   strings.TrimSpace(string(tipHashBytes)),
		BlockNumber: tipHeight,
		Timestamp:   time.Now(),
	}, nil
}

// getJSON issues a GET and returns the raw body on 2xx, or an error otherwise.
func (p *EsploraBalanceProvider) getJSON(ctx context.Context, url string) ([]byte, error) {
	return p.getRaw(ctx, url)
}

// getRaw performs the HTTP GET. Kept separate from getJSON for semantic clarity.
func (p *EsploraBalanceProvider) getRaw(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("esplora: HTTP %d: %s", resp.StatusCode, string(body))
	}
	return body, nil
}
