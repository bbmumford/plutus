/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package maintainer

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/bbmumford/plutus/adapter"
)

// SignAdapterConfig contains the parameters for signing a currency adapter.
type SignAdapterConfig struct {
	// ChainID identifies the chain (e.g., "polygon", "ethereum").
	ChainID string
	// Currency is the token name (e.g., "USDC", "BUSD").
	Currency string
	// Symbol is the token symbol (e.g., "USDC", "BUSD").
	Symbol string
	// Version is the adapter version (semver).
	Version string
	// PRCAddress is the PRC contract address on this chain.
	PRCAddress string
	// AdapterBinary is the raw adapter binary or WASM blob.
	AdapterBinary []byte
}

// SignAdapterResult contains the output of signing an adapter.
type SignAdapterResult struct {
	Descriptor    adapter.AdapterDescriptor `json:"descriptor"`
	AdapterHash   string                    `json:"adapterHash"`
	SignerPubKey  string                    `json:"signerPubKey"`
	SignedAt      time.Time                 `json:"signedAt"`
}

// SignAdapter signs an adapter binary with the maintainer's Ed25519 private key.
// This produces an AdapterDescriptor that wallets verify against the PRC
// maintainerPubKeyHash before loading the adapter.
func SignAdapter(config SignAdapterConfig, privateKey ed25519.PrivateKey) (*SignAdapterResult, error) {
	if err := validateSignConfig(config); err != nil {
		return nil, fmt.Errorf("maintainer/sign: %w", err)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("maintainer/sign: invalid private key size %d", len(privateKey))
	}

	// Compute the SHA256 hash of the adapter binary.
	adapterHash := sha256.Sum256(config.AdapterBinary)

	// Build the descriptor.
	desc := adapter.AdapterDescriptor{
		ChainID:     config.ChainID,
		Currency:    config.Currency,
		Symbol:      config.Symbol,
		Version:     config.Version,
		PRCAddress:  config.PRCAddress,
		AdapterHash: adapterHash[:],
	}

	// Sign with the maintainer key.
	adapter.SignDescriptor(&desc, privateKey)

	return &SignAdapterResult{
		Descriptor:  desc,
		AdapterHash: fmt.Sprintf("%x", adapterHash),
		SignerPubKey: fmt.Sprintf("%x", desc.SignerPubKey),
		SignedAt:     time.Now().UTC(),
	}, nil
}

// SignAdapterFile reads an adapter binary from disk and signs it.
func SignAdapterFile(binaryPath string, config SignAdapterConfig, privateKey ed25519.PrivateKey) (*SignAdapterResult, error) {
	binary, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("maintainer/sign: read adapter binary: %w", err)
	}
	if len(binary) == 0 {
		return nil, errors.New("maintainer/sign: adapter binary is empty")
	}

	config.AdapterBinary = binary
	return SignAdapter(config, privateKey)
}

// SaveDescriptor writes a signed adapter descriptor to a JSON file.
func SaveDescriptor(path string, desc *adapter.AdapterDescriptor) error {
	if path == "" {
		return errors.New("maintainer/sign: file path is empty")
	}
	if desc == nil {
		return errors.New("maintainer/sign: descriptor is nil")
	}

	data, err := json.MarshalIndent(desc, "", "  ")
	if err != nil {
		return fmt.Errorf("maintainer/sign: marshal descriptor: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("maintainer/sign: write descriptor file: %w", err)
	}

	return nil
}

// LoadDescriptor reads a signed adapter descriptor from a JSON file.
func LoadDescriptor(path string) (*adapter.AdapterDescriptor, error) {
	if path == "" {
		return nil, errors.New("maintainer/sign: file path is empty")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("maintainer/sign: read descriptor file: %w", err)
	}

	return adapter.ParseDescriptor(data)
}

// VerifyDescriptor checks that a descriptor is correctly signed and matches
// the given PRC public key hash.
func VerifyDescriptor(desc *adapter.AdapterDescriptor, prcPubKeyHash []byte) error {
	return adapter.ValidateAdapter(desc, prcPubKeyHash)
}

// VerifyAdapterBinary checks that a binary matches the hash declared in a descriptor.
func VerifyAdapterBinary(desc *adapter.AdapterDescriptor, binary []byte) error {
	return adapter.ValidateAdapterHash(desc, binary)
}

// validateSignConfig checks the signing configuration for errors.
func validateSignConfig(config SignAdapterConfig) error {
	if config.ChainID == "" {
		return errors.New("chainID is required")
	}
	if config.Currency == "" {
		return errors.New("currency is required")
	}
	if config.Symbol == "" {
		return errors.New("symbol is required")
	}
	if config.Version == "" {
		return errors.New("version is required")
	}
	if config.PRCAddress == "" {
		return errors.New("PRCAddress is required")
	}
	if len(config.AdapterBinary) == 0 {
		return errors.New("adapter binary is required")
	}
	return nil
}

// BatchSignResult contains the results of signing multiple adapters.
type BatchSignResult struct {
	Results []SignAdapterResult `json:"results"`
	Total   int                `json:"total"`
	Failed  int                `json:"failed"`
	Errors  []string           `json:"errors,omitempty"`
}

// BatchSign signs multiple adapter configurations with the same key.
func BatchSign(configs []SignAdapterConfig, privateKey ed25519.PrivateKey) *BatchSignResult {
	result := &BatchSignResult{
		Results: make([]SignAdapterResult, 0, len(configs)),
		Total:   len(configs),
	}

	for _, config := range configs {
		signed, err := SignAdapter(config, privateKey)
		if err != nil {
			result.Failed++
			result.Errors = append(result.Errors, fmt.Sprintf("%s/%s: %s", config.ChainID, config.Symbol, err))
			continue
		}
		result.Results = append(result.Results, *signed)
	}

	return result
}
