/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package maintainer

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// PRCDeployment records the result of deploying a PRC to a chain.
type PRCDeployment struct {
	ChainID            string    `json:"chainID"`
	PRCAddress         string    `json:"prcAddress"`
	TxHash             string    `json:"txHash"`
	MaintainerPayout   string    `json:"maintainerPayout"`
	MaintainerFeeBPS   uint32    `json:"maintainerFeeBPS"`
	WitnessBPS         uint32    `json:"witnessBPS"`
	MaintainerPubKey   string    `json:"maintainerPubKey"`     // hex-encoded Ed25519 pubkey
	MaintainerKeyHash  string    `json:"maintainerPubKeyHash"` // hex-encoded SHA256 of pubkey
	DeployedAt         time.Time `json:"deployedAt"`
	BlockNumber        uint64    `json:"blockNumber,omitempty"`
}

// PRCDeployConfig contains the configuration for deploying a PRC.
type PRCDeployConfig struct {
	// ChainID is the target chain (e.g., "polygon", "ethereum", "arbitrum", "bsc").
	ChainID string

	// MaintainerPayout is the chain-specific payout address.
	MaintainerPayout string

	// MaintainerFeeBPS is the maintainer fee in basis points (max 500).
	MaintainerFeeBPS uint32

	// WitnessBPS is the witness fee in basis points (max 100).
	WitnessBPS uint32

	// MaintainerKey is the Ed25519 private key used for signing.
	// The public key hash is embedded in the PRC.
	MaintainerKey ed25519.PrivateKey

	// GasLimit overrides the gas estimate (0 = auto).
	GasLimit uint64

	// GasPrice overrides the gas price in wei (nil = auto).
	GasPrice *big.Int
}

// ChainDeployer is the interface for deploying contracts to a chain.
// This is implemented by chain-specific adapters (EVM, etc.).
type ChainDeployer interface {
	// DeployContract deploys a contract and returns the tx hash and contract address.
	DeployContract(ctx context.Context, chainID string, bytecodeHex string, constructorArgs []byte) (txHash string, contractAddr string, err error)

	// WaitForDeployment waits for the deployment transaction to be confirmed
	// and returns the deployed contract address.
	WaitForDeployment(ctx context.Context, chainID string, txHash string) (contractAddr string, blockNumber uint64, err error)
}

// PRCDeployer deploys Protocol Registry Contracts to blockchains.
type PRCDeployer struct {
	deployer ChainDeployer
}

// NewPRCDeployer creates a new PRC deployer.
func NewPRCDeployer(deployer ChainDeployer) (*PRCDeployer, error) {
	if deployer == nil {
		return nil, errors.New("maintainer: chain deployer is nil")
	}
	return &PRCDeployer{deployer: deployer}, nil
}

// Deploy deploys a PRC to the specified chain.
func (d *PRCDeployer) Deploy(ctx context.Context, config PRCDeployConfig) (*PRCDeployment, error) {
	if err := validateDeployConfig(config); err != nil {
		return nil, fmt.Errorf("maintainer: invalid deploy config: %w", err)
	}

	// Compute the maintainer public key hash.
	pubKey := config.MaintainerKey.Public().(ed25519.PublicKey)
	pubKeyHash := sha256.Sum256(pubKey)

	// Encode the constructor arguments for the PRC.
	// Solidity constructor: (address _payout, uint256 _maintainerBPS, uint256 _witnessBPS, bytes32 _pubKeyHash)
	constructorArgs := encodePRCConstructorArgs(
		config.MaintainerPayout,
		config.MaintainerFeeBPS,
		config.WitnessBPS,
		pubKeyHash,
	)

	// Deploy the contract.
	txHash, contractAddr, err := d.deployer.DeployContract(
		ctx,
		config.ChainID,
		"", // bytecode is provided by the deployer implementation
		constructorArgs,
	)
	if err != nil {
		return nil, fmt.Errorf("maintainer: deploy PRC to %s: %w", config.ChainID, err)
	}

	// Wait for confirmation.
	confirmedAddr, blockNum, err := d.deployer.WaitForDeployment(ctx, config.ChainID, txHash)
	if err != nil {
		return nil, fmt.Errorf("maintainer: wait for PRC deployment on %s: %w", config.ChainID, err)
	}

	// Use the confirmed address if available.
	if confirmedAddr != "" {
		contractAddr = confirmedAddr
	}

	return &PRCDeployment{
		ChainID:           config.ChainID,
		PRCAddress:        contractAddr,
		TxHash:            txHash,
		MaintainerPayout:  config.MaintainerPayout,
		MaintainerFeeBPS:  config.MaintainerFeeBPS,
		WitnessBPS:        config.WitnessBPS,
		MaintainerPubKey:  hex.EncodeToString(pubKey),
		MaintainerKeyHash: hex.EncodeToString(pubKeyHash[:]),
		DeployedAt:        time.Now().UTC(),
		BlockNumber:       blockNum,
	}, nil
}

// validateDeployConfig checks the deploy configuration for errors.
func validateDeployConfig(config PRCDeployConfig) error {
	if config.ChainID == "" {
		return errors.New("chainID is required")
	}
	if config.MaintainerPayout == "" {
		return errors.New("maintainerPayout address is required")
	}
	if config.MaintainerFeeBPS > 500 {
		return fmt.Errorf("maintainerFeeBPS %d exceeds maximum 500", config.MaintainerFeeBPS)
	}
	if config.WitnessBPS > 100 {
		return fmt.Errorf("witnessBPS %d exceeds maximum 100", config.WitnessBPS)
	}
	if len(config.MaintainerKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("maintainer key must be %d bytes", ed25519.PrivateKeySize)
	}
	return nil
}

// encodePRCConstructorArgs ABI-encodes the PRC constructor arguments.
func encodePRCConstructorArgs(payout string, maintainerBPS, witnessBPS uint32, pubKeyHash [32]byte) []byte {
	args := make([]byte, 0, 4*32) // 4 x 32-byte words

	// address _payout (left-padded to 32 bytes)
	args = append(args, padAddressToCLI(payout)...)

	// uint256 _maintainerBPS
	args = append(args, padUint256CLI(uint64(maintainerBPS))...)

	// uint256 _witnessBPS
	args = append(args, padUint256CLI(uint64(witnessBPS))...)

	// bytes32 _pubKeyHash
	args = append(args, pubKeyHash[:]...)

	return args
}

// padAddressToCLI pads an address to 32 bytes.
func padAddressToCLI(addr string) []byte {
	// Strip 0x prefix.
	if len(addr) >= 2 && addr[:2] == "0x" {
		addr = addr[2:]
	}
	addrBytes, _ := hex.DecodeString(addr)
	padded := make([]byte, 32)
	copy(padded[32-len(addrBytes):], addrBytes)
	return padded
}

// padUint256CLI encodes a uint64 as a 32-byte big-endian word.
func padUint256CLI(n uint64) []byte {
	b := new(big.Int).SetUint64(n)
	padded := make([]byte, 32)
	bBytes := b.Bytes()
	copy(padded[32-len(bBytes):], bBytes)
	return padded
}

// MarshalDeployment serializes a PRC deployment record to JSON.
func MarshalDeployment(d *PRCDeployment) ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}

// UnmarshalDeployment deserializes a PRC deployment record from JSON.
func UnmarshalDeployment(data []byte) (*PRCDeployment, error) {
	var d PRCDeployment
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("maintainer: unmarshal deployment: %w", err)
	}
	return &d, nil
}

// DeploymentSummary returns a human-readable summary of a deployment.
func DeploymentSummary(d *PRCDeployment) string {
	return fmt.Sprintf(
		"PRC deployed to %s at %s (tx: %s, fee: %d BPS, witness: %d BPS)",
		d.ChainID, d.PRCAddress, d.TxHash, d.MaintainerFeeBPS, d.WitnessBPS,
	)
}
