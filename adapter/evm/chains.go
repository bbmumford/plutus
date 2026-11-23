/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package evm

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/bbmumford/plutus/adapter"
)

// GasModel identifies the gas pricing model used by a chain.
type GasModel string

const (
	// GasModelEIP1559 uses baseFee + maxPriorityFeePerGas (Ethereum post-London,
	// Polygon, Arbitrum, Optimism, Base, etc.).
	GasModelEIP1559 GasModel = "eip1559"
	// GasModelLegacy uses a single gasPrice field (BSC, older chains).
	GasModelLegacy GasModel = "legacy"
)

// TokenSpec describes a single ERC20 (or native) currency on a chain.
type TokenSpec struct {
	// Address is the contract address (hex, 0x-prefixed) for ERC20 tokens.
	// Empty string means native coin (ETH, MATIC, BNB, etc.).
	Address  string `json:"address"`
	Symbol   string `json:"symbol"`
	Decimals uint8  `json:"decimals"`
	IsERC20  bool   `json:"isERC20"`
}

// ChainSpec fully describes an EVM-compatible chain that the generic adapter
// factory can bind to. Adding a new chain (Base, Optimism, Avalanche, etc.)
// is a chains.json edit — no Go code changes.
type ChainSpec struct {
	ID           uint64        `json:"id"`           // EVM chain ID
	Name         string        `json:"name"`         // canonical lowercase name (polygon, ethereum, ...)
	RPCURL       string        `json:"rpcUrl"`       // default public RPC URL
	NativeSymbol string        `json:"nativeSymbol"` // ETH, MATIC, BNB, ...
	GasModel     GasModel      `json:"gasModel"`     // "eip1559" or "legacy"
	BlockTime    time.Duration `json:"-"`            // derived from BlockTimeMs
	BlockTimeMs  uint64        `json:"blockTimeMs"`  // marshaled form
	ExplorerURL  string        `json:"explorerUrl"`
	// Currencies is keyed by symbol inside the in-memory map built by
	// LoadChains. In chains.json it is a flat array for readability.
	Currencies []TokenSpec `json:"currencies"`
}

// chainsFile is the JSON wrapper used by chains.json and overlay files.
type chainsFile struct {
	Chains []ChainSpec `json:"chains"`
}

//go:embed chains.json
var defaultChainsJSON []byte

// LoadChains parses the embedded default chains.json and, if overlayPath is
// non-empty, merges an external operator-supplied file on top.
//
// Overlay semantics:
//   - A chain whose ID matches an existing spec REPLACES that spec (allowing
//     operators to rewrite the RPC URL or currency list without recompiling).
//   - A chain with a new ID is appended.
//
// The returned slice preserves the order: embedded defaults first, then
// overlay additions. Callers use ChainsByID / ChainsByName for lookups.
func LoadChains(overlayPath string) ([]ChainSpec, error) {
	defaults, err := parseChainsJSON(defaultChainsJSON)
	if err != nil {
		return nil, fmt.Errorf("evm/chains: parse embedded defaults: %w", err)
	}

	if overlayPath == "" {
		return defaults, nil
	}

	overlayBytes, err := os.ReadFile(overlayPath)
	if err != nil {
		return nil, fmt.Errorf("evm/chains: read overlay %q: %w", overlayPath, err)
	}
	overlay, err := parseChainsJSON(overlayBytes)
	if err != nil {
		return nil, fmt.Errorf("evm/chains: parse overlay %q: %w", overlayPath, err)
	}

	// Merge by chain ID: overlay entries replace matching IDs and append new ones.
	indexByID := make(map[uint64]int, len(defaults))
	for i, c := range defaults {
		indexByID[c.ID] = i
	}
	merged := append([]ChainSpec(nil), defaults...)
	for _, c := range overlay {
		if idx, ok := indexByID[c.ID]; ok {
			merged[idx] = c
		} else {
			indexByID[c.ID] = len(merged)
			merged = append(merged, c)
		}
	}
	return merged, nil
}

// parseChainsJSON decodes a chains.json payload and fills in derived fields.
func parseChainsJSON(data []byte) ([]ChainSpec, error) {
	var f chainsFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	for i := range f.Chains {
		c := &f.Chains[i]
		if c.Name == "" {
			return nil, fmt.Errorf("chain id=%d missing name", c.ID)
		}
		c.Name = strings.ToLower(c.Name)
		if c.GasModel == "" {
			c.GasModel = GasModelEIP1559
		}
		switch c.GasModel {
		case GasModelEIP1559, GasModelLegacy:
		default:
			return nil, fmt.Errorf("chain %q: unknown gasModel %q", c.Name, c.GasModel)
		}
		if c.BlockTimeMs > 0 {
			c.BlockTime = time.Duration(c.BlockTimeMs) * time.Millisecond
		}
	}
	return f.Chains, nil
}

// ChainByID returns the first matching spec for the given chain ID.
func ChainByID(chains []ChainSpec, id uint64) (ChainSpec, bool) {
	for _, c := range chains {
		if c.ID == id {
			return c, true
		}
	}
	return ChainSpec{}, false
}

// ChainByName returns the first matching spec for the given lowercase name.
func ChainByName(chains []ChainSpec, name string) (ChainSpec, bool) {
	name = strings.ToLower(name)
	for _, c := range chains {
		if c.Name == name {
			return c, true
		}
	}
	return ChainSpec{}, false
}

// Currency returns the TokenSpec for a symbol on a chain.
func (c ChainSpec) Currency(symbol string) (TokenSpec, bool) {
	for _, t := range c.Currencies {
		if strings.EqualFold(t.Symbol, symbol) {
			return t, true
		}
	}
	return TokenSpec{}, false
}

// EVMAdapter is the generic, spec-driven CurrencyAdapter. All chain-specific
// behaviour is derived from the ChainSpec + TokenSpec; there is no per-chain
// Go code. The named constructors (NewEthereumUSDCAdapter, NewPolygonUSDCAdapter,
// etc.) remain as thin wrappers for backward compatibility and delegate here.
type EVMAdapter struct {
	spec    ChainSpec
	token   TokenSpec
	client  *EVMClient
	erc20   *ERC20
	escrow  *EscrowBinding
	gas     *GasEstimator
	prcAddr string
}

// NewEVMAdapterFromSpec builds a generic EVM adapter from a chain+token spec.
// The caller provides the mesh transport and the PRC address.
func NewEVMAdapterFromSpec(transport MeshTransport, spec ChainSpec, token TokenSpec, prcAddr string) (*EVMAdapter, error) {
	if prcAddr == "" {
		return nil, fmt.Errorf("evm/%s: PRC address is empty", spec.Name)
	}

	client, err := NewEVMClient(transport, spec.Name)
	if err != nil {
		return nil, fmt.Errorf("evm/%s: create client: %w", spec.Name, err)
	}

	var erc20 *ERC20
	if token.IsERC20 {
		if token.Address == "" {
			return nil, fmt.Errorf("evm/%s: ERC20 token %s has empty address", spec.Name, token.Symbol)
		}
		erc20, err = NewERC20(client, token.Address)
		if err != nil {
			return nil, fmt.Errorf("evm/%s: create token binding: %w", spec.Name, err)
		}
	}

	escrowBinding, err := NewEscrowBinding(client, erc20, prcAddr)
	if err != nil {
		return nil, fmt.Errorf("evm/%s: create escrow binding: %w", spec.Name, err)
	}

	gas, err := NewGasEstimator(client)
	if err != nil {
		return nil, fmt.Errorf("evm/%s: create gas estimator: %w", spec.Name, err)
	}
	applyChainGasTuning(gas, spec)

	return &EVMAdapter{
		spec:    spec,
		token:   token,
		client:  client,
		erc20:   erc20,
		escrow:  escrowBinding,
		gas:     gas,
		prcAddr: prcAddr,
	}, nil
}

// applyChainGasTuning sets the GasEstimator's defaults based on the chain's
// expected gas profile. The values are conservative defaults — the gas
// estimator still queries the network for the actual fee at tx-build time;
// these just bound the output.
func applyChainGasTuning(gas *GasEstimator, spec ChainSpec) {
	const gwei = 1_000_000_000
	switch spec.Name {
	case "ethereum":
		gas.DefaultMaxPriorityFee = big.NewInt(2 * gwei)
		gas.MaxGasPrice = new(big.Int).Mul(big.NewInt(300), big.NewInt(gwei))
	case "polygon":
		gas.DefaultMaxPriorityFee = big.NewInt(30 * gwei)
		gas.MaxGasPrice = new(big.Int).Mul(big.NewInt(1000), big.NewInt(gwei))
	case "arbitrum":
		gas.DefaultMaxPriorityFee = big.NewInt(gwei / 10) // 0.1 gwei
		gas.MaxGasPrice = new(big.Int).Mul(big.NewInt(10), big.NewInt(gwei))
		gas.GasLimitMultiplier = 1.5
	case "bsc":
		gas.DefaultMaxPriorityFee = big.NewInt(3 * gwei)
		gas.MaxGasPrice = new(big.Int).Mul(big.NewInt(50), big.NewInt(gwei))
	default:
		// Fall back to the GasEstimator defaults initialized in NewGasEstimator.
	}
}

// --- adapter.CurrencyAdapter implementation ---

func (a *EVMAdapter) ChainID() string  { return a.spec.Name }
func (a *EVMAdapter) Currency() string { return a.token.Symbol }
func (a *EVMAdapter) Symbol() string   { return a.token.Symbol }

func (a *EVMAdapter) ConstructEscrow(params adapter.EscrowParams) (*adapter.UnsignedTx, error) {
	params.PRCAddress = a.prcAddr
	tx, err := a.escrow.ConstructEscrow(params)
	if err != nil {
		return nil, err
	}
	a.attachGas(tx, params.Buyer, "", tx.Payload)
	return tx, nil
}

func (a *EVMAdapter) FundEscrow(escrowAddr string, amount *big.Int) (*adapter.UnsignedTx, error) {
	tx, err := a.escrow.FundEscrow(escrowAddr, amount)
	if err != nil {
		return nil, err
	}
	a.attachGas(tx, "", escrowAddr, tx.Payload)
	return tx, nil
}

func (a *EVMAdapter) ReleaseEscrow(escrowAddr string, params adapter.ReleaseParams) (*adapter.UnsignedTx, error) {
	tx, err := a.escrow.ReleaseEscrow(escrowAddr, params)
	if err != nil {
		return nil, err
	}
	a.attachGas(tx, "", escrowAddr, tx.Payload)
	return tx, nil
}

func (a *EVMAdapter) DisputeEscrow(escrowAddr string, params adapter.DisputeParams) (*adapter.UnsignedTx, error) {
	tx, err := a.escrow.DisputeEscrow(escrowAddr, params)
	if err != nil {
		return nil, err
	}
	a.attachGas(tx, "", escrowAddr, tx.Payload)
	return tx, nil
}

func (a *EVMAdapter) SettleWithRuling(escrowAddr string, ruling adapter.Ruling) (*adapter.UnsignedTx, error) {
	tx, err := a.escrow.SettleWithRuling(escrowAddr, ruling)
	if err != nil {
		return nil, err
	}
	a.attachGas(tx, "", escrowAddr, tx.Payload)
	return tx, nil
}

func (a *EVMAdapter) RefundAfterTimeout(escrowAddr string) (*adapter.UnsignedTx, error) {
	tx, err := a.escrow.RefundAfterTimeout(escrowAddr)
	if err != nil {
		return nil, err
	}
	a.attachGas(tx, "", escrowAddr, tx.Payload)
	return tx, nil
}

func (a *EVMAdapter) EscrowState(escrowAddr string) (*adapter.EscrowState, error) {
	return a.escrow.EscrowState(context.Background(), escrowAddr)
}

func (a *EVMAdapter) Balance(addr string) (*big.Int, error) {
	if a.erc20 == nil {
		return a.client.GetBalance(context.Background(), addr)
	}
	return a.erc20.BalanceOf(context.Background(), addr)
}

func (a *EVMAdapter) CalculateFees(amount *big.Int, opts adapter.FeeOptions) adapter.FeeBreakdown {
	return calculateFeesCommon(amount, opts)
}

// attachGas estimates and assigns gas parameters to an unsigned tx. Errors are
// intentionally swallowed — the caller can always retry with manual gas.
func (a *EVMAdapter) attachGas(tx *adapter.UnsignedTx, from, to string, payload []byte) {
	ctx := context.Background()
	if gasLimit, err := a.gas.EstimateGas(ctx, from, to, payload, nil); err == nil {
		tx.GasLimit = gasLimit
	}
	if suggestion, err := a.gas.SuggestGasPrice(ctx); err == nil {
		tx.GasPrice = suggestion.MaxFeePerGas
	}
}
