/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package blob

// Concrete StorageEscrowClient — the on-chain driver for
// PlutusStorageEscrow.sol used by the proof-of-storage challenger loop
// (to report missed responses so the replicator's bond can be slashed)
// and by the pinning flow (CreatePin / PostBond / WithdrawBond).
//
// CONTRACT SHAPE NOTE:
//   PlutusStorageEscrow deploys one instance per (cid, replicator)
//   pair. The CID is baked into the contract via immutable cidHash, so
//   openChallenge / expireChallenge / respond / withdrawBond all take
//   NO CID parameter — the contract address itself identifies the CID
//   under challenge. This client therefore exposes two flavours:
//
//     • Low-level per-contract methods (OpenChallengeAt, ExpireChallengeAt,
//       WithdrawBondFrom, PostBondAt) that take the escrow contract
//       address and route the calldata to that address.
//     • High-level per-CID methods (OpenChallenge, ExpireChallenge,
//       WithdrawBond) that the prompt and callers spell out with a
//       `cid [32]byte` argument. These go through a pluggable
//       EscrowRegistry (cid → contract address) so the high-level API
//       stays chain-agnostic and independent of how the caller
//       remembers which contract pins which CID.
//
//   The registry is caller-supplied. A no-op registry means the
//   high-level methods return ErrNoEscrowForCID — but the low-level
//   path still works, which is what the proof-of-storage loop uses
//   once it has resolved the CID → address mapping from its own
//   bookkeeping.
//
// ABI ENCODING:
//   All function selectors + argument encoding are hand-rolled (see
//   ABI section below). No go-ethereum dependency. Selectors are the
//   first 4 bytes of keccak256(canonicalSig); calldata is selector +
//   ABI-encoded args (each arg padded to 32 bytes; static fields
//   only). The test file verifies each selector against a
//   reference-derived value.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/sha3"

	"github.com/bbmumford/diststore/onchain"
	"github.com/bbmumford/plutus/evmsign"
)

// ─── ABI constants ────────────────────────────────────────────────────

// Function selectors for PlutusStorageEscrow.sol. These are the first 4
// bytes of keccak256(signature). Kept as package-private vars so the
// test file can cross-check them against a reference-derived keccak
// without sharing code.
//
// | Signature                       | Selector   |
// | ------------------------------- | ---------- |
// | openChallenge(bytes32,bytes32)  | 0x60efc6fe |
// | expireChallenge()               | 0xec0f2a67 |
// | respond(bytes32)                | 0x1982f1d3 |
// | withdrawBond()                  | 0x66eb9cec |
// | bondReplicator()                | 0x9edb6fc1 |
// | refundUnbonded()                | 0xff9a717c |
// | releaseWeekly()                 | 0x7289c3ad |
var (
	selOpenChallenge   = mustKeccakSelector("openChallenge(bytes32,bytes32)")
	selExpireChallenge = mustKeccakSelector("expireChallenge()")
	selRespond         = mustKeccakSelector("respond(bytes32)")
	selWithdrawBond    = mustKeccakSelector("withdrawBond()")
	selBondReplicator  = mustKeccakSelector("bondReplicator()")
	selRefundUnbonded  = mustKeccakSelector("refundUnbonded()")
	selReleaseWeekly   = mustKeccakSelector("releaseWeekly()")
)

// ErrNoEscrowForCID is returned when the high-level per-CID methods are
// called for a CID that has no registered escrow contract address.
var ErrNoEscrowForCID = errors.New("plutus/blob: no escrow contract registered for cid")

// ErrNoSigner is returned when the client needs to produce a signed
// transaction but no signer is wired. High-level users of EscrowClient
// whose only function is to READ state may legitimately leave the signer
// unset; any call that mutates chain state fails with this error.
var ErrNoSigner = errors.New("plutus/blob: no signer configured")

// ErrNoBroadcaster mirrors ErrNoSigner for the send path.
var ErrNoBroadcaster = errors.New("plutus/blob: no broadcaster configured")

// ─── Interfaces ───────────────────────────────────────────────────────

// EscrowRegistry resolves a CID (as a 32-byte hash, matching the
// contract's immutable cidHash = keccak256(cid-ASCII)) to the deployed
// PlutusStorageEscrow address on the target chain. The proof-of-storage
// loop populates this as it observes pin acceptances on the mesh.
//
// Callers that do not yet track (cid → contract) mappings can inject
// NoopRegistry; the high-level methods will then return
// ErrNoEscrowForCID and the challenger loop will log-and-skip rather
// than cause a build-time import edge.
type EscrowRegistry interface {
	EscrowAddressForCID(cid [32]byte) (string, bool)
}

// NoopRegistry is a zero-knowledge registry. Useful for tests and for
// runtimes that haven't wired CID→address bookkeeping yet.
type NoopRegistry struct{}

// EscrowAddressForCID always reports "no mapping".
func (NoopRegistry) EscrowAddressForCID(_ [32]byte) (string, bool) { return "", false }

// MemoryRegistry is the trivial in-memory implementation of
// EscrowRegistry. Safe for concurrent use.
type MemoryRegistry struct {
	mu sync.RWMutex
	m  map[[32]byte]string
}

// NewMemoryRegistry builds an empty MemoryRegistry.
func NewMemoryRegistry() *MemoryRegistry { return &MemoryRegistry{m: make(map[[32]byte]string)} }

// Set records cid → addr. An empty addr clears the entry.
func (r *MemoryRegistry) Set(cid [32]byte, addr string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if addr == "" {
		delete(r.m, cid)
		return
	}
	r.m[cid] = addr
}

// EscrowAddressForCID implements EscrowRegistry.
func (r *MemoryRegistry) EscrowAddressForCID(cid [32]byte) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	addr, ok := r.m[cid]
	return addr, ok
}

// TxSigner signs an unsigned legacy transaction and returns the raw
// wire-format bytes for eth_sendRawTransaction. The concrete WalletSigner
// in plutus/witness satisfies a richer API (FeeDistributionSigner); this
// narrower interface lets tests inject a fake signer without dragging the
// whole witness infra in.
type TxSigner interface {
	SignLegacyTx(ctx context.Context, tx evmsign.LegacyTx) ([]byte, error)
}

// TxBroadcaster is the send-side interface. The canonical implementation
// in production is witness.BroadcastService.BroadcastTx; this narrower
// interface lets tests inject a fake broadcaster. Kept identical to the
// witness.FeeDistributionBroadcaster signature so production code can
// just pass the BroadcastService directly.
type TxBroadcaster interface {
	BroadcastTx(ctx context.Context, chainID string, signedTx []byte) (string, error)
}

// NonceFn returns the next usable nonce for the client's sender address
// on the target chain. Typical implementation wraps
// EVMClient.GetTransactionCount. If nil at construction time, the client
// cannot sign — every send path needs a fresh nonce.
type NonceFn func(ctx context.Context) (uint64, error)

// GasPriceFn returns the legacy EIP-155 gas price (wei) to stamp into
// the envelope. Typical implementation wraps a suggested-gas-price query
// or a fixed operator override.
type GasPriceFn func(ctx context.Context) (*big.Int, error)

// ─── StorageEscrowClient ──────────────────────────────────────────────

// StorageEscrowClient is the concrete EscrowClient implementation that
// drives PlutusStorageEscrow.sol instances on a chosen EVM chain.
//
// The client is intentionally small: it builds calldata, wraps it in an
// evmsign.LegacyTx, hands that to the TxSigner, then publishes the
// signed bytes through the TxBroadcaster. It does not maintain any
// internal state beyond its configuration — callers track CID →
// contract address mappings through EscrowRegistry.
//
// A zero-value StorageEscrowClient is NOT usable; construct via
// NewStorageEscrowClient.
type StorageEscrowClient struct {
	// Identity of the chain (used by the broadcaster to route the tx).
	chainID    string
	evmChainID uint64 // e.g. 137 / 1 / 42161 / 56

	// Signing + broadcast plumbing.
	signer      TxSigner
	broadcaster TxBroadcaster
	nonceFn     NonceFn
	gasPriceFn  GasPriceFn

	// Optional registry for high-level CID→address resolution.
	registry EscrowRegistry

	// Default gas limits for each method. Conservative; callers can
	// override per-call via WithGas if needed in a future extension.
	gasOpenChallenge   uint64
	gasExpireChallenge uint64
	gasRespond         uint64
	gasWithdrawBond    uint64
	gasPostBond        uint64
}

// StorageEscrowClientConfig configures a new StorageEscrowClient.
type StorageEscrowClientConfig struct {
	// ChainID is the logical chain name used by the broadcaster (e.g.
	// "polygon", "ethereum"). Required.
	ChainID string
	// EVMChainID is the numeric chain ID used in EIP-155 signing. Required.
	EVMChainID uint64
	// Signer produces raw bytes for eth_sendRawTransaction. Required for
	// any method that mutates chain state.
	Signer TxSigner
	// Broadcaster pushes the signed tx to the chain. Required for any
	// method that mutates chain state.
	Broadcaster TxBroadcaster
	// NonceFn returns the next usable nonce for the sender. Required for
	// mutating calls.
	NonceFn NonceFn
	// GasPriceFn returns the legacy gas price. Required for mutating calls.
	GasPriceFn GasPriceFn
	// Registry is optional. When nil, the high-level per-CID methods
	// return ErrNoEscrowForCID.
	Registry EscrowRegistry
}

// Default per-method gas limits. PlutusStorageEscrow is a small
// state-machine contract; these ceilings cover the worst-case branch
// (slash path on the second missed response, which performs two
// safeTransfer calls). Callers with a tighter ceiling can fork this
// struct — we keep the field package-private for now.
const (
	defaultGasOpenChallenge   uint64 = 120000
	defaultGasExpireChallenge uint64 = 180000 // slash path transfers
	defaultGasRespond         uint64 = 100000
	defaultGasWithdrawBond    uint64 = 80000
	defaultGasPostBond        uint64 = 100000
)

// NewStorageEscrowClient validates cfg and returns a ready client. A
// nil Signer or Broadcaster is permitted at construction — mutating
// calls will fail with ErrNoSigner / ErrNoBroadcaster, which lets a
// read-only caller (e.g. a UI status page) still use the client for
// calldata building via the EncodeXxx helpers.
func NewStorageEscrowClient(cfg StorageEscrowClientConfig) (*StorageEscrowClient, error) {
	if cfg.ChainID == "" {
		return nil, errors.New("plutus/blob: ChainID is required")
	}
	if cfg.EVMChainID == 0 {
		return nil, errors.New("plutus/blob: EVMChainID is required")
	}
	c := &StorageEscrowClient{
		chainID:            cfg.ChainID,
		evmChainID:         cfg.EVMChainID,
		signer:             cfg.Signer,
		broadcaster:        cfg.Broadcaster,
		nonceFn:            cfg.NonceFn,
		gasPriceFn:         cfg.GasPriceFn,
		registry:           cfg.Registry,
		gasOpenChallenge:   defaultGasOpenChallenge,
		gasExpireChallenge: defaultGasExpireChallenge,
		gasRespond:         defaultGasRespond,
		gasWithdrawBond:    defaultGasWithdrawBond,
		gasPostBond:        defaultGasPostBond,
	}
	if c.registry == nil {
		c.registry = NoopRegistry{}
	}
	return c, nil
}

// ─── Calldata builders (pure, exported for testability) ───────────────

// EncodeOpenChallenge returns the 68-byte calldata for
// openChallenge(bytes32 nonce, bytes32 expectedHash) = selector(4) +
// nonce(32) + expectedHash(32).
func EncodeOpenChallenge(nonce, expectedHash [32]byte) []byte {
	out := make([]byte, 0, 4+32+32)
	out = append(out, selOpenChallenge...)
	out = append(out, nonce[:]...)
	out = append(out, expectedHash[:]...)
	return out
}

// EncodeExpireChallenge returns the 4-byte calldata for expireChallenge().
func EncodeExpireChallenge() []byte {
	out := make([]byte, 4)
	copy(out, selExpireChallenge)
	return out
}

// EncodeRespond returns the 36-byte calldata for respond(bytes32 response).
func EncodeRespond(response [32]byte) []byte {
	out := make([]byte, 0, 4+32)
	out = append(out, selRespond...)
	out = append(out, response[:]...)
	return out
}

// EncodeWithdrawBond returns the 4-byte calldata for withdrawBond().
func EncodeWithdrawBond() []byte {
	out := make([]byte, 4)
	copy(out, selWithdrawBond)
	return out
}

// EncodeBondReplicator returns the 4-byte calldata for bondReplicator().
func EncodeBondReplicator() []byte {
	out := make([]byte, 4)
	copy(out, selBondReplicator)
	return out
}

// ─── Mutating methods ─────────────────────────────────────────────────

// OpenChallenge submits openChallenge(nonce, expectedHash) to the
// PlutusStorageEscrow contract bound to `cid` by the registry. The
// returned txHash identifies the on-chain record; the 24h window begins
// at that tx's block timestamp.
//
// expectedHash MUST be keccak256(piece || nonce) as produced by
// onchain.ComputeOnChainExpectedHash — see proof_onchain.go.
// Passing the off-chain BLAKE2b digest produces false misses.
func (c *StorageEscrowClient) OpenChallenge(ctx context.Context, cid, nonce, expectedHash [32]byte) (string, error) {
	addr, ok := c.registry.EscrowAddressForCID(cid)
	if !ok {
		return "", ErrNoEscrowForCID
	}
	return c.OpenChallengeAt(ctx, addr, nonce, expectedHash)
}

// OpenChallengeAt is the low-level form that takes the contract address
// directly. The proof-of-storage loop uses this when it already knows
// which contract a CID lives in (skipping the registry lookup avoids a
// lock on every tick).
func (c *StorageEscrowClient) OpenChallengeAt(ctx context.Context, escrowAddr string, nonce, expectedHash [32]byte) (string, error) {
	calldata := EncodeOpenChallenge(nonce, expectedHash)
	return c.sendTx(ctx, escrowAddr, calldata, c.gasOpenChallenge, new(big.Int))
}

// ExpireChallenge submits expireChallenge() on the contract bound to
// cid. Callable only after the 24h challenge window has elapsed
// (otherwise the contract reverts with ChallengeWindowNotExpired,
// which the caller should treat as a benign "replicator responded in
// time" outcome — see the IsBenignChallengeExpireRevert helper).
func (c *StorageEscrowClient) ExpireChallenge(ctx context.Context, cid [32]byte) (string, error) {
	addr, ok := c.registry.EscrowAddressForCID(cid)
	if !ok {
		return "", ErrNoEscrowForCID
	}
	return c.ExpireChallengeAt(ctx, addr)
}

// ExpireChallengeAt is the low-level form. See ExpireChallenge for
// revert semantics.
func (c *StorageEscrowClient) ExpireChallengeAt(ctx context.Context, escrowAddr string) (string, error) {
	calldata := EncodeExpireChallenge()
	return c.sendTx(ctx, escrowAddr, calldata, c.gasExpireChallenge, new(big.Int))
}

// WithdrawBond submits withdrawBond() from the REPLICATOR'S wallet (not
// the challenger's) against the contract bound to cid. Only legal when
// the contract has transitioned to Status.Completed; earlier calls
// revert. This is the flip-side of the challenger path — the same
// client instance can serve both roles when a node is pinning its own
// content and also acting as a challenger on someone else's.
func (c *StorageEscrowClient) WithdrawBond(ctx context.Context, cid [32]byte) (string, error) {
	addr, ok := c.registry.EscrowAddressForCID(cid)
	if !ok {
		return "", ErrNoEscrowForCID
	}
	return c.WithdrawBondFrom(ctx, addr)
}

// WithdrawBondFrom is the low-level form.
func (c *StorageEscrowClient) WithdrawBondFrom(ctx context.Context, escrowAddr string) (string, error) {
	calldata := EncodeWithdrawBond()
	return c.sendTx(ctx, escrowAddr, calldata, c.gasWithdrawBond, new(big.Int))
}

// Respond submits respond(bytes32 response) on the contract bound to
// cid. Only callable by the replicator who posted the bond; other
// senders get OnlyReplicator(). Provided so that a replicator who is
// watching the mesh for open challenges can short-circuit the 24h
// window by answering on-chain directly — useful when the off-chain
// gossip path is congested.
func (c *StorageEscrowClient) Respond(ctx context.Context, cid [32]byte, response [32]byte) (string, error) {
	addr, ok := c.registry.EscrowAddressForCID(cid)
	if !ok {
		return "", ErrNoEscrowForCID
	}
	return c.RespondAt(ctx, addr, response)
}

// RespondAt is the low-level form.
func (c *StorageEscrowClient) RespondAt(ctx context.Context, escrowAddr string, response [32]byte) (string, error) {
	calldata := EncodeRespond(response)
	return c.sendTx(ctx, escrowAddr, calldata, c.gasRespond, new(big.Int))
}

// ─── onchain.EscrowClient satisfaction ────────────────────────────────

// Compile-time assertion that StorageEscrowClient satisfies the
// pin-side EscrowClient interface declared in diststore/onchain.
var _ onchain.EscrowClient = (*StorageEscrowClient)(nil)

// CreatePin is the pin-side constructor call. It deploys a new
// PlutusStorageEscrow instance for the (cid, replicator) pair on the
// chosen chain. The current plutus build does not yet ship deterministic
// bytecode deployment from Go (we use forge for onboarding), so this
// implementation returns a descriptive error. Once a Go-side bytecode
// generator lands — or once we adopt a factory contract — this method
// swaps to a real deployment tx without changing the interface.
//
// Tests that exercise the pinning flow can substitute a mock
// EscrowClient; the real contract deployment path for production is
// tracked in plutus/contracts/evm/script/.
func (c *StorageEscrowClient) CreatePin(ctx context.Context, _ onchain.CreatePinParams) (string, error) {
	return "", errors.New("plutus/blob: StorageEscrowClient.CreatePin not yet implemented — deploy via forge script or use factory contract; see plutus/contracts/evm/script/")
}

// PostBond submits bondReplicator() on the escrow contract at
// escrowAddress. This is the replicator-side post-construction step: the
// replicator must have already approved bondAmount to the escrow
// contract (see ApproveCallData in adapter/evm/escrow.go for the
// approval calldata). Returns the tx hash.
func (c *StorageEscrowClient) PostBond(ctx context.Context, escrowAddress string) (string, error) {
	calldata := EncodeBondReplicator()
	return c.sendTx(ctx, escrowAddress, calldata, c.gasPostBond, new(big.Int))
}

// ─── Internal tx plumbing ─────────────────────────────────────────────

// sendTx populates a legacy tx, signs it, and broadcasts. Factored out
// so every mutating method is a one-liner over this helper.
func (c *StorageEscrowClient) sendTx(ctx context.Context, to string, calldata []byte, gas uint64, value *big.Int) (string, error) {
	if c.signer == nil {
		return "", ErrNoSigner
	}
	if c.broadcaster == nil {
		return "", ErrNoBroadcaster
	}
	if c.nonceFn == nil {
		return "", errors.New("plutus/blob: no nonce source configured")
	}
	if c.gasPriceFn == nil {
		return "", errors.New("plutus/blob: no gas price source configured")
	}
	if !isHexAddress(to) {
		return "", fmt.Errorf("plutus/blob: invalid escrow address %q", to)
	}

	nonce, err := c.nonceFn(ctx)
	if err != nil {
		return "", fmt.Errorf("plutus/blob: nonce lookup: %w", err)
	}
	gasPrice, err := c.gasPriceFn(ctx)
	if err != nil {
		return "", fmt.Errorf("plutus/blob: gas price lookup: %w", err)
	}
	if gasPrice == nil || gasPrice.Sign() <= 0 {
		return "", errors.New("plutus/blob: gas price must be positive")
	}

	tx := evmsign.LegacyTx{
		Nonce:      nonce,
		GasPrice:   gasPrice,
		GasLimit:   gas,
		To:         to,
		Value:      value,
		Data:       calldata,
		EVMChainID: c.evmChainID,
	}
	signed, err := c.signer.SignLegacyTx(ctx, tx)
	if err != nil {
		return "", fmt.Errorf("plutus/blob: sign tx: %w", err)
	}
	txHash, err := c.broadcaster.BroadcastTx(ctx, c.chainID, signed)
	if err != nil {
		return "", fmt.Errorf("plutus/blob: broadcast tx: %w", err)
	}
	return txHash, nil
}

// ─── Revert classification helpers ────────────────────────────────────

// IsBenignChallengeExpireRevert returns true when the given error from
// ExpireChallenge / ExpireChallengeAt is the contract's
// ChallengeWindowNotExpired / NoOpenChallenge revert — both indicate
// the replicator responded in time (either via Respond or by closing
// the challenge before expireChallenge fired), so the caller should
// treat the result as "no slashing needed" rather than a hard error.
//
// This is a best-effort substring match; the witness broadcaster wraps
// the revert reason in its error message. Callers that need precise
// classification (e.g. for metrics) should parse the revert-data hex
// themselves.
func IsBenignChallengeExpireRevert(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "ChallengeWindowNotExpired") ||
		strings.Contains(msg, "NoOpenChallenge") ||
		strings.Contains(msg, "0xec0f2a67") // rare: revert selector echoed by some rpcs
}

// ─── Helpers ──────────────────────────────────────────────────────────

// mustKeccakSelector computes the 4-byte Keccak-256 selector for a
// canonical Solidity function signature. Called once at package init
// for each selector constant.
func mustKeccakSelector(signature string) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(signature))
	sum := h.Sum(nil)
	out := make([]byte, 4)
	copy(out, sum[:4])
	return out
}

// isHexAddress validates a 20-byte 0x-prefixed hex address.
func isHexAddress(s string) bool {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// cidHashForString returns keccak256(cid-ASCII) — the same value the
// PlutusStorageEscrow constructor computed as the immutable cidHash.
// Exposed so callers with a Go-side CID string can derive the registry
// key without re-implementing the hash themselves.
func CIDHashForString(cid string) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write([]byte(cid))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ProofWindow returns the contract's CHALLENGE_WINDOW_SECONDS as a
// Go duration. Re-exported so callers that schedule an ExpireChallenge
// goroutine don't have to duplicate the magic number from the contract.
func ProofWindow() time.Duration { return 24 * time.Hour }
