/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/bbmumford/plutus/canonical"
	"github.com/bbmumford/plutus/observability"
	"github.com/bbmumford/whisper"
	"go.opentelemetry.io/otel/attribute"
)

// topicAttestRequest and topicAttestResponse are resolved at init time from
// the protocol fingerprint for network isolation.
var (
	topicAttestRequest  string
	topicAttestResponse string
)

func init() {
	topicAttestRequest = canonical.AttestRequestTopic()
	topicAttestResponse = canonical.AttestResponseTopic()
}

// attestRequest is the wire format for an attestation request published on
// the plutus.attest.request topic. Witnesses that support the target chain
// respond with signed ChainWitnessAttestations on the response topic.
type attestRequest struct {
	RequestID  string `json:"requestId"`
	ChainID    string `json:"chainId"`
	Type       string `json:"type"` // "tx-confirm", "balance", "escrow-state"
	TxHash     string `json:"txHash,omitempty"`
	Address    string `json:"address,omitempty"`
	EscrowAddr string `json:"escrowAddr,omitempty"`
}

// attestResponse is the wire format for an attestation response.
type attestResponse struct {
	RequestID   string                   `json:"requestId"`
	Attestation *ChainWitnessAttestation `json:"attestation"`
	Error       string                   `json:"error,omitempty"`
}

// MeshVerifier implements quorum-based blockchain state verification via the
// witness mesh. It publishes attestation requests on the Whisper gossip
// network and collects signed responses from witnesses until the policy
// quorum is met.
type MeshVerifier struct {
	engine   *whisper.Engine
	registry *WitnessRegistry
	detector *CollusionDetector

	mu      sync.Mutex
	pending map[string]*pendingRequest // requestID -> pending
}

// pendingRequest tracks an in-flight attestation request and its collected
// responses.
type pendingRequest struct {
	responses []*ChainWitnessAttestation
	done      chan struct{}
}

// NewMeshVerifier creates a verifier wired to the Whisper engine. It
// subscribes to the attestation response topic to collect incoming
// attestations.
func NewMeshVerifier(engine *whisper.Engine, registry *WitnessRegistry, detector *CollusionDetector) *MeshVerifier {
	v := &MeshVerifier{
		engine:   engine,
		registry: registry,
		detector: detector,
		pending:  make(map[string]*pendingRequest),
	}
	engine.Subscribe(topicAttestResponse, v)
	return v
}

// OnBroadcast implements whisper.Subscriber. It receives attestation responses
// and routes them to the correct pending request.
func (v *MeshVerifier) OnBroadcast(topic string, from string, payload []byte) {
	var resp attestResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return
	}
	if resp.Attestation == nil || resp.Error != "" {
		return
	}
	if !VerifyAttestation(resp.Attestation) {
		return
	}

	v.mu.Lock()
	pr, ok := v.pending[resp.RequestID]
	if ok {
		pr.responses = append(pr.responses, resp.Attestation)
	}
	v.mu.Unlock()

	if ok {
		select {
		case pr.done <- struct{}{}:
		default:
		}
	}
}

// IsConfirmed publishes a transaction confirmation request on the
// plutus.attest.request topic and waits for enough witnesses to agree.
// Returns true only when at least policy.MinAgreement witnesses confirm the
// transaction, with collusion-suspicious witnesses excluded.
func (v *MeshVerifier) IsConfirmed(ctx context.Context, chainID string, txHash string, policy VerificationPolicy) (bool, error) {
	ctx, span := observability.Tracer("plutus.witness").Start(ctx, "MeshVerifier.IsConfirmed")
	defer span.End()
	span.SetAttributes(
		attribute.String(observability.AttrChainID, chainID),
		attribute.String(observability.AttrTxHash, txHash),
	)
	start := time.Now()
	defer func() {
		observability.WitnessVerifyDuration().Record(ctx, float64(time.Since(start).Milliseconds()))
	}()
	observability.WitnessAttestCount().Add(ctx, 1)

	if chainID == "" {
		err := fmt.Errorf("witness: chain ID is required")
		observability.RecordError(span, err)
		return false, err
	}
	if txHash == "" {
		err := fmt.Errorf("witness: tx hash is required")
		observability.RecordError(span, err)
		return false, err
	}

	reqID := fmt.Sprintf("attest-%d", time.Now().UnixNano())

	req := attestRequest{
		RequestID: reqID,
		ChainID:   chainID,
		Type:      "tx-confirm",
		TxHash:    txHash,
	}

	responses, err := v.publishAndCollect(ctx, reqID, req, policy)
	if err != nil {
		observability.RecordError(span, err)
		return false, err
	}

	// Count how many unique, non-suspicious witnesses confirmed.
	// If the policy requires Merkle proofs, reject attestations without them.
	confirmed := 0
	for _, att := range responses {
		if att.Confirmed && !v.detector.IsSuspicious(string(att.WitnessPubKey)) {
			if !VerifyMerkleProofPresence(att, policy.RequireMerkleProof) {
				continue
			}
			confirmed++
		}
	}

	ok := confirmed >= policy.MinAgreement
	if !ok {
		observability.WitnessQuorumFailures().Add(ctx, 1)
	}
	return ok, nil
}

// AttestBalance publishes a balance query on the attestation request topic
// and returns the balance that a quorum of witnesses agreed on. Uses the
// Standard verification policy (3 witnesses, 2 agree).
func (v *MeshVerifier) AttestBalance(ctx context.Context, chainID string, addr string) (*big.Int, error) {
	ctx, span := observability.Tracer("plutus.witness").Start(ctx, "MeshVerifier.AttestBalance")
	defer span.End()
	span.SetAttributes(attribute.String(observability.AttrChainID, chainID))
	observability.WitnessBalanceQueries().Add(ctx, 1)

	if chainID == "" {
		err := fmt.Errorf("witness: chain ID is required")
		observability.RecordError(span, err)
		return nil, err
	}
	if addr == "" {
		err := fmt.Errorf("witness: address is required")
		observability.RecordError(span, err)
		return nil, err
	}

	policy := PolicyForValue(50) // Standard tier for balance queries
	reqID := fmt.Sprintf("bal-%d", time.Now().UnixNano())

	req := attestRequest{
		RequestID: reqID,
		ChainID:   chainID,
		Type:      "balance",
		Address:   addr,
	}

	responses, err := v.publishAndCollect(ctx, reqID, req, policy)
	if err != nil {
		return nil, err
	}

	// Find the balance value with quorum agreement.
	// If the policy requires Merkle proofs, skip attestations without them.
	balanceCounts := make(map[string]int)
	balanceValues := make(map[string]*big.Int)
	for _, att := range responses {
		if att.Balance == nil {
			continue
		}
		if v.detector.IsSuspicious(string(att.WitnessPubKey)) {
			continue
		}
		if !VerifyMerkleProofPresence(att, policy.RequireMerkleProof) {
			continue
		}
		key := att.Balance.String()
		balanceCounts[key]++
		balanceValues[key] = att.Balance
	}

	for key, count := range balanceCounts {
		if count >= policy.MinAgreement {
			return balanceValues[key], nil
		}
	}

	return nil, fmt.Errorf("witness: no quorum on balance for %s (got %d responses, need %d agreement)", addr, len(responses), policy.MinAgreement)
}

// AttestPRCState publishes a PRC state query on the attestation request topic
// and returns the raw PRC data that a quorum of witnesses agreed on. Witnesses
// read the PRC's public view functions (maintainerFeeBPS, witnessBPS,
// maintainerPayout, maintainerPubKeyHash) via eth_call and return encoded state.
// Uses the Standard verification policy (3 witnesses, 2 agree).
func (v *MeshVerifier) AttestPRCState(ctx context.Context, chainID string, prcAddr string) ([]byte, error) {
	if chainID == "" {
		return nil, fmt.Errorf("witness: chain ID is required")
	}
	if prcAddr == "" {
		return nil, fmt.Errorf("witness: PRC address is required")
	}

	policy := PolicyForValue(50) // Standard tier for PRC queries
	reqID := fmt.Sprintf("prc-%d", time.Now().UnixNano())

	req := attestRequest{
		RequestID: reqID,
		ChainID:   chainID,
		Type:      "prc-state",
		Address:   prcAddr,
	}

	responses, err := v.publishAndCollect(ctx, reqID, req, policy)
	if err != nil {
		return nil, err
	}

	// Find the PRC state with quorum agreement by comparing raw balance bytes
	// (witnesses encode PRC view function results as the Balance field).
	balanceCounts := make(map[string]int)
	balanceValues := make(map[string]*big.Int)
	for _, att := range responses {
		if att.Balance == nil {
			continue
		}
		if v.detector.IsSuspicious(string(att.WitnessPubKey)) {
			continue
		}
		key := att.Balance.String()
		balanceCounts[key]++
		balanceValues[key] = att.Balance
	}

	// For PRC attestation, the raw bytes are encoded in the Balance field
	// as a big.Int (the witness packs the 60+ byte PRC data as a number).
	for key, count := range balanceCounts {
		if count >= policy.MinAgreement {
			return balanceValues[key].Bytes(), nil
		}
	}

	return nil, fmt.Errorf("witness: no quorum on PRC state for %s (got %d responses, need %d agreement)", prcAddr, len(responses), policy.MinAgreement)
}

// AttestEscrowState publishes an escrow state query and returns the snapshot
// that a quorum of witnesses agreed on. Uses the High verification policy
// (5 witnesses, 4 agree) because escrow state is high-value.
func (v *MeshVerifier) AttestEscrowState(ctx context.Context, chainID string, escrowAddr string) (*EscrowSnapshot, error) {
	ctx, span := observability.Tracer("plutus.witness").Start(ctx, "MeshVerifier.AttestEscrowState")
	defer span.End()
	span.SetAttributes(
		attribute.String(observability.AttrChainID, chainID),
		attribute.String(observability.AttrEscrowAddr, escrowAddr),
	)

	if chainID == "" {
		err := fmt.Errorf("witness: chain ID is required")
		observability.RecordError(span, err)
		return nil, err
	}
	if escrowAddr == "" {
		err := fmt.Errorf("witness: escrow address is required")
		observability.RecordError(span, err)
		return nil, err
	}

	policy := PolicyForValue(500) // High tier for escrow queries
	reqID := fmt.Sprintf("esc-%d", time.Now().UnixNano())

	req := attestRequest{
		RequestID:  reqID,
		ChainID:    chainID,
		Type:       "escrow-state",
		EscrowAddr: escrowAddr,
	}

	responses, err := v.publishAndCollect(ctx, reqID, req, policy)
	if err != nil {
		return nil, err
	}

	// Find the escrow state with quorum agreement. We compare by hashing
	// the snapshot fields to find agreement.
	type snapshotKey struct {
		address   string
		buyer     string
		seller    string
		amount    string
		status    EscrowSnapshotStatus
		timeoutAt uint64
	}

	snapCounts := make(map[snapshotKey]int)
	snapValues := make(map[snapshotKey]*EscrowSnapshot)

	for _, att := range responses {
		if att.EscrowState == nil {
			continue
		}
		if v.detector.IsSuspicious(string(att.WitnessPubKey)) {
			continue
		}
		if !VerifyMerkleProofPresence(att, policy.RequireMerkleProof) {
			continue
		}
		amountStr := "0"
		if att.EscrowState.Amount != nil {
			amountStr = att.EscrowState.Amount.String()
		}
		key := snapshotKey{
			address:   att.EscrowState.Address,
			buyer:     att.EscrowState.Buyer,
			seller:    att.EscrowState.Seller,
			amount:    amountStr,
			status:    att.EscrowState.Status,
			timeoutAt: att.EscrowState.TimeoutAt,
		}
		snapCounts[key]++
		snapValues[key] = att.EscrowState
	}

	for key, count := range snapCounts {
		if count >= policy.MinAgreement {
			return snapValues[key], nil
		}
	}

	return nil, fmt.Errorf("witness: no quorum on escrow state for %s (got %d responses, need %d agreement)", escrowAddr, len(responses), policy.MinAgreement)
}

// publishAndCollect publishes an attestation request and collects responses
// until the policy quorum is met or the timeout expires.
func (v *MeshVerifier) publishAndCollect(ctx context.Context, reqID string, req attestRequest, policy VerificationPolicy) ([]*ChainWitnessAttestation, error) {
	pr := &pendingRequest{
		done: make(chan struct{}, policy.MinWitnesses),
	}

	v.mu.Lock()
	v.pending[reqID] = pr
	v.mu.Unlock()

	defer func() {
		v.mu.Lock()
		delete(v.pending, reqID)
		v.mu.Unlock()
	}()

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("witness: marshal attest request: %w", err)
	}

	if err := v.engine.Publish(topicAttestRequest, payload); err != nil {
		return nil, fmt.Errorf("witness: publish attest request: %w", err)
	}

	// Derive a deadline from the policy timeout
	deadline := time.After(policy.Timeout)

	for {
		v.mu.Lock()
		count := len(pr.responses)
		v.mu.Unlock()

		if count >= policy.MinWitnesses {
			break
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("witness: attestation cancelled: %w", ctx.Err())
		case <-deadline:
			// Return what we have — caller decides if it's enough
			v.mu.Lock()
			result := make([]*ChainWitnessAttestation, len(pr.responses))
			copy(result, pr.responses)
			v.mu.Unlock()
			return result, nil
		case <-pr.done:
			// New response arrived, loop to check count
		}
	}

	v.mu.Lock()
	result := make([]*ChainWitnessAttestation, len(pr.responses))
	copy(result, pr.responses)
	v.mu.Unlock()

	// Record pairwise agreements for collusion detection
	for i := 0; i < len(result); i++ {
		for j := i + 1; j < len(result); j++ {
			if attestationsAgree(result[i], result[j]) {
				v.detector.RecordAgreement(
					string(result[i].WitnessPubKey),
					string(result[j].WitnessPubKey),
				)
			}
		}
	}

	return result, nil
}

// attestationsAgree returns true if two attestations report the same state
// for the same query. Agreement is determined by matching chain ID, tx hash,
// confirmation status, balance, and escrow state.
func attestationsAgree(a, b *ChainWitnessAttestation) bool {
	if a.ChainID != b.ChainID {
		return false
	}
	if a.TxHash != b.TxHash {
		return false
	}
	if a.Confirmed != b.Confirmed {
		return false
	}

	// Balance agreement
	if a.Balance != nil && b.Balance != nil {
		if a.Balance.Cmp(b.Balance) != 0 {
			return false
		}
	} else if (a.Balance == nil) != (b.Balance == nil) {
		return false
	}

	// Escrow state agreement (both nil = agree, both non-nil must match)
	if a.EscrowState != nil && b.EscrowState != nil {
		if !escrowSnapshotsMatch(a.EscrowState, b.EscrowState) {
			return false
		}
	} else if (a.EscrowState == nil) != (b.EscrowState == nil) {
		return false
	}

	return true
}

// escrowSnapshotsMatch returns true if two escrow snapshots describe the
// same state.
func escrowSnapshotsMatch(a, b *EscrowSnapshot) bool {
	if a.Address != b.Address || a.Buyer != b.Buyer || a.Seller != b.Seller {
		return false
	}
	if a.Status != b.Status {
		return false
	}
	if a.TimeoutAt != b.TimeoutAt {
		return false
	}

	// Amount comparison
	if a.Amount != nil && b.Amount != nil {
		return a.Amount.Cmp(b.Amount) == 0
	}
	return (a.Amount == nil) == (b.Amount == nil)
}
