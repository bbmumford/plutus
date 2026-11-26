/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/bbmumford/plutus/canonical"
	"github.com/bbmumford/whisper"
)

// ErrNoQuorum is returned when a balance query collects responses but fewer
// than policy.MinAgreement witnesses agreed on the same (balance, block_number).
var ErrNoQuorum = errors.New("witness/balance: no quorum on balance query")

// BalanceSnapshot is the raw chain-side reading returned by a
// ChainBalanceProvider. Witnesses use this to assemble a signed
// BalanceAttestation.
type BalanceSnapshot struct {
	Balance     *big.Int
	Decimals    uint64
	BlockHash   string
	BlockNumber uint64
	Timestamp   time.Time
}

// ChainBalanceProvider is the chain-specific adapter that a witness uses to
// read an address's balance. Implementations live in adapter/evm/balance.go
// and adapter/btc/balance.go. A provider is registered per chain_id on the
// BalanceVerifier via its Config; witnesses only serve queries for chains
// they have a registered provider for.
type ChainBalanceProvider interface {
	// QueryBalance returns the current balance for (addr, token) on the
	// provider's chain. token is empty for the chain's native asset (ETH,
	// MATIC, BTC...) and a contract address for ERC20-style tokens.
	QueryBalance(ctx context.Context, addr, token string) (BalanceSnapshot, error)
}

// BalanceQuery is the client-side request for a quorum-verified balance.
// Mirrors proto/plutus.BalanceQuery but kept as a native Go type for ergonomic
// internal use; the wire format is JSON-marshaled from this struct (matching
// the existing verifier.go attestRequest pattern).
type BalanceQuery struct {
	ChainID             string `json:"chainId"`
	Address             string `json:"address"`
	Token               string `json:"token,omitempty"`
	MaxAgeSeconds       uint64 `json:"maxAgeSeconds"`
	RequestNonce        []byte `json:"requestNonce"`
	ProtocolFingerprint string `json:"protocolFingerprint"`
	// OrderContext is a caller-chosen correlation string used to credit the
	// attesting witnesses at settlement time. When empty, attesters are
	// credited under the queried address. Not sent on the wire — witnesses
	// never see this, it only drives local bookkeeping.
	OrderContext string `json:"-"`
}

// BalanceAttestation is a witness's signed balance observation.
type BalanceAttestation struct {
	ChainID             string `json:"chainId"`
	Address             string `json:"address"`
	Token               string `json:"token,omitempty"`
	Balance             []byte `json:"balance"`
	Decimals            uint64 `json:"decimals"`
	BlockHash           string `json:"blockHash"`
	BlockNumber         uint64 `json:"blockNumber"`
	Timestamp           int64  `json:"timestamp"`
	RequestNonce        []byte `json:"requestNonce"`
	WitnessPubKey       []byte `json:"witnessPubkey"`
	Signature           []byte `json:"signature"`
	ProtocolFingerprint string `json:"protocolFingerprint"`
}

// BalanceResult is the outcome of a client-side balance query, once the
// verifier has collected and bucketed enough attestations.
type BalanceResult struct {
	ChainID        string
	Address        string
	Token          string
	Balance        *big.Int
	Decimals       uint64
	BlockNumber    uint64
	QuorumCount    uint64
	QuorumRequired uint64
	QuorumTotal    uint64
	Attestations   []BalanceAttestation
}

// balanceResponse is the wire envelope combining a request_id with the
// attestation. Witnesses publish one of these per query on the response topic.
type balanceResponse struct {
	RequestID   string              `json:"requestId"`
	Attestation *BalanceAttestation `json:"attestation"`
	Error       string              `json:"error,omitempty"`
}

// balanceRequestEnvelope carries a BalanceQuery with a request_id so client
// and witnesses can correlate responses to the originating request. Not to be
// confused with the wire BalanceQuery itself — the request_id is transport
// metadata that never reaches the witness's signed attestation.
type balanceRequestEnvelope struct {
	RequestID string       `json:"requestId"`
	Query     BalanceQuery `json:"query"`
}

// balancePendingRequest holds the in-flight state for one client-side query.
type balancePendingRequest struct {
	query     BalanceQuery
	responses []BalanceAttestation
	done      chan struct{}
}

// BalanceVerifierConfig configures a BalanceVerifier. All fields are optional;
// zero values produce sensible defaults.
type BalanceVerifierConfig struct {
	// Policy is the K-of-N quorum for balance queries. Defaults to BalancePolicy.
	Policy VerificationPolicy

	// CacheTTL is the TTL for the client-side balance cache. Defaults to 30s.
	CacheTTL time.Duration

	// Providers maps chain_id to the ChainBalanceProvider a witness will use
	// to serve queries. Leaving this nil or empty is valid for client-only
	// verifiers (they still publish queries and collect responses).
	Providers map[string]ChainBalanceProvider

	// WitnessPrivKey is the Ed25519 private key witnesses sign attestations
	// with. Required for Run() (witness side); unused by QueryBalance().
	WitnessPrivKey ed25519.PrivateKey
}

// BalanceVerifier implements witness-mesh balance queries. A single instance
// serves both roles: as a client it publishes queries and collects attestations
// via QueryBalance; as a witness it subscribes to requests, reads the chain via
// its registered providers, and publishes signed attestations via Run.
//
// PRIVACY NOTE (spec §Privacy): v1 does NOT implement query mixing or
// dummy-address batching. Every witness sees every queried (address, token).
// Layer-B per-order keys cover transaction privacy but main-wallet balance
// queries are observable. Callers who care should use short-lived derived
// addresses for the queries they want to hide.
type BalanceVerifier struct {
	engine    *whisper.Engine
	policy    VerificationPolicy
	providers map[string]ChainBalanceProvider
	privKey   ed25519.PrivateKey
	cache     *balanceCache

	mu      sync.Mutex
	pending map[string]*balancePendingRequest
	runCtx  context.Context // set by Run; used for provider QueryBalance calls

	// attestLog tracks recent successful BalanceAttestations so a subsequent
	// settlement can credit the witnesses that produced them. Keyed by
	// orderContext (caller-supplied correlation — typically order ID or
	// address); each entry is a bounded FIFO of witness pubkeys (hex).
	attestLog map[string]*attestationWindow
}

// attestationWindow is a bounded FIFO of recent balance attesters for one
// order context. Both a count and a time cap apply.
type attestationWindow struct {
	entries []attestationEntry
}

type attestationEntry struct {
	witnessHex string
	at         time.Time
}

const (
	// balanceAttestWindowSize bounds the number of attestations remembered per
	// order context. Matches the "last 100 queries" cap in the task brief.
	balanceAttestWindowSize = 100
	// balanceAttestWindowTTL bounds the age of attestations eligible for
	// settlement credit. Matches the 24h cap in the task brief.
	balanceAttestWindowTTL = 24 * time.Hour
)

// NewBalanceVerifier constructs a BalanceVerifier wired to the given whisper
// engine. It subscribes to the balance.response topic immediately so client
// QueryBalance calls can collect responses.
func NewBalanceVerifier(engine *whisper.Engine, cfg BalanceVerifierConfig) *BalanceVerifier {
	policy := cfg.Policy
	if policy.MinAgreement == 0 {
		policy = BalancePolicy
	}
	providers := cfg.Providers
	if providers == nil {
		providers = make(map[string]ChainBalanceProvider)
	}
	v := &BalanceVerifier{
		engine:    engine,
		policy:    policy,
		providers: providers,
		privKey:   cfg.WitnessPrivKey,
		cache:     newBalanceCache(cfg.CacheTTL),
		pending:   make(map[string]*balancePendingRequest),
		attestLog: make(map[string]*attestationWindow),
	}
	// Register topics (idempotent — RegisterTopic returns an error on dup
	// registration which we deliberately ignore to match the pattern used in
	// other witness-package constructors).
	_ = engine.RegisterTopic(canonical.BalanceRequestTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	_ = engine.RegisterTopic(canonical.BalanceResponseTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	engine.Subscribe(canonical.BalanceResponseTopic(), &balanceResponseSubscriber{v: v})
	// Register the request subscriber unconditionally; handleRequest is a
	// no-op when no provider serves the queried chain. Doing it here rather
	// than in Run avoids a startup race where the client publishes before
	// witnesses finish goroutine scheduling.
	engine.Subscribe(canonical.BalanceRequestTopic(), &balanceRequestSubscriber{v: v})
	return v
}

// RegisterProvider adds or replaces the ChainBalanceProvider for a chain.
// Safe to call after Run has started.
func (v *BalanceVerifier) RegisterProvider(chainID string, provider ChainBalanceProvider) {
	v.mu.Lock()
	v.providers[chainID] = provider
	v.mu.Unlock()
}

// RecordBalanceAttestation credits the given witness for a successful balance
// attestation served in the context of orderContext. The attestation is held
// in a bounded per-context FIFO (size balanceAttestWindowSize, TTL
// balanceAttestWindowTTL); subsequent settlement of orderContext can fetch
// the attesters via RecentBalanceAttesters and split the witness fee among
// them. orderContext is a caller-chosen correlation string — typically the
// order ID or the queried address — and may be empty, in which case the
// call is a no-op (i.e. the caller is opting out of settlement credit).
func (v *BalanceVerifier) RecordBalanceAttestation(witnessPubkey ed25519.PublicKey, orderContext string) {
	if orderContext == "" || len(witnessPubkey) != ed25519.PublicKeySize {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	win, ok := v.attestLog[orderContext]
	if !ok {
		win = &attestationWindow{}
		v.attestLog[orderContext] = win
	}
	win.entries = append(win.entries, attestationEntry{
		witnessHex: hex.EncodeToString(witnessPubkey),
		at:         time.Now(),
	})
	// Trim to window size.
	if over := len(win.entries) - balanceAttestWindowSize; over > 0 {
		win.entries = win.entries[over:]
	}
}

// RecentBalanceAttesters returns the distinct hex-encoded witness pubkeys that
// have attested balance queries for orderContext within the most recent
// balanceAttestWindowSize entries and balanceAttestWindowTTL time window.
// Entries that exceed the TTL are pruned as a side effect. Returns an empty
// slice (never nil-check required at call sites) if no attestations match.
func (v *BalanceVerifier) RecentBalanceAttesters(orderContext string) []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	win, ok := v.attestLog[orderContext]
	if !ok {
		return nil
	}
	cutoff := time.Now().Add(-balanceAttestWindowTTL)
	// Drop expired entries from the front (entries appended in time order).
	i := 0
	for i < len(win.entries) && win.entries[i].at.Before(cutoff) {
		i++
	}
	if i > 0 {
		win.entries = win.entries[i:]
	}
	if len(win.entries) == 0 {
		delete(v.attestLog, orderContext)
		return nil
	}
	seen := make(map[string]struct{}, len(win.entries))
	out := make([]string, 0, len(win.entries))
	for _, e := range win.entries {
		if _, dup := seen[e.witnessHex]; dup {
			continue
		}
		seen[e.witnessHex] = struct{}{}
		out = append(out, e.witnessHex)
	}
	return out
}

// SplitWitnessFee produces a per-witness distribution map over the given
// attesters such that the values sum to witnessFee exactly. The split is equal,
// and the remainder integer truncation leaves goes to the attester whose name
// sorts first, so no wei/sats are lost and every node computes the same split
// whatever order its attesters arrived in (RecentBalanceAttesters returns them
// in the order this node received them). An attester named more than once is one recipient: the shares
// are counted over distinct attesters, because the map holds one entry per
// attester and a repeated name would otherwise overwrite its own share and
// leave the rest of the fee unassigned. Returns nil when attesters is empty
// (the caller pays the whole fee to a single recipient) or when witnessFee is
// non-positive.
func SplitWitnessFee(witnessFee *big.Int, attesters []string) map[string]*big.Int {
	if witnessFee == nil || witnessFee.Sign() <= 0 || len(attesters) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(attesters))
	distinct := make([]string, 0, len(attesters))
	for _, k := range attesters {
		if _, dup := seen[k]; dup {
			continue
		}
		seen[k] = struct{}{}
		distinct = append(distinct, k)
	}
	sort.Strings(distinct)
	attesters = distinct
	n := big.NewInt(int64(len(attesters)))
	share := new(big.Int).Quo(witnessFee, n)
	remainder := new(big.Int).Sub(witnessFee, new(big.Int).Mul(share, n))
	out := make(map[string]*big.Int, len(attesters))
	for i, k := range attesters {
		amt := new(big.Int).Set(share)
		if i == 0 {
			amt.Add(amt, remainder) // absorb truncation dust
		}
		out[k] = amt
	}
	return out
}

// QueryCached returns the cached BalanceResult for (chainID, address, token)
// or nil if none exists / it has expired. Non-blocking; safe to call from UI
// paths like publishState that must not issue a mesh roundtrip.
func (v *BalanceVerifier) QueryCached(chainID, address, token string) *BalanceResult {
	return v.cache.Get(chainID, address, token)
}

// QueryBalance asks the mesh for a balance on (q.ChainID, q.Address, q.Token)
// and applies a K-of-N quorum to the returned attestations. On cache hit
// within BalanceVerifierConfig.CacheTTL, returns immediately without mesh
// traffic.
func (v *BalanceVerifier) QueryBalance(ctx context.Context, q BalanceQuery) (*BalanceResult, error) {
	if q.ChainID == "" {
		return nil, errors.New("witness/balance: chainID required")
	}
	if q.Address == "" {
		return nil, errors.New("witness/balance: address required")
	}

	if cached := v.cache.Get(q.ChainID, q.Address, q.Token); cached != nil {
		return cached, nil
	}

	if len(q.RequestNonce) == 0 {
		q.RequestNonce = make([]byte, 16)
		if _, err := rand.Read(q.RequestNonce); err != nil {
			return nil, fmt.Errorf("witness/balance: generate nonce: %w", err)
		}
	}
	if q.MaxAgeSeconds == 0 {
		q.MaxAgeSeconds = 60
	}
	q.ProtocolFingerprint = canonical.ProtocolFingerprint()

	reqID := fmt.Sprintf("bal-%d", time.Now().UnixNano())
	pr := &balancePendingRequest{
		query: q,
		done:  make(chan struct{}, v.policy.MinWitnesses),
	}

	v.mu.Lock()
	v.pending[reqID] = pr
	v.mu.Unlock()
	defer func() {
		v.mu.Lock()
		delete(v.pending, reqID)
		v.mu.Unlock()
	}()

	envelope, err := json.Marshal(balanceRequestEnvelope{RequestID: reqID, Query: q})
	if err != nil {
		return nil, fmt.Errorf("witness/balance: marshal request: %w", err)
	}
	if err := v.engine.Publish(canonical.BalanceRequestTopic(), envelope); err != nil {
		return nil, fmt.Errorf("witness/balance: publish request: %w", err)
	}

	deadline := time.After(v.policy.Timeout)
	for {
		v.mu.Lock()
		count := len(pr.responses)
		v.mu.Unlock()
		if count >= v.policy.MinWitnesses {
			break
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("witness/balance: context cancelled: %w", ctx.Err())
		case <-deadline:
			goto evaluate
		case <-pr.done:
		}
	}

evaluate:
	v.mu.Lock()
	collected := make([]BalanceAttestation, len(pr.responses))
	copy(collected, pr.responses)
	v.mu.Unlock()

	result, err := v.applyQuorum(q, collected)
	if err != nil {
		return nil, err
	}
	v.cache.Put(q.ChainID, q.Address, q.Token, result)

	// Record each winning attester against the caller-supplied order context
	// (or the queried address as fallback) so the next settlement can credit
	// a share of the witness fee to them.
	orderKey := q.OrderContext
	if orderKey == "" {
		orderKey = q.ChainID + ":" + q.Address
	}
	for _, att := range result.Attestations {
		v.RecordBalanceAttestation(ed25519.PublicKey(att.WitnessPubKey), orderKey)
	}
	return result, nil
}

// applyQuorum buckets attestations by (balance, block_number) and returns the
// bucket with the most agreement — provided it clears policy.MinAgreement.
func (v *BalanceVerifier) applyQuorum(q BalanceQuery, atts []BalanceAttestation) (*BalanceResult, error) {
	type bucketKey struct {
		balance     string
		blockNumber uint64
	}
	buckets := make(map[bucketKey][]BalanceAttestation)
	for _, a := range atts {
		balStr := new(big.Int).SetBytes(a.Balance).String()
		key := bucketKey{balance: balStr, blockNumber: a.BlockNumber}
		buckets[key] = append(buckets[key], a)
	}

	var bestKey bucketKey
	var bestCount int
	for k, bucket := range buckets {
		if len(bucket) > bestCount {
			bestKey = k
			bestCount = len(bucket)
		}
	}

	if bestCount < v.policy.MinAgreement {
		return nil, fmt.Errorf("%w: got %d responses, %d agreed, need %d",
			ErrNoQuorum, len(atts), bestCount, v.policy.MinAgreement)
	}

	winning := buckets[bestKey]
	first := winning[0]
	return &BalanceResult{
		ChainID:        q.ChainID,
		Address:        q.Address,
		Token:          q.Token,
		Balance:        new(big.Int).SetBytes(first.Balance),
		Decimals:       first.Decimals,
		BlockNumber:    first.BlockNumber,
		QuorumCount:    uint64(bestCount),
		QuorumRequired: uint64(v.policy.MinAgreement),
		QuorumTotal:    uint64(len(atts)),
		Attestations:   atts,
	}, nil
}

// Run starts the witness-side loop: handles balance.request messages with the
// given ctx for provider-call cancellation. Returns when ctx is cancelled.
// Requires WitnessPrivKey and at least one Provider to be configured.
//
// Note: subscription to the request topic is performed by NewBalanceVerifier
// at construction time (provided WitnessPrivKey was set) so that subscribers
// are registered synchronously. Run exists to bind provider-side context and
// block until shutdown.
func (v *BalanceVerifier) Run(ctx context.Context) error {
	if len(v.privKey) != ed25519.PrivateKeySize {
		return errors.New("witness/balance: WitnessPrivKey not configured")
	}
	v.mu.Lock()
	if len(v.providers) == 0 {
		v.mu.Unlock()
		return errors.New("witness/balance: no ChainBalanceProviders registered")
	}
	v.mu.Unlock()

	// Bind the run-ctx to the already-registered request subscriber.
	v.setRunCtx(ctx)
	<-ctx.Done()
	return ctx.Err()
}

// setRunCtx swaps the request subscriber's context. Called by Run.
func (v *BalanceVerifier) setRunCtx(ctx context.Context) {
	v.mu.Lock()
	v.runCtx = ctx
	v.mu.Unlock()
}

// getRunCtx returns the current run context (or Background if none).
func (v *BalanceVerifier) getRunCtx() context.Context {
	v.mu.Lock()
	ctx := v.runCtx
	v.mu.Unlock()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// handleRequest is called by the request-topic subscriber for each incoming
// query. It validates the fingerprint, calls the registered provider, signs
// the attestation, and publishes it on the response topic.
func (v *BalanceVerifier) handleRequest(ctx context.Context, payload []byte) {
	var env balanceRequestEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return
	}
	if env.Query.ProtocolFingerprint != "" &&
		env.Query.ProtocolFingerprint != canonical.ProtocolFingerprint() {
		return
	}

	v.mu.Lock()
	provider, ok := v.providers[env.Query.ChainID]
	v.mu.Unlock()
	if !ok {
		return // we don't serve this chain; silently ignore
	}

	queryCtx, cancel := context.WithTimeout(ctx, v.policy.Timeout)
	defer cancel()
	snap, err := provider.QueryBalance(queryCtx, env.Query.Address, env.Query.Token)
	if err != nil {
		return // let other witnesses respond; don't publish negative attestations
	}
	if snap.Balance == nil {
		snap.Balance = new(big.Int)
	}

	att := BalanceAttestation{
		ChainID:             env.Query.ChainID,
		Address:             env.Query.Address,
		Token:               env.Query.Token,
		Balance:             snap.Balance.Bytes(),
		Decimals:            snap.Decimals,
		BlockHash:           snap.BlockHash,
		BlockNumber:         snap.BlockNumber,
		Timestamp:           snap.Timestamp.Unix(),
		RequestNonce:        env.Query.RequestNonce,
		WitnessPubKey:       v.privKey.Public().(ed25519.PublicKey),
		ProtocolFingerprint: canonical.ProtocolFingerprint(),
	}
	if att.Timestamp == 0 {
		att.Timestamp = time.Now().Unix()
	}
	att.Signature = ed25519.Sign(v.privKey, balanceAttestationDigest(&att))

	resp := balanceResponse{RequestID: env.RequestID, Attestation: &att}
	data, err := json.Marshal(resp)
	if err != nil {
		return
	}
	_ = v.engine.Publish(canonical.BalanceResponseTopic(), data)
}

// handleResponse is called by the response-topic subscriber. It validates the
// attestation and delivers it to the matching pending request.
func (v *BalanceVerifier) handleResponse(payload []byte) {
	var resp balanceResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return
	}
	if resp.Attestation == nil || resp.Error != "" {
		return
	}
	att := resp.Attestation

	// Reject attestations from a different fingerprint (fork isolation).
	localFP := canonical.ProtocolFingerprint()
	if localFP != "" && att.ProtocolFingerprint != localFP {
		return
	}
	if !verifyBalanceAttestation(att) {
		return
	}

	v.mu.Lock()
	pr, ok := v.pending[resp.RequestID]
	if !ok {
		v.mu.Unlock()
		return
	}

	// Replay guard: nonce must match the originating query.
	if len(pr.query.RequestNonce) > 0 &&
		!bytesEqual(att.RequestNonce, pr.query.RequestNonce) {
		v.mu.Unlock()
		return
	}

	// Stale guard: reject snapshots older than MaxAgeSeconds.
	if pr.query.MaxAgeSeconds > 0 {
		age := time.Now().Unix() - att.Timestamp
		if age > int64(pr.query.MaxAgeSeconds) {
			v.mu.Unlock()
			return
		}
	}

	// Duplicate-witness guard: only one attestation per witness pubkey.
	for _, existing := range pr.responses {
		if bytesEqual(existing.WitnessPubKey, att.WitnessPubKey) {
			v.mu.Unlock()
			return
		}
	}

	pr.responses = append(pr.responses, *att)
	v.mu.Unlock()

	select {
	case pr.done <- struct{}{}:
	default:
	}
}

// balanceAttestationDigest computes the canonical SHA-256 covering proto fields
// 1-10 of BalanceAttestation (everything except signature + fingerprint). The
// fingerprint is included via the Layer-4 fork-isolation check in
// handleResponse, not the signed digest.
func balanceAttestationDigest(a *BalanceAttestation) []byte {
	h := sha256.New()
	h.Write([]byte(a.ChainID))
	h.Write([]byte{0})
	h.Write([]byte(a.Address))
	h.Write([]byte{0})
	h.Write([]byte(a.Token))
	h.Write([]byte{0})
	h.Write(a.Balance)
	var u64 [8]byte
	binary.BigEndian.PutUint64(u64[:], a.Decimals)
	h.Write(u64[:])
	h.Write([]byte(a.BlockHash))
	h.Write([]byte{0})
	binary.BigEndian.PutUint64(u64[:], a.BlockNumber)
	h.Write(u64[:])
	binary.BigEndian.PutUint64(u64[:], uint64(a.Timestamp))
	h.Write(u64[:])
	h.Write(a.RequestNonce)
	h.Write(a.WitnessPubKey)
	return h.Sum(nil)
}

// verifyBalanceAttestation checks signature validity.
func verifyBalanceAttestation(a *BalanceAttestation) bool {
	if len(a.WitnessPubKey) != ed25519.PublicKeySize {
		return false
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(a.WitnessPubKey, balanceAttestationDigest(a), a.Signature)
}

// bytesEqual is a tiny stdlib-free equality helper.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// balanceRequestSubscriber dispatches request-topic messages to handleRequest.
// The context is read lazily via v.getRunCtx() so late changes from Run take
// effect without requiring unsubscribe/resubscribe.
type balanceRequestSubscriber struct {
	v *BalanceVerifier
}

func (s *balanceRequestSubscriber) OnBroadcast(topic string, from string, payload []byte) {
	// Witness-side: only respond if we have a private key (configured by Run
	// caller or SDK wiring). Client-only deployments set no privKey and
	// silently ignore incoming requests.
	if len(s.v.privKey) != ed25519.PrivateKeySize {
		return
	}
	s.v.handleRequest(s.v.getRunCtx(), payload)
}

// balanceResponseSubscriber dispatches response-topic messages to handleResponse.
type balanceResponseSubscriber struct {
	v *BalanceVerifier
}

func (s *balanceResponseSubscriber) OnBroadcast(topic string, from string, payload []byte) {
	s.v.handleResponse(payload)
}
