/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 */
package witness

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/bbmumford/plutus/canonical"
	"github.com/bbmumford/whisper"
)

// registerAttestTopics registers the attest request/response topics on the
// engine so MeshVerifier's Publish calls succeed. In production these are
// registered by upstream wiring (mercury-node).
func registerAttestTopics(t *testing.T, e *whisper.Engine) {
	t.Helper()
	_ = e.RegisterTopic(canonical.AttestRequestTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	_ = e.RegisterTopic(canonical.AttestResponseTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
}

// fakeWitness simulates a remote witness that responds to attestation requests.
// It subscribes to the request topic and publishes signed responses according
// to a programmable response function.
type fakeWitness struct {
	engine  *whisper.Engine
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	respond func(req attestRequest) *ChainWitnessAttestation // nil = no response

	mu           sync.Mutex
	requestsSeen int
}

func newFakeWitness(engine *whisper.Engine, respond func(req attestRequest) *ChainWitnessAttestation) *fakeWitness {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	w := &fakeWitness{engine: engine, priv: priv, pub: pub, respond: respond}
	engine.Subscribe(canonical.AttestRequestTopic(), w)
	return w
}

func (w *fakeWitness) OnBroadcast(topic string, from string, payload []byte) {
	if topic != canonical.AttestRequestTopic() {
		return
	}
	var req attestRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return
	}
	w.mu.Lock()
	w.requestsSeen++
	w.mu.Unlock()

	att := w.respond(req)
	if att == nil {
		return
	}
	att.WitnessPubKey = w.pub
	// Sign if not already signed.
	if len(att.Signature) == 0 {
		_ = SignAttestation(att, w.priv)
	}

	resp := attestResponse{RequestID: req.RequestID, Attestation: att}
	data, _ := json.Marshal(resp)
	_ = w.engine.Publish(canonical.AttestResponseTopic(), data)
}

// meshFixture wires a MeshVerifier with N fake witnesses to one engine.
type meshFixture struct {
	engine   *whisper.Engine
	registry *WitnessRegistry
	detector *CollusionDetector
	verifier *MeshVerifier
	witnesses []*fakeWitness
}

func newMeshFixture(t *testing.T) *meshFixture {
	t.Helper()
	engine := whisper.NewEngine()
	registerAttestTopics(t, engine)
	detector := NewCollusionDetector()
	// Skip NewWitnessRegistry which wants a real cache — tests don't need it.
	reg := &WitnessRegistry{engine: engine, entries: map[string]*WitnessRegistration{}}
	verifier := NewMeshVerifier(engine, reg, detector)
	return &meshFixture{
		engine:   engine,
		registry: reg,
		detector: detector,
		verifier: verifier,
	}
}

func (f *meshFixture) addWitness(respond func(req attestRequest) *ChainWitnessAttestation) *fakeWitness {
	w := newFakeWitness(f.engine, respond)
	f.witnesses = append(f.witnesses, w)
	return w
}

// --- Tests ---

func TestIsConfirmed_QuorumReached_Quick(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	// Quick policy wants 1 witness, 1 agree; $5 is Quick.
	f.addWitness(func(req attestRequest) *ChainWitnessAttestation {
		return &ChainWitnessAttestation{
			ChainID:   req.ChainID,
			TxHash:    req.TxHash,
			Confirmed: true,
			Timestamp: time.Now(),
		}
	})

	policy := PolicyForValue(5)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ok, err := f.verifier.IsConfirmed(ctx, "ethereum", "0xabc", policy)
	if err != nil {
		t.Fatalf("IsConfirmed: %v", err)
	}
	if !ok {
		t.Error("expected confirmed with one agreeing witness")
	}
}

func TestIsConfirmed_StandardQuorum_2of3(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	// Standard policy wants 3 witnesses, 2 agree.
	confirmer := func(confirmed bool) func(attestRequest) *ChainWitnessAttestation {
		return func(req attestRequest) *ChainWitnessAttestation {
			return &ChainWitnessAttestation{
				ChainID:   req.ChainID,
				TxHash:    req.TxHash,
				Confirmed: confirmed,
				Timestamp: time.Now(),
			}
		}
	}
	f.addWitness(confirmer(true))
	f.addWitness(confirmer(true))
	f.addWitness(confirmer(false))

	policy := PolicyForValue(50)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ok, err := f.verifier.IsConfirmed(ctx, "ethereum", "0xabc", policy)
	if err != nil {
		t.Fatalf("IsConfirmed: %v", err)
	}
	if !ok {
		t.Error("expected confirmed with 2-of-3 agreement")
	}
}

func TestIsConfirmed_InsufficientAgreement(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	// 3 witnesses respond but only 1 confirms.
	f.addWitness(func(req attestRequest) *ChainWitnessAttestation {
		return &ChainWitnessAttestation{ChainID: req.ChainID, TxHash: req.TxHash, Confirmed: true, Timestamp: time.Now()}
	})
	f.addWitness(func(req attestRequest) *ChainWitnessAttestation {
		return &ChainWitnessAttestation{ChainID: req.ChainID, TxHash: req.TxHash, Confirmed: false, Timestamp: time.Now()}
	})
	f.addWitness(func(req attestRequest) *ChainWitnessAttestation {
		return &ChainWitnessAttestation{ChainID: req.ChainID, TxHash: req.TxHash, Confirmed: false, Timestamp: time.Now()}
	})

	policy := PolicyForValue(50)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ok, err := f.verifier.IsConfirmed(ctx, "ethereum", "0xabc", policy)
	if err != nil {
		t.Fatalf("IsConfirmed: %v", err)
	}
	if ok {
		t.Error("expected false with only 1 confirming witness against 2-agree requirement")
	}
}

func TestIsConfirmed_Validation(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	policy := PolicyForValue(5)
	if _, err := f.verifier.IsConfirmed(context.Background(), "", "0xabc", policy); err == nil {
		t.Error("expected chainID required")
	}
	if _, err := f.verifier.IsConfirmed(context.Background(), "ethereum", "", policy); err == nil {
		t.Error("expected txHash required")
	}
}

func TestAttestBalance_Quorum(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	agreeBalance := big.NewInt(12345)
	reply := func(req attestRequest) *ChainWitnessAttestation {
		return &ChainWitnessAttestation{
			ChainID:   req.ChainID,
			Balance:   new(big.Int).Set(agreeBalance),
			Timestamp: time.Now(),
		}
	}
	f.addWitness(reply)
	f.addWitness(reply)
	f.addWitness(func(req attestRequest) *ChainWitnessAttestation {
		return &ChainWitnessAttestation{
			ChainID:   req.ChainID,
			Balance:   big.NewInt(99999), // disagrees
			Timestamp: time.Now(),
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	bal, err := f.verifier.AttestBalance(ctx, "ethereum", "0xaddr")
	if err != nil {
		t.Fatalf("AttestBalance: %v", err)
	}
	if bal.Cmp(agreeBalance) != 0 {
		t.Errorf("balance: got %s, want %s", bal, agreeBalance)
	}
}

func TestAttestBalance_NoQuorum(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	// All three disagree on balance.
	for i := 0; i < 3; i++ {
		i := i
		f.addWitness(func(req attestRequest) *ChainWitnessAttestation {
			return &ChainWitnessAttestation{
				ChainID:   req.ChainID,
				Balance:   big.NewInt(int64(100 + i)),
				Timestamp: time.Now(),
			}
		})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := f.verifier.AttestBalance(ctx, "ethereum", "0xaddr"); err == nil {
		t.Error("expected no-quorum error")
	}
}

func TestAttestBalance_Validation(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	if _, err := f.verifier.AttestBalance(context.Background(), "", "0xaddr"); err == nil {
		t.Error("expected chainID required")
	}
	if _, err := f.verifier.AttestBalance(context.Background(), "ethereum", ""); err == nil {
		t.Error("expected address required")
	}
}

func TestAttestPRCState_QuorumAgreement(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	prcData := big.NewInt(0xDEADBEEF)
	reply := func(req attestRequest) *ChainWitnessAttestation {
		return &ChainWitnessAttestation{
			ChainID:   req.ChainID,
			Balance:   new(big.Int).Set(prcData),
			Timestamp: time.Now(),
		}
	}
	f.addWitness(reply)
	f.addWitness(reply)
	f.addWitness(reply)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, err := f.verifier.AttestPRCState(ctx, "ethereum", "0xprc")
	if err != nil {
		t.Fatalf("AttestPRCState: %v", err)
	}
	decoded := new(big.Int).SetBytes(got)
	if decoded.Cmp(prcData) != 0 {
		t.Errorf("prc data: got %s, want %s", decoded, prcData)
	}
}

func TestAttestPRCState_Validation(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	if _, err := f.verifier.AttestPRCState(context.Background(), "", "0xprc"); err == nil {
		t.Error("expected chainID required")
	}
	if _, err := f.verifier.AttestPRCState(context.Background(), "ethereum", ""); err == nil {
		t.Error("expected PRC address required")
	}
}

func TestAttestEscrowState_HighPolicy_Quorum(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)

	// High policy wants 5 witnesses, 4 agree, with Merkle proofs.
	escrow := &EscrowSnapshot{
		Address:   "0xE",
		Buyer:     "0xB",
		Seller:    "0xS",
		Amount:    big.NewInt(500),
		Status:    EscrowSnapshotStatusFunded,
		TimeoutAt: 100,
	}
	replyAgree := func(req attestRequest) *ChainWitnessAttestation {
		es := *escrow
		return &ChainWitnessAttestation{
			ChainID:     req.ChainID,
			EscrowState: &es,
			Timestamp:   time.Now(),
			MerkleRoot:  []byte("merkle-root"),
			MerkleProof: [][]byte{[]byte("proof-node")},
		}
	}
	// 4 agree, 1 disagrees.
	for i := 0; i < 4; i++ {
		f.addWitness(replyAgree)
	}
	f.addWitness(func(req attestRequest) *ChainWitnessAttestation {
		dis := &EscrowSnapshot{Address: "0xOther", Status: EscrowSnapshotStatusPending}
		return &ChainWitnessAttestation{
			ChainID:     req.ChainID,
			EscrowState: dis,
			Timestamp:   time.Now(),
			MerkleRoot:  []byte("merkle-root"),
			MerkleProof: [][]byte{[]byte("p")},
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	snap, err := f.verifier.AttestEscrowState(ctx, "ethereum", "0xE")
	if err != nil {
		t.Fatalf("AttestEscrowState: %v", err)
	}
	if snap.Address != "0xE" {
		t.Errorf("address: got %s, want 0xE", snap.Address)
	}
	if snap.Status != EscrowSnapshotStatusFunded {
		t.Errorf("status: got %d, want %d", snap.Status, EscrowSnapshotStatusFunded)
	}
}

func TestAttestEscrowState_MissingMerkleProofRejected(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	// All responses lack Merkle proofs at High policy — must fail.
	for i := 0; i < 5; i++ {
		f.addWitness(func(req attestRequest) *ChainWitnessAttestation {
			return &ChainWitnessAttestation{
				ChainID: req.ChainID,
				EscrowState: &EscrowSnapshot{
					Address: "0xE",
					Status:  EscrowSnapshotStatusFunded,
					Amount:  big.NewInt(500),
				},
				Timestamp: time.Now(),
				// no MerkleRoot, no MerkleProof
			}
		})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if _, err := f.verifier.AttestEscrowState(ctx, "ethereum", "0xE"); err == nil {
		t.Error("expected error: attestations lack Merkle proofs under High policy")
	}
}

func TestAttestEscrowState_Validation(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	if _, err := f.verifier.AttestEscrowState(context.Background(), "", "0xE"); err == nil {
		t.Error("expected chainID required")
	}
	if _, err := f.verifier.AttestEscrowState(context.Background(), "ethereum", ""); err == nil {
		t.Error("expected escrow address required")
	}
}

func TestMeshVerifier_OnBroadcast_RoutesResponses(t *testing.T) {
	t.Parallel()
	f := newMeshFixture(t)
	// Send a malformed response — it must be silently dropped.
	f.verifier.OnBroadcast(canonical.AttestResponseTopic(), "peer", []byte("not-json"))
	// Send a valid response with no pending request — must not panic.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	att := &ChainWitnessAttestation{
		ChainID:       "ethereum",
		TxHash:        "0xabc",
		Confirmed:     true,
		WitnessPubKey: pub,
		Timestamp:     time.Now(),
	}
	_ = SignAttestation(att, priv)
	resp := attestResponse{RequestID: "no-such-request", Attestation: att}
	data, _ := json.Marshal(resp)
	f.verifier.OnBroadcast(canonical.AttestResponseTopic(), "peer", data)

	// Send a response with Error set — must drop.
	errResp := attestResponse{RequestID: "x", Error: "bad", Attestation: att}
	data, _ = json.Marshal(errResp)
	f.verifier.OnBroadcast(canonical.AttestResponseTopic(), "peer", data)
}

// --- BroadcastService integration ---

func TestBroadcastService_SuccessfulTx(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	_ = engine.RegisterTopic(canonical.BroadcastTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	_ = engine.RegisterTopic(canonical.BroadcastResponseTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})

	svc := NewBroadcastService(engine)

	// Set up a fake broadcaster that publishes a success response for every
	// request on the broadcast topic.
	fakeResp := &fakeBroadcastResponder{engine: engine, txHash: "0xRESULT"}
	engine.Subscribe(canonical.BroadcastTopic(), fakeResp)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	txHash, err := svc.BroadcastTx(ctx, "ethereum", []byte("signed-tx"))
	if err != nil {
		t.Fatalf("BroadcastTx: %v", err)
	}
	if txHash != "0xRESULT" {
		t.Errorf("txHash: got %q, want 0xRESULT", txHash)
	}
}

func TestBroadcastService_ErrorResponse(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	_ = engine.RegisterTopic(canonical.BroadcastTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	_ = engine.RegisterTopic(canonical.BroadcastResponseTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	svc := NewBroadcastService(engine)

	fakeResp := &fakeBroadcastResponder{engine: engine, errStr: "rpc rejected"}
	engine.Subscribe(canonical.BroadcastTopic(), fakeResp)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := svc.BroadcastTx(ctx, "ethereum", []byte("signed-tx")); err == nil {
		t.Error("expected broadcast error response")
	}
}

func TestBroadcastService_Timeout(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	_ = engine.RegisterTopic(canonical.BroadcastTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	_ = engine.RegisterTopic(canonical.BroadcastResponseTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	svc := NewBroadcastService(engine)

	// No responder -- ctx must deadline.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := svc.BroadcastTx(ctx, "ethereum", []byte("signed-tx")); err == nil {
		t.Error("expected timeout error")
	}
}

func TestBroadcastService_Validation(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	_ = engine.RegisterTopic(canonical.BroadcastTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	_ = engine.RegisterTopic(canonical.BroadcastResponseTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	svc := NewBroadcastService(engine)

	if _, err := svc.BroadcastTx(context.Background(), "", []byte("x")); err == nil {
		t.Error("expected chainID required")
	}
	if _, err := svc.BroadcastTx(context.Background(), "ethereum", nil); err == nil {
		t.Error("expected signedTx required")
	}
}

func TestBroadcastService_OnBroadcast_MalformedDropped(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	_ = engine.RegisterTopic(canonical.BroadcastTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	_ = engine.RegisterTopic(canonical.BroadcastResponseTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})
	svc := NewBroadcastService(engine)

	// Malformed payload must not panic.
	svc.OnBroadcast(canonical.BroadcastResponseTopic(), "peer", []byte("not-json"))
	// Response for unknown requestID must be silently dropped.
	resp := broadcastResponse{RequestID: "no-such", TxHash: "0xabc"}
	data, _ := json.Marshal(resp)
	svc.OnBroadcast(canonical.BroadcastResponseTopic(), "peer", data)
}

// fakeBroadcastResponder subscribes to the broadcast topic and publishes
// a response for each incoming request.
type fakeBroadcastResponder struct {
	engine *whisper.Engine
	txHash string
	errStr string
}

func (r *fakeBroadcastResponder) OnBroadcast(topic string, from string, payload []byte) {
	if topic != canonical.BroadcastTopic() {
		return
	}
	var req broadcastRequest
	if err := json.Unmarshal(payload, &req); err != nil {
		return
	}
	resp := broadcastResponse{RequestID: req.RequestID, TxHash: r.txHash, Error: r.errStr}
	data, _ := json.Marshal(resp)
	_ = r.engine.Publish(canonical.BroadcastResponseTopic(), data)
}

// --- BalanceVerifier integration ---

// fakeBalanceProvider lets tests serve BalanceSnapshots for specific chains.
type fakeBalanceProvider struct {
	snapshot BalanceSnapshot
	err      error
}

func (p *fakeBalanceProvider) QueryBalance(ctx context.Context, addr, token string) (BalanceSnapshot, error) {
	if p.err != nil {
		return BalanceSnapshot{}, p.err
	}
	return p.snapshot, nil
}

func TestBalanceVerifier_QuerySucceeds(t *testing.T) {
	t.Parallel()
	// 3 co-located verifier+witness instances on one engine. Each registers a
	// provider and runs in the same process.
	engine := whisper.NewEngine()

	// Three witness-side verifiers sharing the engine.
	snap := BalanceSnapshot{
		Balance:     big.NewInt(4242),
		Decimals:    18,
		BlockHash:   "0xblock",
		BlockNumber: 1000,
		Timestamp:   time.Now(),
	}
	for i := 0; i < 3; i++ {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		wv := NewBalanceVerifier(engine, BalanceVerifierConfig{
			WitnessPrivKey: priv,
			Providers: map[string]ChainBalanceProvider{
				"ethereum": &fakeBalanceProvider{snapshot: snap},
			},
		})
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = wv.Run(ctx) }()
	}

	// Client-side verifier (also on the same engine).
	client := NewBalanceVerifier(engine, BalanceVerifierConfig{
		Policy: VerificationPolicy{MinWitnesses: 3, MinAgreement: 2, Timeout: 2 * time.Second},
	})

	// Give witnesses a moment to subscribe.
	time.Sleep(50 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := client.QueryBalance(ctx, BalanceQuery{
		ChainID:       "ethereum",
		Address:       "0xSomeone",
		MaxAgeSeconds: 3600,
	})
	if err != nil {
		t.Fatalf("QueryBalance: %v", err)
	}
	if result.Balance.Cmp(snap.Balance) != 0 {
		t.Errorf("balance: got %s, want %s", result.Balance, snap.Balance)
	}
	if result.QuorumCount < 2 {
		t.Errorf("quorum count: got %d, want >=2", result.QuorumCount)
	}
}

func TestBalanceVerifier_QueryValidation(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	v := NewBalanceVerifier(engine, BalanceVerifierConfig{})
	if _, err := v.QueryBalance(context.Background(), BalanceQuery{ChainID: "", Address: "0xA"}); err == nil {
		t.Error("expected chainID required")
	}
	if _, err := v.QueryBalance(context.Background(), BalanceQuery{ChainID: "ethereum", Address: ""}); err == nil {
		t.Error("expected address required")
	}
}

func TestBalanceVerifier_Run_RequiresConfig(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	v := NewBalanceVerifier(engine, BalanceVerifierConfig{}) // no priv key
	if err := v.Run(context.Background()); err == nil {
		t.Error("expected priv key required")
	}

	// Priv key but no providers.
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	v = NewBalanceVerifier(engine, BalanceVerifierConfig{WitnessPrivKey: priv})
	if err := v.Run(context.Background()); err == nil {
		t.Error("expected providers required")
	}
}

func TestBalanceVerifier_QueryCached(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	v := NewBalanceVerifier(engine, BalanceVerifierConfig{})
	// Cache is empty — returns nil.
	if got := v.QueryCached("ethereum", "0xA", ""); got != nil {
		t.Error("expected nil cache miss")
	}
}

func TestBalanceVerifier_RegisterProvider(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	v := NewBalanceVerifier(engine, BalanceVerifierConfig{})
	v.RegisterProvider("ethereum", &fakeBalanceProvider{
		snapshot: BalanceSnapshot{Balance: big.NewInt(1), Timestamp: time.Now()},
	})
	v.mu.Lock()
	_, ok := v.providers["ethereum"]
	v.mu.Unlock()
	if !ok {
		t.Error("expected provider registered")
	}
}

// --- WitnessRegistry integration ---

func TestWitnessRegistry_RegisterAndFind(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	r := &WitnessRegistry{engine: engine, entries: map[string]*WitnessRegistration{}}
	// Manually register topic so Publish works.
	_ = engine.RegisterTopic(canonical.WitnessTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	reg := WitnessRegistration{
		PubKey:       pub,
		ChainIDs:     []string{"ethereum", "polygon"},
		Reputation:   0.8,
		RegisteredAt: time.Now(),
	}
	if err := reg.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := r.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got := r.FindForChain("ethereum")
	if len(got) != 1 {
		t.Fatalf("FindForChain: got %d, want 1", len(got))
	}
	if r.Count() != 1 {
		t.Errorf("Count: got %d, want 1", r.Count())
	}
	fetched := r.Get(pub)
	if fetched == nil || fetched.Reputation != 0.8 {
		t.Errorf("Get: got %+v, want reputation 0.8", fetched)
	}
}

func TestWitnessRegistry_ValidationErrors(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	r := &WitnessRegistry{engine: engine, entries: map[string]*WitnessRegistration{}}
	_ = engine.RegisterTopic(canonical.WitnessTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})

	// Short pubkey.
	if err := r.Register(WitnessRegistration{PubKey: []byte{1, 2}, ChainIDs: []string{"ethereum"}}); err == nil {
		t.Error("expected short-pubkey error")
	}
	// No chains.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := r.Register(WitnessRegistration{PubKey: pub}); err == nil {
		t.Error("expected no-chains error")
	}
	// Unsigned registration: has pubkey + chains but no signature.
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := r.Register(WitnessRegistration{PubKey: pub2, ChainIDs: []string{"ethereum"}}); err == nil {
		t.Error("expected unsigned-registration error")
	}
	// Mismatched signature: signed by different key.
	pub3, _, _ := ed25519.GenerateKey(rand.Reader)
	_, priv4, _ := ed25519.GenerateKey(rand.Reader)
	bad := WitnessRegistration{PubKey: pub3, ChainIDs: []string{"ethereum"}}
	// Force-forge a signature over the wrong key's canonical bytes.
	bad.PubKey = priv4.Public().(ed25519.PublicKey)
	_ = bad.Sign(priv4)
	bad.PubKey = pub3 // restore mismatched pubkey
	if err := r.Register(bad); err == nil {
		t.Error("expected mismatched-signature error")
	}
}

func TestWitnessRegistry_UpdateReputation(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	r := &WitnessRegistry{engine: engine, entries: map[string]*WitnessRegistration{}}
	_ = engine.RegisterTopic(canonical.WitnessTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	reg := WitnessRegistration{
		PubKey: pub, ChainIDs: []string{"ethereum"}, Reputation: 0.5,
		RegisteredAt: time.Now(),
	}
	if err := reg.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := r.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	r.UpdateReputation(pub, 0.3)
	got := r.Get(pub)
	if got == nil || got.Reputation != 0.8 {
		t.Errorf("updated reputation: got %v, want 0.8", got)
	}
	// Cap at 1.0.
	r.UpdateReputation(pub, 5.0)
	got = r.Get(pub)
	if got.Reputation != 1.0 {
		t.Errorf("capped: got %v, want 1.0", got.Reputation)
	}
	// Floor at 0.
	r.UpdateReputation(pub, -99)
	got = r.Get(pub)
	if got.Reputation != 0.0 {
		t.Errorf("floored: got %v, want 0.0", got.Reputation)
	}
}

func TestWitnessRegistry_Unregister(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	r := &WitnessRegistry{engine: engine, entries: map[string]*WitnessRegistration{}}
	_ = engine.RegisterTopic(canonical.WitnessTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	reg := WitnessRegistration{PubKey: pub, ChainIDs: []string{"ethereum"}, RegisteredAt: time.Now()}
	if err := reg.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := r.Register(reg); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if err := r.Unregister(pub); err != nil {
		t.Fatalf("Unregister: %v", err)
	}
	if r.Count() != 0 {
		t.Error("count after unregister must be 0")
	}
	// Unregistering again should error.
	if err := r.Unregister(pub); err == nil {
		t.Error("expected not-found error on double-unregister")
	}
	// Short pubkey.
	if err := r.Unregister([]byte{1, 2}); err == nil {
		t.Error("expected short-key error")
	}
}

func TestWitnessRegistry_OnBroadcast_MergeNewer(t *testing.T) {
	t.Parallel()
	engine := whisper.NewEngine()
	r := &WitnessRegistry{engine: engine, entries: map[string]*WitnessRegistration{}}
	_ = engine.RegisterTopic(canonical.WitnessTopic(), whisper.TopicConfig{Mode: whisper.BroadcastOnly})

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Register an initial entry with old timestamp.
	old := WitnessRegistration{PubKey: pub, ChainIDs: []string{"ethereum"}, Reputation: 0.1, RegisteredAt: time.Now().Add(-1 * time.Hour)}
	if err := old.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	_ = r.Register(old)

	// Craft a newer gossip message with better reputation.
	newer := witnessRegistrationWire{
		PubKey:       pub,
		ChainIDs:     []string{"ethereum"},
		Reputation:   0.9,
		RegisteredAt: time.Now().UnixNano(),
	}
	data, _ := json.Marshal(newer)
	r.OnBroadcast(canonical.WitnessTopic(), "peer", data)

	got := r.Get(pub)
	if got == nil || got.Reputation != 0.9 {
		t.Errorf("newer gossip did not merge: got %v", got)
	}
}
