/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package reputation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/bbmumford/whisper"
)

// keyPair is a convenience for tests.
type keyPair struct {
	pub  ed25519.PublicKey
	priv ed25519.PrivateKey
}

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{pub: pub, priv: priv}
}

// newIntegrationService builds a real ReputationService backed by an in-memory
// Whisper engine. Ledger cache is nil which is supported.
func newIntegrationService(t *testing.T) *ReputationService {
	t.Helper()
	engine := whisper.NewEngine()
	return NewReputationService(engine, nil)
}

// signed builds and signs a reputation record.
func signed(t *testing.T, subject, recorder keyPair, typ RepType, score int32, appID, tx string) ReputationRecord {
	t.Helper()
	rec := ReputationRecord{
		SubjectPubKey:  subject.pub,
		RecorderPubKey: recorder.pub,
		Type:           typ,
		Score:          score,
		AppID:          appID,
		TxHash:         tx,
		Timestamp:      time.Now().UTC(),
	}
	if err := SignRecord(&rec, recorder.priv); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	return rec
}

// --- ReputationService tests ---

func TestReputationService_RecordAndScore(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	seller := newKeyPair(t)
	buyer := newKeyPair(t)

	// Two positive trade completions and one dispute.
	rec1 := signed(t, seller, buyer, TradeComplete, 1, "app1", "0xtx1")
	rec2 := signed(t, seller, buyer, TradeComplete, 1, "app1", "0xtx2")
	rec3 := signed(t, seller, buyer, Dispute, 0, "app1", "0xtx3")

	for _, r := range []ReputationRecord{rec1, rec2, rec3} {
		if err := svc.Record(r); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	score := svc.Score(seller.pub)
	if score.TotalTrades != 2 {
		t.Errorf("total trades: got %d, want 2", score.TotalTrades)
	}
	if score.PositiveRate != 1.0 {
		t.Errorf("positive rate: got %v, want 1.0", score.PositiveRate)
	}
	if score.DisputeRate != 0.5 {
		t.Errorf("dispute rate: got %v, want 0.5 (1 dispute / 2 trades)", score.DisputeRate)
	}
	if score.AppBreakdown["app1"] != 3 {
		t.Errorf("app breakdown: got %d, want 3", score.AppBreakdown["app1"])
	}
	if svc.TotalTrades(seller.pub) != 2 {
		t.Error("TotalTrades helper mismatch")
	}
	if svc.PositiveRate(seller.pub) != 1.0 {
		t.Error("PositiveRate helper mismatch")
	}
}

func TestReputationService_Score_UnknownSubject(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	unknown := newKeyPair(t)
	score := svc.Score(unknown.pub)
	if score.TotalTrades != 0 {
		t.Errorf("unknown: trades %d, want 0", score.TotalTrades)
	}
	if score.AppBreakdown == nil {
		t.Error("AppBreakdown must not be nil for unknown subject")
	}
}

func TestReputationService_Record_InvalidRecord(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)

	// Short subject pubkey.
	bad := ReputationRecord{
		SubjectPubKey: []byte{1, 2},
		Timestamp:     time.Now(),
	}
	if err := svc.Record(bad); err == nil {
		t.Error("expected invalid subject error")
	}

	// Invalid score.
	seller := newKeyPair(t)
	recorder := newKeyPair(t)
	rec := signed(t, seller, recorder, TradeComplete, 1, "app", "0x1")
	rec.Score = 99 // out of range
	// Re-sign with new score so it's not the signature that's invalid.
	_ = SignRecord(&rec, recorder.priv)
	if err := svc.Record(rec); err == nil {
		t.Error("expected score-range error")
	}
}

func TestReputationService_History(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)

	for i := 0; i < 5; i++ {
		rec := signed(t, subject, recorder, TradeComplete, 1, "app", fmt.Sprintf("0xtx-%d", i))
		if err := svc.Record(rec); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	// No limit -> all.
	all := svc.History(subject.pub, 0)
	if len(all) != 5 {
		t.Errorf("history all: got %d, want 5", len(all))
	}
	// Limited.
	limited := svc.History(subject.pub, 2)
	if len(limited) != 2 {
		t.Errorf("limited history: got %d, want 2", len(limited))
	}
	// Unknown subject.
	unknown := newKeyPair(t)
	if svc.History(unknown.pub, 0) != nil {
		t.Error("unknown history must be nil")
	}
}

func TestReputationService_OnBroadcast_GossipMerge(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)

	rec := signed(t, subject, recorder, TradeComplete, 1, "app", "0xgossip-1")
	data, _ := json.Marshal(rec)

	svc.OnBroadcast(topicRepTrades, "peer-id", data)

	// Now score should include the gossiped record.
	s := svc.Score(subject.pub)
	if s.TotalTrades != 1 {
		t.Errorf("gossip merge total: got %d, want 1", s.TotalTrades)
	}
}

func TestReputationService_OnBroadcast_RejectInvalidSig(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)

	rec := signed(t, subject, recorder, TradeComplete, 1, "app", "0xbad-sig")
	// Tamper the signature so VerifyRecord fails.
	rec.Signature[0] ^= 0xFF
	data, _ := json.Marshal(rec)
	svc.OnBroadcast(topicRepTrades, "peer", data)

	if svc.Score(subject.pub).TotalTrades != 0 {
		t.Error("tampered record must not be accepted")
	}
}

func TestReputationService_OnBroadcast_WrongTopic(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)
	rec := signed(t, subject, recorder, TradeComplete, 1, "app", "0xtx")
	data, _ := json.Marshal(rec)
	// Wrong topic -> must be ignored.
	svc.OnBroadcast("not.a.reputation.topic", "peer", data)
	if svc.Score(subject.pub).TotalTrades != 0 {
		t.Error("wrong-topic record must be ignored")
	}
}

func TestReputationService_OnBroadcast_Malformed(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	// Malformed JSON must be silently dropped.
	svc.OnBroadcast(topicRepTrades, "peer", []byte("not-json"))
	// Short pubkey in valid JSON.
	rec := ReputationRecord{SubjectPubKey: []byte{1, 2}}
	data, _ := json.Marshal(rec)
	svc.OnBroadcast(topicRepTrades, "peer", data)
}

func TestReputationService_Dedup_SameTxHash(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)

	rec := signed(t, subject, recorder, TradeComplete, 1, "app", "0xtx-dup")
	if err := svc.Record(rec); err != nil {
		t.Fatal(err)
	}

	// Same TxHash + recorder should dedup via OnBroadcast path.
	data, _ := json.Marshal(rec)
	svc.OnBroadcast(topicRepTrades, "peer", data)
	if svc.Score(subject.pub).TotalTrades != 1 {
		t.Error("duplicate tx/recorder should be deduped")
	}
}

// --- AntiGamingService integration ---

type canonicalVerifier struct {
	confirmed map[string]bool
	err       error
}

func (c *canonicalVerifier) IsConfirmed(ctx context.Context, chainID, txHash string) (bool, error) {
	if c.err != nil {
		return false, c.err
	}
	return c.confirmed[txHash], nil
}

func TestAntiGaming_ValidateRecord_HappyPath(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)

	// First, record a TradeComplete between them so the counterparty check passes.
	trade := signed(t, subject, recorder, TradeComplete, 1, "app", "0xtrade")
	if err := svc.Record(trade); err != nil {
		t.Fatal(err)
	}

	// Now the review:
	review := signed(t, subject, recorder, Review, 1, "app", "0xreview")
	ag := NewAntiGamingService(svc, &canonicalVerifier{confirmed: map[string]bool{"0xreview": true}})
	if err := ag.ValidateRecord(&review, "ethereum"); err != nil {
		t.Errorf("valid review rejected: %v", err)
	}
}

func TestAntiGaming_ValidateRecord_NoCounterpartyTrade(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)

	// No trade between them — review should be rejected.
	review := signed(t, subject, recorder, Review, 1, "app", "0xreview")
	ag := NewAntiGamingService(svc, &canonicalVerifier{confirmed: map[string]bool{"0xreview": true}})
	if err := ag.ValidateRecord(&review, "ethereum"); err == nil {
		t.Error("expected no-counterparty-trade error")
	}
}

func TestAntiGaming_ValidateRecord_UnconfirmedTx(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)

	// Record trade first so counterparty passes.
	trade := signed(t, subject, recorder, TradeComplete, 1, "app", "0xtrade")
	_ = svc.Record(trade)

	review := signed(t, subject, recorder, Review, 1, "app", "0xreview")
	// Verifier returns NOT confirmed.
	ag := NewAntiGamingService(svc, &canonicalVerifier{confirmed: map[string]bool{}})
	if err := ag.ValidateRecord(&review, "ethereum"); err == nil {
		t.Error("expected not-confirmed error")
	}
}

func TestAntiGaming_ValidateRecord_VerifierError(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)

	// Trade exists so counterparty passes.
	trade := signed(t, subject, recorder, TradeComplete, 1, "app", "0xtrade")
	_ = svc.Record(trade)

	review := signed(t, subject, recorder, Review, 1, "app", "0xreview")
	ag := NewAntiGamingService(svc, &canonicalVerifier{err: errors.New("rpc broken")})
	if err := ag.ValidateRecord(&review, "ethereum"); err == nil {
		t.Error("expected verifier-error")
	}
}

func TestAntiGaming_ValidateRecord_TradeCompleteSkipsCounterpartyCheck(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)

	// Record a TradeComplete (not a review). No pre-existing trade needed.
	tradeRec := signed(t, subject, recorder, TradeComplete, 1, "app", "0xtrade-first")
	ag := NewAntiGamingService(svc, &canonicalVerifier{confirmed: map[string]bool{"0xtrade-first": true}})
	if err := ag.ValidateRecord(&tradeRec, "ethereum"); err != nil {
		t.Errorf("TradeComplete must bypass counterparty: %v", err)
	}
}

func TestAntiGaming_RequireCounterpartyTrade_ReverseDirection(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)

	// Trade recorded in the opposite direction (recorder as subject).
	reverse := signed(t, recorder, subject, TradeComplete, 1, "app", "0xreverse")
	_ = svc.Record(reverse)

	// Now check the original direction.
	review := signed(t, subject, recorder, Review, 1, "app", "0xreview")
	ag := NewAntiGamingService(svc, &canonicalVerifier{})
	if err := ag.RequireCounterpartyTrade(&review); err != nil {
		t.Errorf("reverse-direction trade should satisfy counterparty: %v", err)
	}
}

func TestAntiGaming_VerifyTradeCompletion_ContextTimeout(t *testing.T) {
	t.Parallel()
	// Timeout verifier that never resolves within the service timeout.
	slow := &slowVerifier{delay: 2 * time.Second}
	ag := NewAntiGamingService(nil, slow)
	ag.timeout = 50 * time.Millisecond
	if err := ag.VerifyTradeCompletion("0xabc", "ethereum"); err == nil {
		t.Error("expected timeout error")
	}
}

type slowVerifier struct{ delay time.Duration }

func (s *slowVerifier) IsConfirmed(ctx context.Context, chainID, txHash string) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(s.delay):
		return true, nil
	}
}

// --- State store path ---

func TestReputationStateStore_DeltaSync(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)
	rec := signed(t, subject, recorder, TradeComplete, 1, "app", "0xds-1")
	if err := svc.Record(rec); err != nil {
		t.Fatal(err)
	}

	// Reputation service registers the trade-topic state store via its
	// engine; fetch it back from the registry to test Snapshot/Delta/Apply.
	cfg, ok := svc.engine.Registry().Get(topicRepTrades)
	if !ok || cfg.Store == nil {
		t.Fatal("expected trade-topic state store")
	}
	before := cfg.Store.Fingerprint()
	if before == 0 {
		t.Fatal("a store holding a record must report a non-zero fingerprint")
	}
	// Apply a fresh incoming record; rec is already stored, so a new one
	// is needed for the fingerprint to move.
	rec2 := signed(t, subject, recorder, TradeComplete, 1, "app", "0xds-applied")
	data, _ := json.Marshal(rec2)
	if err := cfg.Store.Apply(data); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if cfg.Store.Fingerprint() == before {
		t.Fatal("Apply of a new record must change the fingerprint")
	}
	snap := cfg.Store.Snapshot()
	if len(snap) == 0 {
		t.Fatal("expected the snapshot to carry the stored records")
	}
	// Delta returns the snapshot for any watermark, so a peer behind on a
	// record whose recorder stamped it earlier still receives it.
	if got := cfg.Store.Delta(time.Now().Add(time.Hour)); len(got) != len(snap) {
		t.Errorf("Delta after a future watermark: got %d records, want %d", len(got), len(snap))
	}
	if got := cfg.Store.Delta(time.Time{}); len(got) != len(snap) {
		t.Errorf("Delta from the zero time: got %d records, want %d", len(got), len(snap))
	}

	// A second node holding the same records reports the same fingerprint,
	// which is what lets whisper's G2 digest skip the exchange.
	peer := newIntegrationService(t)
	peerCfg, _ := peer.engine.Registry().Get(topicRepTrades)
	for _, r := range snap {
		if err := peerCfg.Store.Apply(r); err != nil {
			t.Fatalf("peer Apply: %v", err)
		}
	}
	if peerCfg.Store.Fingerprint() != cfg.Store.Fingerprint() {
		t.Error("two nodes holding the same records must report the same fingerprint")
	}
}

// Two nodes that each applied one different record must not report the
// same fingerprint, or whisper's G2 digest would skip the exchange that
// brings them together.
func TestReputationStateStore_FingerprintDiffersForDifferentRecords(t *testing.T) {
	t.Parallel()
	subject := newKeyPair(t)
	recorder := newKeyPair(t)
	fingerprintAfter := func(tx string) uint64 {
		svc := newIntegrationService(t)
		cfg, _ := svc.engine.Registry().Get(topicRepTrades)
		data, _ := json.Marshal(signed(t, subject, recorder, TradeComplete, 1, "app", tx))
		if err := cfg.Store.Apply(data); err != nil {
			t.Fatalf("Apply: %v", err)
		}
		return cfg.Store.Fingerprint()
	}
	if fingerprintAfter("0xfp-a") == fingerprintAfter("0xfp-b") {
		t.Error("nodes holding different records reported the same fingerprint")
	}
}

func TestReputationStateStore_Apply(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	subject := newKeyPair(t)
	recorder := newKeyPair(t)
	rec := signed(t, subject, recorder, Review, 1, "app", "0xapply-1")
	data, _ := json.Marshal(rec)

	cfg, _ := svc.engine.Registry().Get(topicRepReviews)
	if err := cfg.Store.Apply(data); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	// Score should reflect the applied record.
	s := svc.Score(subject.pub)
	if s.AvgRating == 0 {
		t.Error("Apply should have introduced rated record")
	}
}

func TestReputationStateStore_Apply_Malformed(t *testing.T) {
	t.Parallel()
	svc := newIntegrationService(t)
	cfg, _ := svc.engine.Registry().Get(topicRepTrades)
	if err := cfg.Store.Apply([]byte("not-json")); err == nil {
		t.Error("expected unmarshal error")
	}
	// Short subject pubkey.
	rec := ReputationRecord{SubjectPubKey: []byte{1, 2}, Timestamp: time.Now()}
	data, _ := json.Marshal(rec)
	if err := cfg.Store.Apply(data); err == nil {
		t.Error("expected short subject-key error")
	}
}

func TestTopicForType(t *testing.T) {
	t.Parallel()
	if topicForType(Review) != topicRepReviews {
		t.Error("Review must route to reviews topic")
	}
	if topicForType(TradeComplete) != topicRepTrades {
		t.Error("TradeComplete must route to trades topic")
	}
	if topicForType(Dispute) != topicRepTrades {
		t.Error("Dispute must route to trades topic (default)")
	}
}

func TestValidateRecord_EmptyTimestamp(t *testing.T) {
	t.Parallel()
	subject, _, _ := ed25519.GenerateKey(rand.Reader)
	recorder, recorderPriv, _ := ed25519.GenerateKey(rand.Reader)
	rec := &ReputationRecord{
		SubjectPubKey:  subject,
		RecorderPubKey: recorder,
		Score:          0,
		// Timestamp zero.
	}
	_ = SignRecord(rec, recorderPriv)
	if err := validateRecord(rec); err == nil {
		t.Error("expected timestamp required")
	}
}

func TestValidateRecord_LongComment(t *testing.T) {
	t.Parallel()
	subject, _, _ := ed25519.GenerateKey(rand.Reader)
	recorder, recorderPriv, _ := ed25519.GenerateKey(rand.Reader)
	rec := &ReputationRecord{
		SubjectPubKey:  subject,
		RecorderPubKey: recorder,
		Score:          0,
		Comment:        string(make([]byte, maxCommentLength+1)),
		Timestamp:      time.Now(),
	}
	_ = SignRecord(rec, recorderPriv)
	if err := validateRecord(rec); err == nil {
		t.Error("expected long comment error")
	}
}
