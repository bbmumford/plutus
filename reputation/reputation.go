/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package reputation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/bbmumford/plutus/canonical"
	"github.com/bbmumford/plutus/internal/gossipstate"

	"github.com/bbmumford/ledger/cache"
	"github.com/bbmumford/whisper"
)

// topicRepTrades and topicRepReviews are resolved at init time from the
// protocol fingerprint for network isolation.
var (
	topicRepTrades  string
	topicRepReviews string
)

func init() {
	topicRepTrades = canonical.RepTradesTopic()
	topicRepReviews = canonical.RepReviewsTopic()
}

const (
	// maxCommentLength caps review comments to prevent gossip abuse.
	maxCommentLength = 2048
)

// RepType classifies the type of reputation record.
type RepType int

const (
	TradeComplete RepType = iota
	Dispute
	Review
)

// String returns the name of the reputation type.
func (t RepType) String() string {
	switch t {
	case TradeComplete:
		return "TradeComplete"
	case Dispute:
		return "Dispute"
	case Review:
		return "Review"
	default:
		return fmt.Sprintf("RepType(%d)", t)
	}
}

// ReputationRecord represents a single reputation event. Records are signed
// by the recorder and gossiped via Whisper StatefulMerge topics.
type ReputationRecord struct {
	SubjectPubKey  []byte    `json:"subjectPubKey"`  // the party being reviewed
	RecorderPubKey []byte    `json:"recorderPubKey"` // the party recording the reputation
	Type           RepType   `json:"type"`
	Score          int32     `json:"score"`     // -1, 0, or +1
	AppID          string    `json:"appId"`     // which application the trade occurred on
	TxHash         string    `json:"txHash"`    // on-chain transaction hash for verification
	Comment        string    `json:"comment"`   // optional review text
	Timestamp      time.Time `json:"timestamp"`
	Signature      []byte    `json:"signature"`
}

// recordDigest computes the SHA-256 hash of all record fields except Signature.
func recordDigest(r *ReputationRecord) []byte {
	h := sha256.New()
	h.Write(r.SubjectPubKey)
	h.Write(r.RecorderPubKey)

	var typeBuf [4]byte
	binary.BigEndian.PutUint32(typeBuf[:], uint32(r.Type))
	h.Write(typeBuf[:])

	var scoreBuf [4]byte
	binary.BigEndian.PutUint32(scoreBuf[:], uint32(r.Score))
	h.Write(scoreBuf[:])

	h.Write([]byte(r.AppID))
	h.Write([]byte(r.TxHash))
	h.Write([]byte(r.Comment))

	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(r.Timestamp.UnixNano()))
	h.Write(tsBuf[:])

	return h.Sum(nil)
}

// SignRecord signs the record with the recorder's Ed25519 private key.
func SignRecord(r *ReputationRecord, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("reputation: invalid private key size %d", len(privateKey))
	}
	digest := recordDigest(r)
	r.Signature = ed25519.Sign(privateKey, digest)
	return nil
}

// VerifyRecord checks that the record's signature is valid.
func VerifyRecord(r *ReputationRecord) bool {
	if len(r.RecorderPubKey) != ed25519.PublicKeySize {
		return false
	}
	if len(r.Signature) != ed25519.SignatureSize {
		return false
	}
	digest := recordDigest(r)
	return ed25519.Verify(r.RecorderPubKey, digest, r.Signature)
}

// ReputationScore aggregates reputation metrics for a single identity.
type ReputationScore struct {
	TotalTrades  int                `json:"totalTrades"`
	PositiveRate float64            `json:"positiveRate"` // 0.0 - 1.0
	DisputeRate  float64            `json:"disputeRate"`  // 0.0 - 1.0
	AvgRating    float64            `json:"avgRating"`    // -1.0 to +1.0
	FirstTradeAt time.Time          `json:"firstTradeAt"`
	LastTradeAt  time.Time          `json:"lastTradeAt"`
	AppBreakdown map[string]int     `json:"appBreakdown"` // appID -> trade count
}

// ReputationService tracks and computes reputation scores across the mesh.
// Records are gossiped via Whisper StatefulMerge and stored locally.
type ReputationService struct {
	engine *whisper.Engine
	cache  *cache.DirectoryCache

	mu      sync.RWMutex
	records map[string][]*ReputationRecord // hex(subjectPubKey) -> records
}

// NewReputationService creates a service wired to Whisper for gossip.
func NewReputationService(engine *whisper.Engine, c *cache.DirectoryCache) *ReputationService {
	s := &ReputationService{
		engine:  engine,
		cache:   c,
		records: make(map[string][]*ReputationRecord),
	}

	// Register both StatefulMerge topics before subscribing so that
	// delta-sync and Apply work correctly for reputation records.
	tradeStore := &reputationStateStore{service: s, topic: topicRepTrades}
	reviewStore := &reputationStateStore{service: s, topic: topicRepReviews}

	engine.RegisterTopic(topicRepTrades, whisper.TopicConfig{
		Mode:  whisper.StatefulMerge,
		Store: tradeStore,
	})
	engine.RegisterTopic(topicRepReviews, whisper.TopicConfig{
		Mode:  whisper.StatefulMerge,
		Store: reviewStore,
	})

	engine.Subscribe(topicRepTrades, s)
	engine.Subscribe(topicRepReviews, s)
	return s
}

// Record submits a new reputation record. The record must be signed and valid.
func (s *ReputationService) Record(rec ReputationRecord) error {
	if err := validateRecord(&rec); err != nil {
		return err
	}

	key := hex.EncodeToString(rec.SubjectPubKey)

	s.mu.Lock()
	s.records[key] = append(s.records[key], &rec)
	s.mu.Unlock()

	// Gossip the record via the appropriate topic
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("reputation: marshal record: %w", err)
	}

	topic := topicForType(rec.Type)
	cfg, ok := s.engine.Registry().Get(topic)
	if ok && cfg.Store != nil {
		if err := cfg.Store.Apply(payload); err != nil {
			return fmt.Errorf("reputation: apply to state store: %w", err)
		}
	}

	return nil
}

// Score computes the aggregate reputation score for a given identity.
func (s *ReputationService) Score(pubkey []byte) ReputationScore {
	key := hex.EncodeToString(pubkey)

	s.mu.RLock()
	recs := s.records[key]
	s.mu.RUnlock()

	if len(recs) == 0 {
		return ReputationScore{
			AppBreakdown: make(map[string]int),
		}
	}

	score := ReputationScore{
		AppBreakdown: make(map[string]int),
	}

	var positiveCount, disputeCount int
	var totalScore int64

	for _, rec := range recs {
		switch rec.Type {
		case TradeComplete:
			score.TotalTrades++
			if rec.Score > 0 {
				positiveCount++
			}
			totalScore += int64(rec.Score)
		case Dispute:
			disputeCount++
		case Review:
			totalScore += int64(rec.Score)
		}

		if rec.AppID != "" {
			score.AppBreakdown[rec.AppID]++
		}

		if score.FirstTradeAt.IsZero() || rec.Timestamp.Before(score.FirstTradeAt) {
			score.FirstTradeAt = rec.Timestamp
		}
		if rec.Timestamp.After(score.LastTradeAt) {
			score.LastTradeAt = rec.Timestamp
		}
	}

	if score.TotalTrades > 0 {
		score.PositiveRate = float64(positiveCount) / float64(score.TotalTrades)
		score.DisputeRate = float64(disputeCount) / float64(score.TotalTrades)
	}

	totalRated := len(recs)
	if totalRated > 0 {
		score.AvgRating = float64(totalScore) / float64(totalRated)
	}

	return score
}

// PositiveRate implements arbitrator.ReputationScorer.
func (s *ReputationService) PositiveRate(pubkey []byte) float64 {
	return s.Score(pubkey).PositiveRate
}

// TotalTrades implements arbitrator.ReputationScorer.
func (s *ReputationService) TotalTrades(pubkey []byte) int {
	return s.Score(pubkey).TotalTrades
}

// History returns the most recent reputation records for a given identity,
// up to the specified limit.
func (s *ReputationService) History(pubkey []byte, limit int) []ReputationRecord {
	key := hex.EncodeToString(pubkey)

	s.mu.RLock()
	recs := s.records[key]
	s.mu.RUnlock()

	if len(recs) == 0 {
		return nil
	}

	// Return most recent first: iterate from the end
	if limit <= 0 || limit > len(recs) {
		limit = len(recs)
	}

	result := make([]ReputationRecord, limit)
	for i := 0; i < limit; i++ {
		result[i] = *recs[len(recs)-1-i]
	}
	return result
}

// OnBroadcast implements whisper.Subscriber. It receives gossiped reputation
// records and merges them into the local store.
func (s *ReputationService) OnBroadcast(topic string, from string, payload []byte) {
	if topic != topicRepTrades && topic != topicRepReviews {
		return
	}

	var rec ReputationRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		return
	}
	// A refused record is dropped silently: gossip is best-effort.
	_ = s.merge(&rec)
}

// merge admits one record a peer sent, by gossip (OnBroadcast) or by state
// sync (reputationStateStore.Apply), under the same rule: a signature
// VerifyRecord accepts, a subject key of the right size, a score in [-1, 1],
// and no record already held with the same TxHash from the same recorder.
// Both paths go through it so that a peer cannot place on one path a record
// the other refuses.
func (s *ReputationService) merge(rec *ReputationRecord) error {
	if !VerifyRecord(rec) {
		return fmt.Errorf("reputation: the record's signature does not verify")
	}
	if len(rec.SubjectPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("reputation: invalid subject public key in record")
	}
	if rec.Score < -1 || rec.Score > 1 {
		return fmt.Errorf("reputation: score %v outside [-1, 1]", rec.Score)
	}

	key := hex.EncodeToString(rec.SubjectPubKey)

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec.TxHash != "" {
		for _, existing := range s.records[key] {
			if existing.TxHash == rec.TxHash &&
				hex.EncodeToString(existing.RecorderPubKey) == hex.EncodeToString(rec.RecorderPubKey) {
				return nil
			}
		}
	}

	s.records[key] = append(s.records[key], rec)
	return nil
}

// validateRecord performs comprehensive validation on a reputation record.
func validateRecord(rec *ReputationRecord) error {
	if len(rec.SubjectPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("reputation: invalid subject public key size %d", len(rec.SubjectPubKey))
	}
	if len(rec.RecorderPubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("reputation: invalid recorder public key size %d", len(rec.RecorderPubKey))
	}
	if rec.Score < -1 || rec.Score > 1 {
		return fmt.Errorf("reputation: score must be -1, 0, or +1, got %d", rec.Score)
	}
	if len(rec.Comment) > maxCommentLength {
		return fmt.Errorf("reputation: comment length %d exceeds limit %d", len(rec.Comment), maxCommentLength)
	}
	if rec.Timestamp.IsZero() {
		return fmt.Errorf("reputation: timestamp is required")
	}
	if !VerifyRecord(rec) {
		return fmt.Errorf("reputation: invalid signature")
	}
	return nil
}

// topicForType returns the Whisper topic for a given reputation type.
func topicForType(t RepType) string {
	switch t {
	case Review:
		return topicRepReviews
	default:
		return topicRepTrades
	}
}

// reputationStateStore implements whisper.StateStore for a reputation
// StatefulMerge topic. It wraps the in-memory service records for
// delta-sync and merge-on-apply.
type reputationStateStore struct {
	service *ReputationService
	topic   string
}

// Fingerprint summarises this topic's records for whisper's G2 digest.
func (s *reputationStateStore) Fingerprint() uint64 {
	return gossipstate.Fingerprint(s.Snapshot())
}

// Snapshot returns every record whose type routes to this store's topic
// (trades or reviews); a record that fails to marshal is left out so it
// does not block the rest.
func (s *reputationStateStore) Snapshot() [][]byte {
	s.service.mu.RLock()
	defer s.service.mu.RUnlock()

	var records [][]byte
	for _, recs := range s.service.records {
		for _, rec := range recs {
			recTopic := topicForType(rec.Type)
			if recTopic != s.topic {
				continue
			}
			data, err := json.Marshal(rec)
			if err != nil {
				continue
			}
			records = append(records, data)
		}
	}
	return records
}

// Delta returns the full snapshot: a record's Timestamp is stamped by its
// recorder, not by the local Apply, so filtering on it would drop a record
// that reached this node after the peer's watermark.
func (s *reputationStateStore) Delta(_ time.Time) [][]byte {
	return s.Snapshot()
}

// Apply admits an incoming reputation record through the service's merge,
// the rule gossip uses: a record whose signature does not verify is refused.
func (s *reputationStateStore) Apply(data []byte) error {
	var rec ReputationRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		return fmt.Errorf("reputation: unmarshal state record: %w", err)
	}
	return s.service.merge(&rec)
}
