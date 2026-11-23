/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package reputation

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"
)

// ChainVerifier verifies on-chain transaction settlement. This is injected
// by the consumer and typically backed by the witness MeshVerifier.
type ChainVerifier interface {
	// IsConfirmed checks whether a transaction has been confirmed on-chain
	// via witness quorum attestation.
	IsConfirmed(ctx context.Context, chainID string, txHash string) (bool, error)
}

// AntiGamingService prevents reputation manipulation by verifying that
// reputation records correspond to real on-chain trades and enforcing
// rules against self-review and unrelated-party reviews.
type AntiGamingService struct {
	repService *ReputationService
	verifier   ChainVerifier
	timeout    time.Duration
}

// NewAntiGamingService creates an anti-gaming service backed by the given
// reputation service and chain verifier.
func NewAntiGamingService(repService *ReputationService, verifier ChainVerifier) *AntiGamingService {
	return &AntiGamingService{
		repService: repService,
		verifier:   verifier,
		timeout:    30 * time.Second,
	}
}

// VerifyTradeCompletion confirms that a trade transaction was actually settled
// on-chain by querying the MeshVerifier for witness quorum confirmation.
// Returns an error if the transaction is not confirmed.
func (a *AntiGamingService) VerifyTradeCompletion(txHash, chainID string) error {
	if txHash == "" {
		return fmt.Errorf("reputation/anti-gaming: tx hash is required")
	}
	if chainID == "" {
		return fmt.Errorf("reputation/anti-gaming: chain ID is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), a.timeout)
	defer cancel()

	confirmed, err := a.verifier.IsConfirmed(ctx, chainID, txHash)
	if err != nil {
		return fmt.Errorf("reputation/anti-gaming: verification failed for %s on %s: %w", txHash, chainID, err)
	}
	if !confirmed {
		return fmt.Errorf("reputation/anti-gaming: transaction %s not confirmed on chain %s", txHash, chainID)
	}

	return nil
}

// RejectSelfReview checks whether a reputation record is a self-review
// (where the recorder and subject are the same identity). Self-reviews are
// always rejected as they are a primary vector for reputation gaming.
func RejectSelfReview(rec *ReputationRecord) error {
	if hex.EncodeToString(rec.SubjectPubKey) == hex.EncodeToString(rec.RecorderPubKey) {
		return fmt.Errorf("reputation/anti-gaming: self-review rejected (subject == recorder)")
	}
	return nil
}

// RequireCounterpartyTrade verifies that the recorder and subject have
// participated in at least one verified trade together. Reviews are only
// accepted if there is a TradeComplete record where one party is the subject
// and the other is the recorder.
func (a *AntiGamingService) RequireCounterpartyTrade(rec *ReputationRecord) error {
	if rec.Type != Review {
		// Only reviews require counterparty verification
		return nil
	}

	subjectKey := hex.EncodeToString(rec.SubjectPubKey)
	recorderKey := hex.EncodeToString(rec.RecorderPubKey)

	// Check trades where the subject is recorded
	subjectHistory := a.repService.History(rec.SubjectPubKey, 0) // all records
	for _, histRec := range subjectHistory {
		if histRec.Type != TradeComplete {
			continue
		}
		// The recorder of the trade must be or involve the reviewer
		if hex.EncodeToString(histRec.RecorderPubKey) == recorderKey {
			return nil // found a trade between recorder and subject
		}
	}

	// Also check trades where the recorder is the subject
	recorderHistory := a.repService.History(rec.RecorderPubKey, 0)
	for _, histRec := range recorderHistory {
		if histRec.Type != TradeComplete {
			continue
		}
		if hex.EncodeToString(histRec.RecorderPubKey) == subjectKey {
			return nil // found a trade between subject and recorder
		}
	}

	return fmt.Errorf("reputation/anti-gaming: no verified trade found between recorder %s and subject %s",
		recorderKey[:16], subjectKey[:16])
}

// ValidateRecord performs the full anti-gaming validation pipeline on a
// reputation record:
//  1. Reject self-reviews
//  2. Verify trade completion on-chain (if TxHash is present)
//  3. Require counterparty trade for reviews
//
// Returns nil if the record passes all checks.
func (a *AntiGamingService) ValidateRecord(rec *ReputationRecord, chainID string) error {
	// Step 1: Reject self-reviews
	if err := RejectSelfReview(rec); err != nil {
		return err
	}

	// Step 2: Verify on-chain trade completion
	if rec.TxHash != "" && chainID != "" {
		if err := a.VerifyTradeCompletion(rec.TxHash, chainID); err != nil {
			return err
		}
	}

	// Step 3: Require counterparty trade for reviews
	if err := a.RequireCounterpartyTrade(rec); err != nil {
		return err
	}

	return nil
}
