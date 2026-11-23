/*
 * Copyright (c) 2026 Brandon Miller-Mumford. Licensed under the MIT License; see LICENSE.
 */
package reputation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakeVerifier struct {
	confirmed bool
	err       error
}

func (f *fakeVerifier) IsConfirmed(ctx context.Context, chainID, txHash string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	return f.confirmed, nil
}

func TestRejectSelfReview(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	rec := &ReputationRecord{
		SubjectPubKey:  pub,
		RecorderPubKey: pub,
	}
	err := RejectSelfReview(rec)
	if err == nil {
		t.Fatal("expected self-review error")
	}
	if !strings.Contains(err.Error(), "self-review") {
		t.Errorf("unexpected error text: %v", err)
	}

	// Different parties -> no error.
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	rec.RecorderPubKey = other
	if err := RejectSelfReview(rec); err != nil {
		t.Errorf("distinct parties should pass: %v", err)
	}
}

func TestVerifyTradeCompletion_Requires_Confirmation(t *testing.T) {
	t.Parallel()
	svc := &AntiGamingService{verifier: &fakeVerifier{confirmed: false}, timeout: 1 * time.Second}

	if err := svc.VerifyTradeCompletion("0xabc", "ethereum"); err == nil {
		t.Error("expected not-confirmed error")
	}
	if err := svc.VerifyTradeCompletion("", "ethereum"); err == nil {
		t.Error("expected empty tx error")
	}
	if err := svc.VerifyTradeCompletion("0xabc", ""); err == nil {
		t.Error("expected empty chain error")
	}
}

func TestVerifyTradeCompletion_Confirmed(t *testing.T) {
	t.Parallel()
	svc := &AntiGamingService{verifier: &fakeVerifier{confirmed: true}, timeout: 1 * time.Second}
	if err := svc.VerifyTradeCompletion("0xabc", "ethereum"); err != nil {
		t.Errorf("confirmed tx should pass: %v", err)
	}
}

func TestVerifyTradeCompletion_VerifierError(t *testing.T) {
	t.Parallel()
	svc := &AntiGamingService{verifier: &fakeVerifier{err: errors.New("rpc failed")}, timeout: 1 * time.Second}
	if err := svc.VerifyTradeCompletion("0xabc", "ethereum"); err == nil {
		t.Error("expected verifier error")
	}
}

func TestValidateRecord_RejectsSelfReviewEarly(t *testing.T) {
	t.Parallel()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	rec := &ReputationRecord{
		SubjectPubKey:  pub,
		RecorderPubKey: pub,
		Type:           Review,
	}
	svc := &AntiGamingService{verifier: &fakeVerifier{confirmed: true}, timeout: 1 * time.Second}
	// Even with confirmed tx, self-review must be rejected before chain check.
	if err := svc.ValidateRecord(rec, "ethereum"); err == nil {
		t.Error("expected self-review rejection")
	}
}
