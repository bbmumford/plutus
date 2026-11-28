/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package reputation

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestADisputeRecordSignedByTheArbitratorIsStored(t *testing.T) {
	subject, _, _ := ed25519.GenerateKey(rand.Reader)
	arbPub, arbPriv, _ := ed25519.GenerateKey(rand.Reader)
	ruledAt := time.Unix(1_700_000_100, 42)

	rec := DisputeRecord(subject, arbPub, -1, "mercury", "order-7", ruledAt)
	if rec.Type != Dispute || rec.Score != -1 || rec.AppID != "mercury" || rec.TxHash != "order-7" ||
		!rec.Timestamp.Equal(ruledAt) || rec.Comment != "" ||
		!bytes.Equal(rec.SubjectPubKey, subject) || !bytes.Equal(rec.RecorderPubKey, arbPub) {
		t.Fatalf("DisputeRecord = %+v", rec)
	}
	if err := SignRecord(&rec, arbPriv); err != nil {
		t.Fatal(err)
	}

	svc := newIntegrationService(t)
	if err := svc.Record(rec); err != nil {
		t.Fatalf("Record refused the arbitrator's signed dispute record: %v", err)
	}
	hist := svc.History(subject, 10)
	if len(hist) != 1 || hist[0].Type != Dispute || hist[0].TxHash != "order-7" {
		t.Fatalf("History = %+v; want the one dispute record", hist)
	}
}

// The signature over a dispute record holds only for the record both sides
// build: a different subject, score, order or time does not verify.
func TestADisputeRecordSignatureCoversEveryFieldItIsBuiltFrom(t *testing.T) {
	subject, _, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	arbPub, arbPriv, _ := ed25519.GenerateKey(rand.Reader)
	ruledAt := time.Unix(1_700_000_100, 0)

	signed := DisputeRecord(subject, arbPub, 1, "mercury", "order-7", ruledAt)
	if err := SignRecord(&signed, arbPriv); err != nil {
		t.Fatal(err)
	}
	for name, rebuilt := range map[string]ReputationRecord{
		"subject": DisputeRecord(other, arbPub, 1, "mercury", "order-7", ruledAt),
		"score":   DisputeRecord(subject, arbPub, -1, "mercury", "order-7", ruledAt),
		"app":     DisputeRecord(subject, arbPub, 1, "plutus", "order-7", ruledAt),
		"order":   DisputeRecord(subject, arbPub, 1, "mercury", "order-8", ruledAt),
		"time":    DisputeRecord(subject, arbPub, 1, "mercury", "order-7", ruledAt.Add(time.Nanosecond)),
	} {
		rebuilt.Signature = signed.Signature
		if VerifyRecord(&rebuilt) {
			t.Errorf("%s changed: the arbitrator's signature still verifies", name)
		}
	}
	same := DisputeRecord(subject, arbPub, 1, "mercury", "order-7", ruledAt)
	same.Signature = signed.Signature
	if !VerifyRecord(&same) {
		t.Fatal("the record rebuilt from the same fields does not verify")
	}
}
