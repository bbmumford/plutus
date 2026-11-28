/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package reputation

import "time"

// DisputeRecord builds the unsigned reputation record a dispute's
// arbitrator gives one party of an order: Type Dispute, the arbitrator as
// recorder, the order's ID as TxHash, the ruling's time as Timestamp and no
// comment. The arbitrator signs the record it returns (SignRecord), and the
// node that settles the dispute builds it again from the ruling and the
// order to check that signature (VerifyRecord) before storing it (Record).
// Both sides build it here because the signature covers every field
// recordDigest hashes: a field that differed between them, a comment
// included, would void it.
func DisputeRecord(subject, arbitrator []byte, score int32, appID, orderID string, ruledAt time.Time) ReputationRecord {
	return ReputationRecord{
		SubjectPubKey:  subject,
		RecorderPubKey: arbitrator,
		Type:           Dispute,
		Score:          score,
		AppID:          appID,
		TxHash:         orderID,
		Timestamp:      ruledAt,
	}
}
