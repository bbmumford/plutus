/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package witness

import "time"

// VerificationPolicy specifies how many witnesses must participate and agree
// for an attestation request to be considered verified. Policies are scaled
// by transaction value — higher values require more witnesses.
type VerificationPolicy struct {
	MinWitnesses       int           // how many witnesses to solicit
	MinAgreement       int           // how many must agree
	Timeout            time.Duration // max time to wait for responses
	RequireMerkleProof bool          // if true, attestations must include Merkle proofs
}

// PolicyForValue returns a VerificationPolicy scaled to the given USD value.
// The tiers:
//
//	Quick    — $0-10:     1 witness, 1 agree, 2s
//	Standard — $10-100:   3 witnesses, 2 agree, 5s
//	High     — $100-1000: 5 witnesses, 4 agree, 10s
//	Maximum  — $1000+:    7 witnesses, 6 agree, 15s
func PolicyForValue(usdValue float64) VerificationPolicy {
	switch {
	case usdValue < 10:
		return VerificationPolicy{
			MinWitnesses: 1,
			MinAgreement: 1,
			Timeout:      2 * time.Second,
		}
	case usdValue < 100:
		return VerificationPolicy{
			MinWitnesses: 3,
			MinAgreement: 2,
			Timeout:      5 * time.Second,
		}
	case usdValue < 1000:
		return VerificationPolicy{
			MinWitnesses:       5,
			MinAgreement:       4,
			Timeout:            10 * time.Second,
			RequireMerkleProof: true,
		}
	default:
		return VerificationPolicy{
			MinWitnesses:       7,
			MinAgreement:       6,
			Timeout:            15 * time.Second,
			RequireMerkleProof: true,
		}
	}
}

// BalancePolicy is the default quorum policy for witness-mesh balance queries.
// Balance reads are lower-stakes than transaction confirmations (no funds move
// as a direct result), so we start with 2-of-3 per the spec design question #2.
// Callers can override via BalanceVerifier config.
//
// NOTE: this is a distinct policy level from the value-scaled PolicyForValue
// tiers; it does NOT replace or modify Quick/Standard/High/Maximum.
var BalancePolicy = VerificationPolicy{
	MinWitnesses: 3,
	MinAgreement: 2,
	Timeout:      5 * time.Second,
}
