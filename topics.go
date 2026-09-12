/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package plutus

import "github.com/bbmumford/plutus/canonical"

// Topic names include the protocol fingerprint for network isolation.
// A fork with a different trust chain gets different topic names and
// cannot exchange messages with the canonical network.
//
// These are convenience wrappers around canonical.* for callers that
// already import the root plutus package.

// WitnessTopic returns the gossip topic for witness registrations.
func WitnessTopic() string { return canonical.WitnessTopic() }

// AttestRequestTopic returns the gossip topic for attestation requests.
func AttestRequestTopic() string { return canonical.AttestRequestTopic() }

// AttestResponseTopic returns the gossip topic for attestation responses.
func AttestResponseTopic() string { return canonical.AttestResponseTopic() }

// BroadcastTopic returns the gossip topic for transaction broadcast requests.
func BroadcastTopic() string { return canonical.BroadcastTopic() }

// BroadcastResponseTopic returns the gossip topic for transaction broadcast responses.
func BroadcastResponseTopic() string { return canonical.BroadcastResponseTopic() }

// ArbitratorTopic returns the gossip topic for arbitrator registrations.
func ArbitratorTopic() string { return canonical.ArbitratorTopic() }

// RepTradesTopic returns the gossip topic for trade completion records.
func RepTradesTopic() string { return canonical.RepTradesTopic() }

// RepReviewsTopic returns the gossip topic for review records.
func RepReviewsTopic() string { return canonical.RepReviewsTopic() }
