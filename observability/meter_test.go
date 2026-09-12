/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package observability

import (
	"context"
	"testing"
)

func TestMeterReturnsNonNil(t *testing.T) {
	if Meter() == nil {
		t.Fatal("Meter returned nil")
	}
}

func TestPreDefinedInstrumentsUsable(t *testing.T) {
	ctx := context.Background()
	// Every pre-defined counter should accept Add(ctx, 1) without panic.
	EscrowFundedCount().Add(ctx, 1)
	EscrowReleasedCount().Add(ctx, 1)
	EscrowDisputedCount().Add(ctx, 1)
	EscrowRefundedCount().Add(ctx, 1)
	EscrowStateQueries().Add(ctx, 1)
	WitnessAttestCount().Add(ctx, 1)
	WitnessQuorumFailures().Add(ctx, 1)
	WitnessBalanceQueries().Add(ctx, 1)
	SettlementCount().Add(ctx, 1)
	GossipBroadcastCount().Add(ctx, 1)
	GossipBroadcastFailures().Add(ctx, 1)
	FeeCalculatedCount().Add(ctx, 1)
	FeeRejectedCount().Add(ctx, 1)
	OrderCreatedCount().Add(ctx, 1)
	OrderSettledCount().Add(ctx, 1)
	ArbitrationOpened().Add(ctx, 1)
	ArbitrationResolved().Add(ctx, 1)
	MessagingSentCount().Add(ctx, 1)
	StorePutCount().Add(ctx, 1)
	StoreReplicateCount().Add(ctx, 1)

	// Histograms.
	EscrowFundDuration().Record(ctx, 1.5)
	WitnessVerifyDuration().Record(ctx, 2.3)
	SettlementDuration().Record(ctx, 4.7)
	SettlementFeeTotal().Record(ctx, 42)
}
