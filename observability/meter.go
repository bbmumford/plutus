/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package observability

import (
	"sync"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// meterScope is the instrumentation scope used for every pre-defined meter.
const meterScope = "github.com/bbmumford/plutus/observability"

// Meter returns the shared meter for Plutus/Mercury. When no MeterProvider has
// been installed this resolves to a no-op meter and all instruments become
// zero-cost.
func Meter() metric.Meter {
	return otel.Meter(meterScope)
}

// ----- Pre-defined instruments ----------------------------------------------
//
// All instruments are initialised lazily and cached in package-level vars. If
// instrument creation fails (extremely unlikely for a no-op / SDK meter), a
// fallback no-op instrument is substituted so callers never have to guard
// nils.

var (
	instrumentsOnce sync.Once

	// Escrow instruments.
	escrowFundedCount    metric.Int64Counter
	escrowReleasedCount  metric.Int64Counter
	escrowDisputedCount  metric.Int64Counter
	escrowRefundedCount  metric.Int64Counter
	escrowFundDuration   metric.Float64Histogram
	escrowStateQueries   metric.Int64Counter

	// Witness instruments.
	witnessAttestCount    metric.Int64Counter
	witnessQuorumFailures metric.Int64Counter
	witnessVerifyDuration metric.Float64Histogram
	witnessBalanceQueries metric.Int64Counter

	// Settlement instruments.
	settlementCount     metric.Int64Counter
	settlementDuration  metric.Float64Histogram
	settlementFeeTotal  metric.Int64Histogram

	// Gossip / mesh-broadcast instruments.
	gossipBroadcastCount    metric.Int64Counter
	gossipBroadcastFailures metric.Int64Counter

	// Fee / PRC instruments.
	feeCalculatedCount metric.Int64Counter
	feeRejectedCount   metric.Int64Counter

	// Mercury order & arbitration instruments.
	orderCreatedCount   metric.Int64Counter
	orderSettledCount   metric.Int64Counter
	arbitrationOpened   metric.Int64Counter
	arbitrationResolved metric.Int64Counter
	messagingSentCount  metric.Int64Counter
	storePutCount       metric.Int64Counter
	storeReplicateCount metric.Int64Counter
)

// initInstruments lazily constructs every pre-defined instrument.
func initInstruments() {
	m := Meter()

	escrowFundedCount = mustCounter(m, "plutus.escrow.funded", "Number of escrows successfully funded.")
	escrowReleasedCount = mustCounter(m, "plutus.escrow.released", "Number of escrows released to the seller.")
	escrowDisputedCount = mustCounter(m, "plutus.escrow.disputed", "Number of escrows placed into dispute.")
	escrowRefundedCount = mustCounter(m, "plutus.escrow.refunded", "Number of escrows refunded after timeout.")
	escrowFundDuration = mustFloatHistogram(m, "plutus.escrow.fund.duration_ms", "Duration of escrow funding in milliseconds.")
	escrowStateQueries = mustCounter(m, "plutus.escrow.state_queries", "Number of escrow state attestations requested.")

	witnessAttestCount = mustCounter(m, "plutus.witness.attestations", "Total witness attestations produced.")
	witnessQuorumFailures = mustCounter(m, "plutus.witness.quorum_failures", "Attestation rounds that failed to reach quorum.")
	witnessVerifyDuration = mustFloatHistogram(m, "plutus.witness.verify.duration_ms", "Witness verification duration in milliseconds.")
	witnessBalanceQueries = mustCounter(m, "plutus.witness.balance_queries", "Total balance witness queries executed.")

	settlementCount = mustCounter(m, "plutus.settlement.count", "Number of settlements executed.")
	settlementDuration = mustFloatHistogram(m, "plutus.settlement.duration_ms", "Settlement orchestration duration in milliseconds.")
	settlementFeeTotal = mustIntHistogram(m, "plutus.settlement.fee_total", "Total fees extracted from settlements (minor units).")

	gossipBroadcastCount = mustCounter(m, "plutus.gossip.broadcast.count", "Number of gossip broadcasts sent.")
	gossipBroadcastFailures = mustCounter(m, "plutus.gossip.broadcast.failures", "Number of gossip broadcast failures.")

	feeCalculatedCount = mustCounter(m, "plutus.fee.calculated", "Number of fee-breakdown calculations performed.")
	feeRejectedCount = mustCounter(m, "plutus.fee.rejected", "Number of settlements rejected due to fee mismatch.")

	orderCreatedCount = mustCounter(m, "mercury.order.created", "Orders created via Mercury.")
	orderSettledCount = mustCounter(m, "mercury.order.settled", "Orders completed via Mercury.")
	arbitrationOpened = mustCounter(m, "mercury.arbitration.opened", "Arbitration disputes opened.")
	arbitrationResolved = mustCounter(m, "mercury.arbitration.resolved", "Arbitration disputes resolved.")
	messagingSentCount = mustCounter(m, "mercury.messaging.sent", "Peer messages sent.")
	storePutCount = mustCounter(m, "mercury.store.put", "Store writes performed.")
	storeReplicateCount = mustCounter(m, "mercury.store.replicate", "Store replications performed.")
}

func ensureInstruments() { instrumentsOnce.Do(initInstruments) }

// ----- Accessors (typed to encourage discovery) -----------------------------

// EscrowFundedCount returns the counter incremented when an escrow is funded.
func EscrowFundedCount() metric.Int64Counter { ensureInstruments(); return escrowFundedCount }

// EscrowReleasedCount returns the counter incremented when an escrow is released.
func EscrowReleasedCount() metric.Int64Counter { ensureInstruments(); return escrowReleasedCount }

// EscrowDisputedCount returns the counter incremented when an escrow is disputed.
func EscrowDisputedCount() metric.Int64Counter { ensureInstruments(); return escrowDisputedCount }

// EscrowRefundedCount returns the counter incremented when an escrow is refunded.
func EscrowRefundedCount() metric.Int64Counter { ensureInstruments(); return escrowRefundedCount }

// EscrowFundDuration returns the histogram that records escrow funding latency.
func EscrowFundDuration() metric.Float64Histogram { ensureInstruments(); return escrowFundDuration }

// EscrowStateQueries returns the counter for escrow state attestation calls.
func EscrowStateQueries() metric.Int64Counter { ensureInstruments(); return escrowStateQueries }

// WitnessAttestCount returns the witness attestation counter.
func WitnessAttestCount() metric.Int64Counter { ensureInstruments(); return witnessAttestCount }

// WitnessQuorumFailures returns the witness quorum-failure counter.
func WitnessQuorumFailures() metric.Int64Counter { ensureInstruments(); return witnessQuorumFailures }

// WitnessVerifyDuration returns the witness verification latency histogram.
func WitnessVerifyDuration() metric.Float64Histogram { ensureInstruments(); return witnessVerifyDuration }

// WitnessBalanceQueries returns the balance witness-query counter.
func WitnessBalanceQueries() metric.Int64Counter { ensureInstruments(); return witnessBalanceQueries }

// SettlementCount returns the settlement counter.
func SettlementCount() metric.Int64Counter { ensureInstruments(); return settlementCount }

// SettlementDuration returns the settlement latency histogram.
func SettlementDuration() metric.Float64Histogram { ensureInstruments(); return settlementDuration }

// SettlementFeeTotal returns the histogram of fee totals in minor units.
func SettlementFeeTotal() metric.Int64Histogram { ensureInstruments(); return settlementFeeTotal }

// GossipBroadcastCount returns the gossip broadcast counter.
func GossipBroadcastCount() metric.Int64Counter { ensureInstruments(); return gossipBroadcastCount }

// GossipBroadcastFailures returns the gossip broadcast failure counter.
func GossipBroadcastFailures() metric.Int64Counter {
	ensureInstruments()
	return gossipBroadcastFailures
}

// FeeCalculatedCount returns the fee calculation counter.
func FeeCalculatedCount() metric.Int64Counter { ensureInstruments(); return feeCalculatedCount }

// FeeRejectedCount returns the counter for fee enforcement rejections.
func FeeRejectedCount() metric.Int64Counter { ensureInstruments(); return feeRejectedCount }

// OrderCreatedCount returns the Mercury order creation counter.
func OrderCreatedCount() metric.Int64Counter { ensureInstruments(); return orderCreatedCount }

// OrderSettledCount returns the Mercury order-settled counter.
func OrderSettledCount() metric.Int64Counter { ensureInstruments(); return orderSettledCount }

// ArbitrationOpened returns the arbitration opened counter.
func ArbitrationOpened() metric.Int64Counter { ensureInstruments(); return arbitrationOpened }

// ArbitrationResolved returns the arbitration resolved counter.
func ArbitrationResolved() metric.Int64Counter { ensureInstruments(); return arbitrationResolved }

// MessagingSentCount returns the Mercury messaging sent counter.
func MessagingSentCount() metric.Int64Counter { ensureInstruments(); return messagingSentCount }

// StorePutCount returns the Mercury store put counter.
func StorePutCount() metric.Int64Counter { ensureInstruments(); return storePutCount }

// StoreReplicateCount returns the Mercury store replication counter.
func StoreReplicateCount() metric.Int64Counter { ensureInstruments(); return storeReplicateCount }

// ----- Internal helpers ------------------------------------------------------

// nopMeter is used as an explicit fallback whenever instrument creation fails
// against the globally configured meter. It guarantees non-nil instruments.
var nopMeter = noop.NewMeterProvider().Meter(meterScope)

func mustCounter(m metric.Meter, name, desc string) metric.Int64Counter {
	c, err := m.Int64Counter(name, metric.WithDescription(desc))
	if err != nil || c == nil {
		fallback, _ := nopMeter.Int64Counter(name)
		return fallback
	}
	return c
}

func mustFloatHistogram(m metric.Meter, name, desc string) metric.Float64Histogram {
	h, err := m.Float64Histogram(name, metric.WithDescription(desc))
	if err != nil || h == nil {
		fallback, _ := nopMeter.Float64Histogram(name)
		return fallback
	}
	return h
}

func mustIntHistogram(m metric.Meter, name, desc string) metric.Int64Histogram {
	h, err := m.Int64Histogram(name, metric.WithDescription(desc))
	if err != nil || h == nil {
		fallback, _ := nopMeter.Int64Histogram(name)
		return fallback
	}
	return h
}
