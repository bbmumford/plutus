/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package observability

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// Common attribute keys reused across Plutus/Mercury spans so that backends
// stay consistent regardless of subsystem. Keys use dotted notation following
// OpenTelemetry semantic conventions.
const (
	AttrChainID    = "plutus.chain_id"
	AttrCurrency   = "plutus.currency"
	AttrEscrowAddr = "plutus.escrow.addr"
	AttrTxHash     = "plutus.tx_hash"
	AttrOutcome    = "plutus.outcome"
	AttrOrderID    = "mercury.order.id"
	AttrPeerID     = "mercury.peer.id"
	AttrSubsystem  = "plutus.subsystem"
)

// RecordError marks the current span as failed, records the error, and sets
// the status to Error. Safe to call with a nil span.
func RecordError(span trace.Span, err error) {
	if span == nil || err == nil {
		return
	}
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// StartSpan is a convenience wrapper that starts a span on the given subsystem
// tracer. It is functionally identical to Tracer(subsystem).Start(ctx, name).
func StartSpan(ctx context.Context, subsystem, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return Tracer(subsystem).Start(ctx, name, trace.WithAttributes(attrs...))
}

// AddAttrs appends attributes to a span if the span is non-nil.
func AddAttrs(span trace.Span, attrs ...attribute.KeyValue) {
	if span == nil || len(attrs) == 0 {
		return
	}
	span.SetAttributes(attrs...)
}

// AttrSet collects an attribute slice into a metric.MeasurementOption for
// histogram/counter calls so callers don't need to rebuild WithAttributes
// each time.
func AttrSet(attrs ...attribute.KeyValue) metric.MeasurementOption {
	return metric.WithAttributes(attrs...)
}
