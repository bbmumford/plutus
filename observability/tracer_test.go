/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package observability

import (
	"context"
	"testing"
)

func TestTracerReturnsNonNil(t *testing.T) {
	tr := Tracer("plutus.test")
	if tr == nil {
		t.Fatal("Tracer returned nil")
	}
}

func TestTracerDistinctSubsystems(t *testing.T) {
	a := Tracer("plutus.escrow")
	b := Tracer("plutus.witness")
	if a == nil || b == nil {
		t.Fatal("Tracer returned nil for a valid subsystem")
	}
	// Start a span on each so the no-op providers are exercised end-to-end.
	_, s1 := a.Start(context.Background(), "op-a")
	s1.End()
	_, s2 := b.Start(context.Background(), "op-b")
	s2.End()
}

func TestStartSpanHelper(t *testing.T) {
	ctx, span := StartSpan(context.Background(), "plutus.test", "TestOp")
	if span == nil {
		t.Fatal("StartSpan returned nil span")
	}
	defer span.End()
	if ctx == nil {
		t.Fatal("StartSpan returned nil context")
	}
	AddAttrs(span) // no-op branch
	RecordError(span, nil)
	RecordError(nil, nil)
}
