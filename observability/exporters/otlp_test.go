/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

//go:build !js

package exporters

import (
	"context"
	"testing"
)

func TestNewOTLPProviderRejectsEmptyEndpoint(t *testing.T) {
	_, err := NewOTLPProvider(context.Background(), "", "svc")
	if err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

func TestNewOTLPProviderConstructs(t *testing.T) {
	// Use a bogus but syntactically valid endpoint; we don't attempt to
	// dial it at construction time.
	tp, err := NewOTLPProvider(context.Background(), "127.0.0.1:65535", "plutus-test")
	if err != nil {
		t.Fatalf("NewOTLPProvider: %v", err)
	}
	if tp == nil {
		t.Fatal("TracerProvider is nil")
	}
	_ = tp.Shutdown(context.Background())
}
