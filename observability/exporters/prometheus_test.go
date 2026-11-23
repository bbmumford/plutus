/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

//go:build !js

package exporters

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
)

func TestPrometheusMeterProviderServesMetrics(t *testing.T) {
	mp, handler, err := NewPrometheusMeterProvider()
	if err != nil {
		t.Fatalf("NewPrometheusMeterProvider: %v", err)
	}
	defer func() { _ = mp.Shutdown(context.Background()) }()

	// Register the MeterProvider and emit one observation so /metrics has
	// something to report.
	otel.SetMeterProvider(mp)
	meter := otel.Meter("github.com/bbmumford/plutus/observability/test")
	c, err := meter.Int64Counter("plutus_test_counter")
	if err != nil {
		t.Fatalf("counter: %v", err)
	}
	c.Add(context.Background(), 7)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "plutus_test_counter") {
		t.Fatalf("expected plutus_test_counter in scrape body, got:\n%s", body)
	}
}
