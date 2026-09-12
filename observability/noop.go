/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package observability

import (
	"go.opentelemetry.io/otel"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// init registers explicit no-op Tracer/Meter providers so any imports of this
// package get defined zero-cost behaviour even when no exporter is installed.
// Callers wishing to enable real export must invoke exporters.Install (which
// lives in the !js subpackage) — that call replaces these providers.
func init() {
	otel.SetTracerProvider(tracenoop.NewTracerProvider())
	otel.SetMeterProvider(metricnoop.NewMeterProvider())
}
