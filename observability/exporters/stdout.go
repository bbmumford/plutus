/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

//go:build !js

package exporters

import (
	"fmt"
	"io"
	"os"

	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// NewStdoutTracerProvider returns a TracerProvider that writes spans to w as
// pretty-printed JSON. Designed for local dev / zero-config operation.
func NewStdoutTracerProvider(w io.Writer) (*sdktrace.TracerProvider, error) {
	if w == nil {
		w = os.Stdout
	}
	exp, err := stdouttrace.New(stdouttrace.WithWriter(w), stdouttrace.WithPrettyPrint())
	if err != nil {
		return nil, fmt.Errorf("exporters: stdout trace exporter: %w", err)
	}
	return sdktrace.NewTracerProvider(
		sdktrace.WithSyncer(exp),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	), nil
}

// NewStdoutMeterProvider returns a MeterProvider that periodically writes
// metric readings to w.
func NewStdoutMeterProvider(w io.Writer) (*metric.MeterProvider, error) {
	if w == nil {
		w = os.Stdout
	}
	exp, err := stdoutmetric.New(stdoutmetric.WithWriter(w), stdoutmetric.WithPrettyPrint())
	if err != nil {
		return nil, fmt.Errorf("exporters: stdout metric exporter: %w", err)
	}
	return metric.NewMeterProvider(metric.WithReader(metric.NewPeriodicReader(exp))), nil
}
