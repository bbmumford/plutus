/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

//go:build !js

package exporters

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Options configures Install.
type Options struct {
	// OTLPEndpoint is the host:port for the OTLP gRPC collector. Empty means
	// "do not enable OTLP export".
	OTLPEndpoint string
	// ServiceName is attached as the otel.service.name resource attribute.
	ServiceName string
	// MetricsEnabled enables the Prometheus MeterProvider. The scrape handler
	// is returned from Install so the caller can mount it at /metrics on a
	// listener of its choosing.
	MetricsEnabled bool
	// StdoutFallback emits spans and metrics to stdout when neither OTLP nor
	// Prometheus is configured — useful in dev.
	StdoutFallback bool
}

// Installed describes the providers activated by Install and the work
// required to cleanly shut them down.
type Installed struct {
	TracerProvider  *sdktrace.TracerProvider
	MeterProvider   *sdkmetric.MeterProvider
	MetricsHandler  http.Handler
	Shutdown        func(context.Context) error
}

// Install wires global providers according to opts. It returns an Installed
// struct; the embedded Shutdown func should be deferred by the caller so
// buffered spans/metrics flush on exit.
//
// Behaviour:
//   - If opts.OTLPEndpoint != "" → install OTLP TracerProvider.
//   - else if opts.StdoutFallback → install stdout TracerProvider.
//   - If opts.MetricsEnabled → install Prometheus MeterProvider + return handler.
//   - else if opts.StdoutFallback → install stdout MeterProvider.
func Install(ctx context.Context, opts Options) (*Installed, error) {
	out := &Installed{}

	// Tracer provider selection.
	switch {
	case opts.OTLPEndpoint != "":
		tp, err := NewOTLPProvider(ctx, opts.OTLPEndpoint, opts.ServiceName)
		if err != nil {
			return nil, fmt.Errorf("install: otlp tracer: %w", err)
		}
		otel.SetTracerProvider(tp)
		out.TracerProvider = tp
	case opts.StdoutFallback:
		tp, err := NewStdoutTracerProvider(os.Stdout)
		if err != nil {
			return nil, fmt.Errorf("install: stdout tracer: %w", err)
		}
		otel.SetTracerProvider(tp)
		out.TracerProvider = tp
	}

	// Meter provider selection.
	switch {
	case opts.MetricsEnabled:
		mp, handler, err := NewPrometheusMeterProvider()
		if err != nil {
			return nil, fmt.Errorf("install: prometheus meter: %w", err)
		}
		otel.SetMeterProvider(mp)
		out.MeterProvider = mp
		out.MetricsHandler = handler
	case opts.StdoutFallback:
		mp, err := NewStdoutMeterProvider(os.Stdout)
		if err != nil {
			return nil, fmt.Errorf("install: stdout meter: %w", err)
		}
		otel.SetMeterProvider(mp)
		out.MeterProvider = mp
	}

	out.Shutdown = func(sctx context.Context) error {
		shutdownCtx, cancel := context.WithTimeout(sctx, 5*time.Second)
		defer cancel()
		var firstErr error
		if out.TracerProvider != nil {
			if err := out.TracerProvider.Shutdown(shutdownCtx); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if out.MeterProvider != nil {
			if err := out.MeterProvider.Shutdown(shutdownCtx); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}
	return out, nil
}
