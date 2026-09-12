/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

//go:build !js

package exporters

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// NewPrometheusMeterProvider constructs an OTel MeterProvider that routes
// measurements into a Prometheus registry and returns the HTTP handler that
// serves the `/metrics` scrape endpoint.
func NewPrometheusMeterProvider() (*sdkmetric.MeterProvider, http.Handler, error) {
	registry := prometheus.NewRegistry()
	exp, err := otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		return nil, nil, fmt.Errorf("exporters: prometheus exporter: %w", err)
	}

	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(exp))
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry})
	return mp, handler, nil
}
