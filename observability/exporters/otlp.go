/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

//go:build !js

package exporters

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// NewOTLPProvider constructs a TracerProvider that exports spans over OTLP
// gRPC to the configured endpoint. The caller owns the returned provider and
// must call Shutdown during graceful termination.
func NewOTLPProvider(ctx context.Context, endpoint, serviceName string) (*sdktrace.TracerProvider, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("exporters: OTLP endpoint required")
	}
	if serviceName == "" {
		serviceName = "plutus"
	}

	exp, err := otlptrace.New(ctx, otlptracegrpc.NewClient(
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
		otlptracegrpc.WithTimeout(5*time.Second),
	))
	if err != nil {
		return nil, fmt.Errorf("exporters: OTLP trace exporter: %w", err)
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(semconv.ServiceName(serviceName)),
	)
	if err != nil {
		return nil, fmt.Errorf("exporters: resource init: %w", err)
	}

	bsp := sdktrace.NewBatchSpanProcessor(exp,
		sdktrace.WithMaxQueueSize(2048),
		sdktrace.WithBatchTimeout(5*time.Second),
	)

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSpanProcessor(bsp),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	return tp, nil
}
