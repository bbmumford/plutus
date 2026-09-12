/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

// Package exporters wires OpenTelemetry SDK providers (OTLP tracing,
// Prometheus metrics, stdout) into the global registry used by the
// observability package. The full SDK is incompatible with GOOS=js /
// GOARCH=wasm, so every file in this subpackage is guarded with the
// !js build tag and only compiled into server binaries such as
// mercury-node.
package exporters
