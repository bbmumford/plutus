/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

// Package observability exposes the WASM-safe OpenTelemetry API surface used
// by Plutus and Mercury business logic. The subpackage observability/exporters
// (build tag !js) wires the SDK-backed providers into the global registry.
// When no provider is installed, all tracers/meters resolve to no-ops and the
// overhead is effectively zero.
package observability

import (
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// tracerScopeBase is the base instrumentation scope reported with each span.
const tracerScopeBase = "github.com/bbmumford/plutus/observability"

// Tracer returns a named tracer for the given subsystem (e.g. "plutus.escrow",
// "mercury.order"). The returned tracer uses the globally registered
// TracerProvider. If no provider has been installed, the tracer is a no-op.
//
// Callers should pass a dotted subsystem name so that spans from different
// subsystems remain easy to filter in observability backends.
func Tracer(subsystem string) trace.Tracer {
	if subsystem == "" {
		subsystem = tracerScopeBase
	}
	return otel.Tracer(subsystem)
}
