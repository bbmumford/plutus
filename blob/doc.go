/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

// Package blob wires the ledger distributed-blob subsystem onto the
// Aether wire protocol. It is the Plutus-side "Phase 3" adapter the
// ledger.distributed package intentionally stops short of providing.
//
// # Responsibilities
//
// The ledger package (see _PACKAGES/ledger/blob/distributed) defines the
// transport-agnostic pieces of the blob subsystem:
//
//   - BlobFetchStreamID (uint64 = 300) — the well-known Aether stream ID
//     assigned to the blob-fetch subprotocol.
//   - FetchRequest / FetchResponse — JSON-encoded wire envelopes.
//   - EncodeFetchRequest / DecodeFetchRequest / EncodeFetchResponse /
//     DecodeFetchResponse — canonical codecs.
//   - PeerTransport — the interface the Fetcher needs to reach a peer.
//
// The ledger package deliberately does NOT import aether so the extraction
// direction stays clean. This package supplies the Aether binding: an
// AetherTransport type that satisfies distributed.PeerTransport by opening
// a stream on BlobFetchStreamID and exchanging length-prefixed JSON frames.
//
// # Wire format
//
// Both directions use a 4-byte big-endian uint32 length prefix followed by
// the JSON-encoded payload:
//
//	→ client writes len(req) || EncodeFetchRequest(req)
//	← server writes len(resp) || EncodeFetchResponse(resp)
//
// Frames > MaxFrameSize (300 KiB) are rejected. A single piece is 256 KiB
// plus a small JSON envelope — 300 KiB leaves headroom without risking
// DoS via unbounded allocations.
//
// # Usage
//
// The consumer (mesh_embed in ORBTR) constructs only the outbound side
// here; the inbound (server) side is wired via minerva_sdk.Node.OnStream
// inside mesh_embed itself (see mesh_embed.serveBlobFetches) so that a
// single handler dispatches across every peer session without an
// explicit per-session accept loop:
//
//	// Outbound: turn a SessionProvider into a PeerTransport.
//	transport := blob.NewAetherTransport(provider)
//	fetcher, _ := distributed.NewFetcher(resolver, transport, cfg)
//
// See _PACKAGES/ledger/blob/distributed/fetcher.go for the full transport
// contract and the Phase 2 agent notes on Aether integration.
package blob
