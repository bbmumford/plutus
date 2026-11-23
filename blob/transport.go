/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */

package blob

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/bbmumford/diststore/fetch"
)

// MaxFrameSize caps both request and response envelopes at 300 KiB. A
// single piece is 256 KiB; the extra 44 KiB absorbs the JSON envelope
// (CID + error fields) and prevents DoS via unbounded allocations.
const MaxFrameSize = 300 * 1024

// ReliabilityReliableOrdered mirrors aether.ReliableOrdered (= 0) without
// forcing blob-transport callers or tests to import aether. We assert the
// value at wire time; if aether ever renumbers the constant, the adapter
// that implements AetherSession must translate.
const ReliabilityReliableOrdered uint8 = 0

// StreamConfig is the subset of aether.StreamConfig the blob transport
// needs. Keeping it local means AetherSession stays a minimal interface
// that tests can satisfy with a handful of lines.
type StreamConfig struct {
	// StreamID is the application stream ID — always
	// fetch.BlobFetchStreamID (300) for this subprotocol.
	StreamID uint64
	// Reliability is the delivery guarantee — always
	// ReliabilityReliableOrdered for blob fetch.
	Reliability uint8
}

// AetherStream is the minimal view of aether.Stream used for a single
// fetch-piece exchange: send the request, read the response, close.
//
// Tests mock this with an in-memory byte buffer.
type AetherStream interface {
	// Send writes data onto the stream. Must respect ctx cancellation.
	Send(ctx context.Context, data []byte) error
	// Receive reads the next payload from the stream. Must respect ctx
	// cancellation.
	Receive(ctx context.Context) ([]byte, error)
	// Close half-closes the stream gracefully. Safe to call more than
	// once — subsequent calls return nil.
	Close() error
}

// AetherSession is the minimal view of aether.Session the blob transport
// needs to open a new blob-fetch stream to a connected peer.
//
// The real *aether.Session (or a per-peer wrapper) satisfies this
// interface directly because its OpenStream signature takes a matching
// StreamConfig shape.
//
// AcceptStream is retained on the interface because mesh_embed's
// minervaAetherSession adapter must compile against it, but the
// server side now runs through minerva_sdk.Node.OnStream rather than a
// per-session accept loop — adapters that cannot support AcceptStream
// return an explanatory error instead of implementing it.
type AetherSession interface {
	// OpenStream opens a new stream with the given configuration.
	OpenStream(ctx context.Context, cfg StreamConfig) (AetherStream, error)
	// AcceptStream blocks until the peer opens a stream; adapters
	// wired through minerva's OnStream dispatcher may return an error
	// here since the server side is handled out-of-band.
	AcceptStream(ctx context.Context) (AetherStream, error)
}

// SessionProvider resolves a peerID to a live Aether session.
//
// Minerva owns the sessions table keyed by peerID
// (*minerva_sdk.Node.sessions). Mesh-embed supplies an adapter that looks
// up the session via that table plus a thin wrapper satisfying
// AetherSession.
type SessionProvider interface {
	// SessionFor returns the active session to peerID, or an error when
	// no session is connected.
	SessionFor(peerID string) (AetherSession, error)
}

// ErrFrameTooLarge is returned when a wire frame exceeds MaxFrameSize.
var ErrFrameTooLarge = errors.New("plutus/blob: frame exceeds MaxFrameSize")

// AetherTransport satisfies fetch.PeerTransport by opening an Aether
// stream on BlobFetchStreamID, exchanging a single length-prefixed
// JSON request/response pair, then closing the stream.
type AetherTransport struct {
	provider SessionProvider
}

// NewAetherTransport wraps the given SessionProvider. provider must be
// non-nil; FetchPiece returns an error for any peerID the provider
// cannot resolve.
func NewAetherTransport(provider SessionProvider) *AetherTransport {
	return &AetherTransport{provider: provider}
}

// FetchPiece implements fetch.PeerTransport. It:
//  1. Resolves the peerID to a live Aether session.
//  2. Opens a fresh stream on BlobFetchStreamID with
//     ReliableOrdered semantics.
//  3. Writes the length-prefixed FetchRequest.
//  4. Reads ONE length-prefixed FetchResponse.
//  5. Closes the stream.
//
// On transport errors the stream is still closed (best-effort) before
// returning. When the response carries FetchResponse.Error, the returned
// error is errors.New(resp.Error) so the fetcher can log the peer's
// reason; the response is also returned so callers that want to inspect
// CID / partial payload can do so.
func (t *AetherTransport) FetchPiece(ctx context.Context, peerID string, req fetch.FetchRequest) (fetch.FetchResponse, error) {
	if t == nil || t.provider == nil {
		return fetch.FetchResponse{}, errors.New("plutus/blob: transport has no session provider")
	}
	if peerID == "" {
		return fetch.FetchResponse{}, errors.New("plutus/blob: empty peerID")
	}

	session, err := t.provider.SessionFor(peerID)
	if err != nil {
		return fetch.FetchResponse{}, fmt.Errorf("plutus/blob: session for %q: %w", peerID, err)
	}
	if session == nil {
		return fetch.FetchResponse{}, fmt.Errorf("plutus/blob: no session for %q", peerID)
	}

	stream, err := session.OpenStream(ctx, StreamConfig{
		StreamID:    fetch.BlobFetchStreamID,
		Reliability: ReliabilityReliableOrdered,
	})
	if err != nil {
		return fetch.FetchResponse{}, fmt.Errorf("plutus/blob: open stream: %w", err)
	}
	// Close is idempotent per AetherStream contract.
	defer func() { _ = stream.Close() }()

	reqBytes, err := fetch.EncodeFetchRequest(req)
	if err != nil {
		return fetch.FetchResponse{}, fmt.Errorf("plutus/blob: encode request: %w", err)
	}
	if err := writeFrame(ctx, stream, reqBytes); err != nil {
		return fetch.FetchResponse{}, fmt.Errorf("plutus/blob: write request: %w", err)
	}

	respBytes, err := readFrame(ctx, stream)
	if err != nil {
		return fetch.FetchResponse{}, fmt.Errorf("plutus/blob: read response: %w", err)
	}
	resp, err := fetch.DecodeFetchResponse(respBytes)
	if err != nil {
		return fetch.FetchResponse{}, fmt.Errorf("plutus/blob: decode response: %w", err)
	}
	if resp.Error != "" {
		// Return the decoded response too so callers can inspect CID echo.
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// writeFrame writes a 4-byte big-endian length prefix followed by payload.
// Payloads exceeding MaxFrameSize are rejected locally rather than
// offered to the peer.
func writeFrame(ctx context.Context, stream AetherStream, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("%w: %d > %d", ErrFrameTooLarge, len(payload), MaxFrameSize)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(payload)))
	frame := make([]byte, 0, 4+len(payload))
	frame = append(frame, hdr[:]...)
	frame = append(frame, payload...)
	return stream.Send(ctx, frame)
}

// readFrame reads a single length-prefixed frame. The length prefix MAY
// arrive in a separate Receive from the body (aether does not guarantee
// one-Send = one-Receive), so we accumulate until we have header + body.
//
// Returns ErrFrameTooLarge when the advertised length exceeds
// MaxFrameSize — we refuse to allocate the buffer in that case.
func readFrame(ctx context.Context, stream AetherStream) ([]byte, error) {
	var buf []byte
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(buf) >= 4 {
			length := binary.BigEndian.Uint32(buf[:4])
			if length > MaxFrameSize {
				return nil, fmt.Errorf("%w: advertised %d", ErrFrameTooLarge, length)
			}
			total := 4 + int(length)
			if len(buf) >= total {
				return buf[4:total], nil
			}
		}
		chunk, err := stream.Receive(ctx)
		if err != nil {
			return nil, err
		}
		if len(chunk) == 0 {
			// Peer closed before sending the full frame.
			return nil, errors.New("plutus/blob: stream closed mid-frame")
		}
		buf = append(buf, chunk...)
	}
}
