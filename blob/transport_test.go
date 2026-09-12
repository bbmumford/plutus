/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */

package blob

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/bbmumford/diststore/fetch"
)

// ─── Test doubles ──────────────────────────────────────────────────────────

// memStream is an in-memory AetherStream for tests. Send/Receive round-trip
// through a buffered channel; Close closes the channel.
type memStream struct {
	mu       sync.Mutex
	sendBuf  [][]byte
	recvCh   chan []byte
	closed   bool
	sendHook func([]byte) error
}

func newMemStream() *memStream {
	return &memStream{recvCh: make(chan []byte, 16)}
}

func (s *memStream) Send(ctx context.Context, data []byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("memStream: closed")
	}
	hook := s.sendHook
	s.sendBuf = append(s.sendBuf, append([]byte(nil), data...))
	s.mu.Unlock()
	if hook != nil {
		return hook(data)
	}
	return nil
}

func (s *memStream) Receive(ctx context.Context) ([]byte, error) {
	select {
	case data, ok := <-s.recvCh:
		if !ok {
			return nil, errors.New("memStream: closed")
		}
		return data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (s *memStream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	close(s.recvCh)
	return nil
}

// memSession is an in-memory AetherSession that vends memStreams.
type memSession struct {
	mu     sync.Mutex
	pairs  []*memStream // streams the test has opened
	openCh chan *memStream
}

func newMemSession() *memSession {
	return &memSession{openCh: make(chan *memStream, 8)}
}

func (s *memSession) OpenStream(ctx context.Context, cfg StreamConfig) (AetherStream, error) {
	if cfg.StreamID != fetch.BlobFetchStreamID {
		return nil, errors.New("memSession: unexpected stream id")
	}
	ms := newMemStream()
	s.mu.Lock()
	s.pairs = append(s.pairs, ms)
	s.mu.Unlock()
	return ms, nil
}

func (s *memSession) AcceptStream(ctx context.Context) (AetherStream, error) {
	select {
	case ms := <-s.openCh:
		return ms, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// staticProvider is a SessionProvider that returns a single pre-built session.
type staticProvider struct {
	session AetherSession
	err     error
}

func (p *staticProvider) SessionFor(peerID string) (AetherSession, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.session, nil
}

// ─── Tests ────────────────────────────────────────────────────────────────

func TestAetherTransport_HappyPath(t *testing.T) {
	session := newMemSession()
	provider := &staticProvider{session: session}
	transport := NewAetherTransport(provider)

	// Queue the response the peer will send back.
	respBytes, err := fetch.EncodeFetchResponse(fetch.FetchResponse{
		CID:     "abc123",
		Payload: []byte("hello-piece"),
	})
	if err != nil {
		t.Fatalf("EncodeFetchResponse: %v", err)
	}

	// Prime: when FetchPiece opens the stream, we'll put the framed response
	// into the stream's recvCh. Use a goroutine because OpenStream returns
	// synchronously and we need to seed recvCh before the transport reads it.
	go func() {
		// Wait for the stream to be opened.
		for {
			session.mu.Lock()
			n := len(session.pairs)
			var stream *memStream
			if n > 0 {
				stream = session.pairs[0]
			}
			session.mu.Unlock()
			if stream != nil {
				// Frame: 4-byte big-endian length + payload.
				framed := make([]byte, 4+len(respBytes))
				framed[0] = byte(len(respBytes) >> 24)
				framed[1] = byte(len(respBytes) >> 16)
				framed[2] = byte(len(respBytes) >> 8)
				framed[3] = byte(len(respBytes))
				copy(framed[4:], respBytes)
				stream.recvCh <- framed
				return
			}
		}
	}()

	resp, err := transport.FetchPiece(context.Background(), "peer-A", fetch.FetchRequest{CID: "abc123"})
	if err != nil {
		t.Fatalf("FetchPiece: %v", err)
	}
	if resp.CID != "abc123" {
		t.Errorf("CID = %q, want abc123", resp.CID)
	}
	if string(resp.Payload) != "hello-piece" {
		t.Errorf("Payload = %q, want hello-piece", resp.Payload)
	}
}

func TestAetherTransport_ResponseError(t *testing.T) {
	session := newMemSession()
	transport := NewAetherTransport(&staticProvider{session: session})

	// Peer replies with a FetchResponse.Error payload.
	respBytes, _ := fetch.EncodeFetchResponse(fetch.FetchResponse{
		CID:   "xyz",
		Error: "not held",
	})
	go func() {
		for {
			session.mu.Lock()
			n := len(session.pairs)
			var stream *memStream
			if n > 0 {
				stream = session.pairs[0]
			}
			session.mu.Unlock()
			if stream != nil {
				framed := make([]byte, 4+len(respBytes))
				framed[0] = byte(len(respBytes) >> 24)
				framed[1] = byte(len(respBytes) >> 16)
				framed[2] = byte(len(respBytes) >> 8)
				framed[3] = byte(len(respBytes))
				copy(framed[4:], respBytes)
				stream.recvCh <- framed
				return
			}
		}
	}()

	resp, err := transport.FetchPiece(context.Background(), "peer-A", fetch.FetchRequest{CID: "xyz"})
	if err == nil {
		t.Fatal("expected error from FetchResponse.Error")
	}
	if resp.CID != "xyz" {
		t.Errorf("CID echo = %q, want xyz", resp.CID)
	}
	if resp.Error != "not held" {
		t.Errorf("response Error = %q, want 'not held'", resp.Error)
	}
}

func TestAetherTransport_EmptyPeerIDRejected(t *testing.T) {
	transport := NewAetherTransport(&staticProvider{session: newMemSession()})
	_, err := transport.FetchPiece(context.Background(), "", fetch.FetchRequest{CID: "x"})
	if err == nil {
		t.Fatal("expected error for empty peerID")
	}
}

func TestAetherTransport_NilProviderRejected(t *testing.T) {
	transport := NewAetherTransport(nil)
	_, err := transport.FetchPiece(context.Background(), "p", fetch.FetchRequest{CID: "x"})
	if err == nil {
		t.Fatal("expected error for nil provider")
	}
}

func TestAetherTransport_SessionResolveError(t *testing.T) {
	provider := &staticProvider{err: errors.New("no session")}
	transport := NewAetherTransport(provider)
	_, err := transport.FetchPiece(context.Background(), "peer-X", fetch.FetchRequest{CID: "x"})
	if err == nil {
		t.Fatal("expected session-resolve error")
	}
}
