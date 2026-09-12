/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package witness

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/bbmumford/plutus/canonical"
	"github.com/bbmumford/whisper"
)

// topicBroadcast and topicBroadcastResponse are resolved at init time from
// the protocol fingerprint for network isolation.
var (
	topicBroadcast         string
	topicBroadcastResponse string
)

func init() {
	topicBroadcast = canonical.BroadcastTopic()
	topicBroadcastResponse = canonical.BroadcastResponseTopic()
}

// broadcastRequest is the wire format for a transaction broadcast request.
// Witnesses that have RPC access to the target chain pick these up, submit
// the signed transaction, and publish the resulting txHash back on the
// response topic.
type broadcastRequest struct {
	RequestID string `json:"requestId"`
	ChainID   string `json:"chainId"`
	SignedTx  []byte `json:"signedTx"`
}

// broadcastResponse is the wire format for a broadcast result.
type broadcastResponse struct {
	RequestID string `json:"requestId"`
	TxHash    string `json:"txHash"`
	Error     string `json:"error,omitempty"`
}

// BroadcastService relays signed transactions to the chain via the witness
// mesh. Browser WASM nodes that cannot connect to chain RPCs directly publish
// their signed transactions here; witness nodes with chain access pick them
// up and submit them.
//
// A single long-lived subscriber is registered on the response topic to
// avoid subscriber leaks. Pending requests are tracked in a map and routed
// by request ID.
type BroadcastService struct {
	engine *whisper.Engine

	mu      sync.Mutex
	pending map[string]chan broadcastResponse // requestID -> response channel
}

// NewBroadcastService creates a broadcast service wired to the Whisper engine.
// It registers a single subscriber on the response topic that demultiplexes
// responses to pending requests.
func NewBroadcastService(engine *whisper.Engine) *BroadcastService {
	b := &BroadcastService{
		engine:  engine,
		pending: make(map[string]chan broadcastResponse),
	}
	// Single long-lived subscriber -- no leak.
	engine.Subscribe(topicBroadcastResponse, b)
	return b
}

// OnBroadcast implements whisper.Subscriber. It demultiplexes broadcast
// responses to the correct pending request by request ID.
func (b *BroadcastService) OnBroadcast(topic string, from string, payload []byte) {
	var resp broadcastResponse
	if err := json.Unmarshal(payload, &resp); err != nil {
		return
	}

	b.mu.Lock()
	ch, ok := b.pending[resp.RequestID]
	if ok {
		delete(b.pending, resp.RequestID) // one-shot: remove after first response
	}
	b.mu.Unlock()

	if ok {
		select {
		case ch <- resp:
		default:
		}
	}
}

// BroadcastTx publishes a signed transaction on the plutus.broadcast topic and
// waits for a witness to submit it and return the txHash. Returns an error if
// no witness responds within the context deadline.
func (b *BroadcastService) BroadcastTx(ctx context.Context, chainID string, signedTx []byte) (string, error) {
	if len(signedTx) == 0 {
		return "", fmt.Errorf("witness: signed transaction is empty")
	}
	if chainID == "" {
		return "", fmt.Errorf("witness: chain ID is required")
	}

	reqID := fmt.Sprintf("bc-%d", time.Now().UnixNano())

	req := broadcastRequest{
		RequestID: reqID,
		ChainID:   chainID,
		SignedTx:  signedTx,
	}
	payload, err := json.Marshal(req)
	if err != nil {
		return "", fmt.Errorf("witness: marshal broadcast request: %w", err)
	}

	// Register the pending request before publishing to avoid races.
	responseCh := make(chan broadcastResponse, 1)
	b.mu.Lock()
	b.pending[reqID] = responseCh
	b.mu.Unlock()

	// Cleanup on exit to prevent map leak if context cancels.
	defer func() {
		b.mu.Lock()
		delete(b.pending, reqID)
		b.mu.Unlock()
	}()

	// Publish the request.
	if err := b.engine.Publish(topicBroadcast, payload); err != nil {
		return "", fmt.Errorf("witness: publish broadcast request: %w", err)
	}

	// Wait for response or timeout.
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("witness: broadcast timed out: %w", ctx.Err())
	case resp := <-responseCh:
		if resp.Error != "" {
			return "", fmt.Errorf("witness: broadcast failed: %s", resp.Error)
		}
		return resp.TxHash, nil
	}
}
