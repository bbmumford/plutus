/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package escrow

import (
	"context"
	"math/big"
	"sync"
	"time"
)

// btcFundingDefaultPollInterval is how often the BTC funding watcher polls
// the witness mesh for funding UTXO arrival. Slightly longer than the EVM
// poll interval because BTC blocks land roughly every 10 minutes.
const btcFundingDefaultPollInterval = 30 * time.Second

// btcMinConfirmations is the minimum confirmation count required before the
// watcher records the funding. Two confirmations is the standard "soft
// finality" threshold for low-to-medium-value escrows; higher-value escrows
// should add additional check delay at the SDK layer before releasing.
const btcMinConfirmations = 2

// BTCFundingRecorder is the minimum surface a BTC adapter must expose for
// the watcher to mark an escrow funded once the funding UTXO is observed.
//
// The adapter package owns the concrete implementation; this interface lives
// in escrow because the watcher does not depend on the BTC adapter package
// directly (avoids a cycle: escrow already imports the chain-agnostic
// adapter interface, but cannot import adapter/btc without leaking BTC into
// every escrow consumer).
type BTCFundingRecorder interface {
	// RecordFunding marks the escrow at address as funded with the given
	// UTXO (txid, vout, value satoshis). Idempotent.
	RecordFunding(address, fundingTxID string, vout uint32, amountSat *big.Int) error
}

// BTCMeshUTXOSource is the witness-mesh primitive the watcher uses to
// discover the funding UTXO. Implementations attest the address via the
// canonical chain-witness flow (the BTC adapter's BTCClient.ListUnspent
// already routes through the mesh transport, so wiring is a thin wrapper).
type BTCMeshUTXOSource interface {
	// FindFundingUTXO returns the first confirmed UTXO at the given P2WSH
	// address with at least minConf confirmations. Returns ok=false when
	// no qualifying UTXO is present yet (the watcher will retry on the
	// next poll). Returning an error aborts the watcher.
	FindFundingUTXO(ctx context.Context, address string, minConf uint32) (txID string, vout uint32, amountSat *big.Int, ok bool, err error)
}

// BTCEscrowWatcher polls the witness mesh for the funding UTXO of each
// registered BTC escrow and calls RecordFunding on the adapter once the
// UTXO arrives with the required number of confirmations.
//
// This is the BTC counterpart to escrow.watcher: where the EVM watcher
// polls AttestEscrowState and reacts to the contract's Funded flag, the BTC
// watcher polls the address's UTXO set via the mesh because BTC has no
// notion of contract state — funding is observed by witnessing a tx output
// that pays the P2WSH script-hash address.
type BTCEscrowWatcher struct {
	source   BTCMeshUTXOSource
	recorder BTCFundingRecorder
	interval time.Duration
	minConf  uint32

	mu       sync.Mutex
	tracked  map[string]*btcWatchTarget // address -> target
	cancel   context.CancelFunc
	stopped  chan struct{}
}

// btcWatchTarget describes a single escrow being watched.
type btcWatchTarget struct {
	address string
	handler EventHandler
	// recorded turns true after the watcher successfully called RecordFunding
	// — the watcher then drops the entry on its next sweep. Re-funding is
	// not supported (BTC escrows are single-shot).
	recorded bool
}

// NewBTCEscrowWatcher constructs a watcher. Both source and recorder are
// required. Use Start to begin polling; Stop to terminate.
func NewBTCEscrowWatcher(source BTCMeshUTXOSource, recorder BTCFundingRecorder) *BTCEscrowWatcher {
	return &BTCEscrowWatcher{
		source:   source,
		recorder: recorder,
		interval: btcFundingDefaultPollInterval,
		minConf:  btcMinConfirmations,
		tracked:  make(map[string]*btcWatchTarget),
	}
}

// SetPollInterval overrides the default poll interval. Must be called
// before Start; ignored after the watcher is running.
func (w *BTCEscrowWatcher) SetPollInterval(d time.Duration) {
	if d > 0 {
		w.interval = d
	}
}

// SetMinConfirmations overrides the default confirmation threshold (2).
func (w *BTCEscrowWatcher) SetMinConfirmations(n uint32) {
	if n > 0 {
		w.minConf = n
	}
}

// Watch registers a BTC escrow address to be watched. The handler receives
// an EventFunded event once the funding UTXO is observed and recorded.
// Calling Watch on an already-tracked address replaces the handler.
func (w *BTCEscrowWatcher) Watch(address string, handler EventHandler) {
	if address == "" {
		return
	}
	w.mu.Lock()
	w.tracked[address] = &btcWatchTarget{address: address, handler: handler}
	w.mu.Unlock()
}

// Unwatch removes an escrow address from the watch set.
func (w *BTCEscrowWatcher) Unwatch(address string) {
	w.mu.Lock()
	delete(w.tracked, address)
	w.mu.Unlock()
}

// Start launches the polling goroutine. Calling Start more than once is a
// no-op (the watcher already running takes precedence). The context controls
// the lifetime: cancelling it stops the watcher. Stop() also stops it
// regardless of context state.
func (w *BTCEscrowWatcher) Start(ctx context.Context) {
	w.mu.Lock()
	if w.cancel != nil {
		w.mu.Unlock()
		return
	}
	loopCtx, cancel := context.WithCancel(ctx)
	w.cancel = cancel
	w.stopped = make(chan struct{})
	stopped := w.stopped
	w.mu.Unlock()

	go func() {
		defer close(stopped)
		ticker := time.NewTicker(w.interval)
		defer ticker.Stop()

		// Initial sweep so callers don't have to wait one tick on startup.
		w.sweep(loopCtx)
		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				w.sweep(loopCtx)
			}
		}
	}()
}

// Stop terminates the watcher and waits for the goroutine to exit.
func (w *BTCEscrowWatcher) Stop() {
	w.mu.Lock()
	cancel := w.cancel
	stopped := w.stopped
	w.cancel = nil
	w.stopped = nil
	w.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if stopped != nil {
		<-stopped
	}
}

// sweep iterates the tracked escrows once, querying the mesh for the funding
// UTXO of each. Already-recorded entries are pruned. Errors are surfaced via
// the per-target handler as EventError events; they do not abort the sweep.
func (w *BTCEscrowWatcher) sweep(ctx context.Context) {
	w.mu.Lock()
	snapshot := make([]*btcWatchTarget, 0, len(w.tracked))
	for _, t := range w.tracked {
		if t.recorded {
			continue
		}
		snapshot = append(snapshot, t)
	}
	w.mu.Unlock()

	for _, t := range snapshot {
		if ctx.Err() != nil {
			return
		}
		txID, vout, amountSat, ok, err := w.source.FindFundingUTXO(ctx, t.address, w.minConf)
		if err != nil {
			if t.handler != nil {
				t.handler(EscrowEvent{Type: EventError, Data: err})
			}
			continue
		}
		if !ok {
			continue
		}
		if amountSat == nil || amountSat.Sign() <= 0 {
			continue
		}
		if err := w.recorder.RecordFunding(t.address, txID, vout, amountSat); err != nil {
			if t.handler != nil {
				t.handler(EscrowEvent{Type: EventError, Data: err})
			}
			continue
		}

		w.mu.Lock()
		t.recorded = true
		w.mu.Unlock()

		if t.handler != nil {
			t.handler(EscrowEvent{
				Type:   EventFunded,
				TxHash: txID,
				Data: BTCFundingEventData{
					Address:   t.address,
					TxID:      txID,
					Vout:      vout,
					AmountSat: new(big.Int).Set(amountSat),
				},
			})
		}
	}
}

// BTCFundingEventData is delivered as the Data field of an EventFunded
// event emitted by BTCEscrowWatcher.
type BTCFundingEventData struct {
	Address   string
	TxID      string
	Vout      uint32
	AmountSat *big.Int
}
