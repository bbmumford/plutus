/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
 */
package escrow

import (
	"context"
	"time"
)

const (
	// defaultPollInterval is how often the watcher polls escrow state.
	defaultPollInterval = 15 * time.Second

	// Event type constants emitted by the watcher.
	EventFunded   = "funded"
	EventReleased = "released"
	EventDisputed = "disputed"
	EventSettled  = "settled"
	EventTimedOut = "timed_out"
	EventError    = "error"
)

// watcher polls escrow state via MeshVerifier and emits events when
// state transitions occur. Each watcher monitors a single escrow address.
type watcher struct {
	verifier   MeshVerifier
	chainID    string
	escrowAddr string
	handler    EventHandler
	interval   time.Duration

	// lastState tracks the previous snapshot to detect transitions.
	lastState *OnChainEscrowState
}

// newWatcher creates a watcher for the given escrow address.
func newWatcher(verifier MeshVerifier, chainID, escrowAddr string, handler EventHandler) *watcher {
	return &watcher{
		verifier:   verifier,
		chainID:    chainID,
		escrowAddr: escrowAddr,
		handler:    handler,
		interval:   defaultPollInterval,
	}
}

// run polls the escrow state on a fixed interval until the context is cancelled.
// On each poll, it compares the current state to the last known state and fires
// events for any transitions detected.
func (w *watcher) run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	// Do an initial poll immediately.
	w.poll(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.poll(ctx)
		}
	}
}

// poll fetches the current escrow state and emits events for any transitions.
func (w *watcher) poll(ctx context.Context) {
	snapshot, err := w.verifier.AttestEscrowState(ctx, w.chainID, w.escrowAddr)
	if err != nil {
		w.handler(EscrowEvent{
			Type: EventError,
			Data: err,
		})
		return
	}

	current := &snapshot.State
	w.detectTransitions(current, snapshot)
	w.lastState = current
}

// detectTransitions compares old and new state, emitting events for each
// boolean flag that transitioned from false to true.
func (w *watcher) detectTransitions(current *OnChainEscrowState, snapshot *EscrowSnapshot) {
	prev := w.lastState

	// On first poll, emit events for any already-true flags.
	if prev == nil {
		if current.Funded {
			w.emit(EventFunded, snapshot)
		}
		if current.Released {
			w.emit(EventReleased, snapshot)
		}
		if current.Disputed {
			w.emit(EventDisputed, snapshot)
		}
		if current.Settled {
			w.emit(EventSettled, snapshot)
		}
		if current.TimedOut {
			w.emit(EventTimedOut, snapshot)
		}
		return
	}

	// Detect false -> true transitions.
	if !prev.Funded && current.Funded {
		w.emit(EventFunded, snapshot)
	}
	if !prev.Released && current.Released {
		w.emit(EventReleased, snapshot)
	}
	if !prev.Disputed && current.Disputed {
		w.emit(EventDisputed, snapshot)
	}
	if !prev.Settled && current.Settled {
		w.emit(EventSettled, snapshot)
	}
	if !prev.TimedOut && current.TimedOut {
		w.emit(EventTimedOut, snapshot)
	}
}

// emit fires an event to the registered handler.
func (w *watcher) emit(eventType string, snapshot *EscrowSnapshot) {
	w.handler(EscrowEvent{
		Type: eventType,
		Data: snapshot,
	})
}
