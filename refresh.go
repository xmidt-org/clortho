// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"time"
)

// RefreshEvent describes one refresh of one source.  It is dispatched to every
// Listener after every attempt, successful or not.
//
// Events carry key IDs, never keys.  A string identifier is always a KeyID in
// this package, and "key" alone always means the key material.
type RefreshEvent struct {
	// URI is the source's URI with any password redacted.
	URI string

	// Err is why the refresh failed, or nil.  On failure the ring is untouched
	// and KeyIDs lists what this source still supplies.
	Err error

	// KeyIDs are the key IDs now on the ring from this source, sorted.
	KeyIDs []string

	// NewKeyIDs are the key IDs this refresh added, sorted.
	NewKeyIDs []string

	// DeletedKeyIDs are the key IDs this refresh removed, sorted.
	DeletedKeyIDs []string
}

// Listener is a sink for RefreshEvents.  OnRefreshEvent is called from the
// refresh goroutine and must not panic.
type Listener interface {
	OnRefreshEvent(RefreshEvent)
}

// refreshTask is the refresh loop for one source.
type refreshTask struct {
	index  int
	source RefreshSource
	jitter jitterer
	p      *Provider

	// requests carries early refresh requests.  Each carries a channel that is
	// closed once the request has been handled, whether or not a refresh ran.
	requests chan chan struct{}
}

func newRefreshTask(p *Provider, index int) *refreshTask {
	return &refreshTask{
		index:    index,
		source:   p.sources[index],
		jitter:   newJitterer(p.sources[index]),
		p:        p,
		requests: make(chan chan struct{}),
	}
}

// run refreshes the source until ctx is canceled.  It refreshes once at
// start, then at each jittered interval, and early on request.
func (t *refreshTask) run(ctx context.Context) {
	var pending chan struct{}
	for {
		next := t.refresh(ctx)
		if pending != nil {
			close(pending)
			pending = nil
		}

		timer := t.p.clock.NewTimer(next)
	wait:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return

			case <-timer.C():
				break wait

			case done := <-t.requests:
				if t.rateLimited() {
					// answered without a refresh: the requester sees the ring as is
					close(done)
					continue
				}

				timer.Stop()
				pending = done
				break wait
			}
		}
	}
}

// rateLimited reports whether the source was attempted within its minimum
// interval, in which case an early refresh is refused.
func (t *refreshTask) rateLimited() bool {
	t.p.stateLock.Lock()
	defer t.p.stateLock.Unlock()

	last := t.p.states[t.index].lastAttempt
	return t.p.clock.Now().Sub(last) < t.source.MinRefreshInterval
}

// requestRefresh asks the loop for an early refresh and waits until it has
// been handled, the caller's context ends, or the loop stops.
func (t *refreshTask) requestRefresh(ctx, runCtx context.Context) {
	done := make(chan struct{})
	select {
	case t.requests <- done:
	case <-ctx.Done():
		return
	case <-runCtx.Done():
		return
	}

	select {
	case <-done:
	case <-ctx.Done():
	case <-runCtx.Done():
	}
}

// refresh loads the source once, applies the result to the ring, records the
// outcome, dispatches an event, and returns the time until the next refresh.
func (t *refreshTask) refresh(ctx context.Context) time.Duration {
	t.p.stateLock.Lock()
	since := t.p.states[t.index].lastModified
	t.p.stateLock.Unlock()

	event := RefreshEvent{URI: redactURI(t.source.URI)}
	c, err := load(ctx, t.source, since)
	switch {
	case err != nil:
		event.KeyIDs = t.p.ring.keyIDsFor(t.index)

	case c.notModified:
		event.KeyIDs = t.p.ring.keyIDsFor(t.index)

	default:
		var keys, applyErr = parseKeys(c.data)
		if applyErr == nil {
			event.KeyIDs, event.NewKeyIDs, event.DeletedKeyIDs, applyErr = t.p.ring.apply(t.index, keys)
		} else {
			event.KeyIDs = t.p.ring.keyIDsFor(t.index)
		}

		err = applyErr
	}

	event.Err = err
	t.record(c, err)
	t.p.dispatch(event)
	return t.jitter.nextInterval(c.ttl, err)
}

// record updates the source's status after an attempt.
func (t *refreshTask) record(c content, err error) {
	t.p.stateLock.Lock()
	defer t.p.stateLock.Unlock()

	now := t.p.clock.Now()
	state := &t.p.states[t.index]
	state.lastAttempt = now
	state.status.LastStatusCode = c.statusCode
	state.status.LastErr = err
	if err != nil {
		return
	}

	state.status.LastRetrieved = now
	if !c.notModified {
		state.lastModified = c.lastModified
	}
}
