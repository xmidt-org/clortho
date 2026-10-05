// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"time"
)

// RefreshEvent describes one refresh of one source.  It is dispatched to every
// Listener after every attempt, successful or not.  The one exception is an
// attempt that Stop interrupts, which is abandoned without an event.
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

	// KeySetBytes is the size of the key set the keys in KeyIDs came from: what
	// this source served at its last successful load.  Like KeyIDs it describes
	// what is on the ring, so a failed refresh leaves it unchanged, as does a
	// refresh the server answered with a 304.  Zero if the source has never
	// loaded.
	KeySetBytes int64
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
	p      *KeySetProvider

	// requests carries early refresh requests.  Each carries a channel that is
	// closed once the request has been handled, whether or not a refresh ran.
	requests chan chan struct{}
}

func newRefreshTask(p *KeySetProvider, index int) *refreshTask {
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

// rateLimited reports whether an early refresh is refused: the source was
// attempted within its minimum interval, or the server asked for a wait that
// has not yet passed.
func (t *refreshTask) rateLimited() bool {
	t.p.stateLock.Lock()
	defer t.p.stateLock.Unlock()

	now := t.p.clock.Now()
	state := &t.p.states[t.index]
	return now.Sub(state.lastAttempt) < t.source.MinRefreshInterval || now.Before(state.retryAt)
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
// A load that fails because ctx was canceled is abandoned instead: the status
// and the ring are left as they were and no event is dispatched.
func (t *refreshTask) refresh(ctx context.Context) time.Duration {
	t.p.stateLock.Lock()
	since := t.p.states[t.index].lastModified
	t.p.stateLock.Unlock()

	event := RefreshEvent{URI: redactURI(t.source.URI)}
	c, err := load(ctx, t.source, since)
	if err != nil && ctx.Err() != nil {
		// Stop canceled the loop while the load was in flight.  that is the
		// KeySetProvider abandoning the attempt, not the source failing, so nothing
		// is recorded or dispatched.  the interval is an ordinary one, never zero,
		// so that run finds the canceled context before the timer can fire.
		return t.jitter.nextInterval(0, err)
	}

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
	retryWait, loaded, keySetBytes := t.record(c, err)
	event.KeySetBytes = keySetBytes
	t.p.dispatch(event)
	return t.nextRefresh(c, err, retryWait, loaded)
}

// nextRefresh returns the time until the source's next refresh.  After a
// success that is the normal schedule.  After a failure it depends on what
// went wrong:
//
//   - A wait the server asked for with Retry-After is taken as given, even
//     when it is shorter than the source's minimum.  The server is the one
//     that knows when it can answer.
//   - A key set the source served and clortho rejected waits for the normal
//     schedule, since asking again sooner would get the same key set.
//     A source that has never loaded is the exception: it has no keys to
//     fall back on, so it is retried after the minimum.
//   - Anything else is retried after the minimum.
func (t *refreshTask) nextRefresh(c content, err error, retryWait time.Duration, loaded bool) time.Duration {
	switch {
	case err == nil:
		return t.jitter.nextInterval(c.ttl, nil)

	case retryWait > 0:
		return t.jitter.delayed(retryWait)

	case loaded && rejectedContent(err):
		return t.jitter.nextInterval(0, err)

	default:
		return t.jitter.delayed(t.source.MinRefreshInterval)
	}
}

// rejectedContent reports whether a refresh failed because of what the source
// served, rather than because the source could not be read.  The source
// answered in full, so only a change at the source will change the outcome.
func rejectedContent(err error) bool {
	return errors.Is(err, ErrSymmetricKey) ||
		errors.Is(err, ErrMissingKeyID) ||
		errors.Is(err, ErrDuplicateKeyID) ||
		errors.Is(err, ErrResponseTooLarge)
}

// record updates the source's status after an attempt.  It returns how long
// the key set server asked clortho to wait before the next attempt, or zero if
// it did not ask, whether the source has ever loaded successfully, and the
// size of the key set its keys on the ring came from.
func (t *refreshTask) record(c content, err error) (retryWait time.Duration, loaded bool, keySetBytes int64) {
	t.p.stateLock.Lock()
	defer t.p.stateLock.Unlock()

	now := t.p.clock.Now()
	state := &t.p.states[t.index]
	state.lastAttempt = now
	state.retryAt = time.Time{}
	state.status.LastStatusCode = c.statusCode
	state.status.LastErr = err
	if err != nil {
		if retryWait = c.retryWait(now); retryWait > 0 {
			// the same wait the timer gets, before its jitter
			state.retryAt = now.Add(min(retryWait, t.source.MaxRefreshInterval))
		}

		return retryWait, !state.status.LastRetrieved.IsZero(), state.keySetBytes
	}

	state.status.LastRetrieved = now
	if !c.notModified {
		state.lastModified = c.lastModified
		state.keySetBytes = int64(len(c.data))
	}

	return 0, true, state.keySetBytes
}
