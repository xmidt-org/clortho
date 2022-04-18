/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package clortho

import (
	"container/list"
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"math/rand"
	"sync"
	"time"

	_ "crypto/sha256"

	"github.com/xmidt-org/chronon"
	"go.uber.org/multierr"
)

var (
	// ErrRefresherStarted is returned by Refresher.Start if the Refresher is running.
	ErrRefresherStarted = errors.New("That refresher has already been started")

	// ErrRefresherStopped is returned by Refresher.Stop if the Refresher is not running.
	ErrRefresherStopped = errors.New("That refresher is not running")
)

// RefreshEvent represents a set of keys from a given URI that has been
// asynchronously fetched.
type RefreshEvent struct {
	// URI is the source of the keys.
	URI string

	// Err is the error that occurred while trying to interact with the URI.
	// This field can be nil to indicate no error.  When this field is non-nil,
	// the various keys fields will be populated with the last valid set of keys
	// from the URI.
	Err error

	// Keys represents the complete set of keys from the URI.  When Err is not nil,
	// this field will be set to the last known valid set of keys.
	Keys []Key

	// New are the keys that a brand new with this event.  These keys will be
	// included in the Keys field.
	New []Key

	// Deleted are the keys that are now missing from the refreshed keys.
	// These keys will not be in the Keys field.  These keys will have been present
	// in the previous event(s).
	Deleted []Key
}

// RefreshListener is a sink for RefreshEvents.
type RefreshListener interface {
	// OnRefreshEvent receives a refresh event.  This method must not panic.
	OnRefreshEvent(RefreshEvent)
}

// CancelRefreshFunc is returned by Refresher.AddListener so that callers
// can remove the RefreshListener just added.
//
// A CancelRefreshFunc is idempotent:  after the first invocation, calling this
// closure will have no effect.
type CancelRefreshFunc func()

// refreshListeners holds a set of listener channels and a cached set of events
// that have been dispatched, one per source URI.
type refreshListeners struct {
	lock      sync.Mutex
	listeners *list.List
	cache     map[string]RefreshEvent
}

// cancelRefresh creates an idempotent closure that removes the given linked list element.
func (rl *refreshListeners) cancelRefresh(e *list.Element) CancelRefreshFunc {
	return func() {
		rl.lock.Lock()
		defer rl.lock.Unlock()

		// NOTE: Remove is idempotent: it will not do anything if e is not in the list
		rl.listeners.Remove(e)
	}
}

func (rl *refreshListeners) addListener(l RefreshListener) CancelRefreshFunc {
	rl.lock.Lock()
	defer rl.lock.Unlock()

	if rl.listeners == nil {
		rl.listeners = list.New()
	}

	e := rl.listeners.PushBack(l)

	// dispatch cached events to this new listener
	for _, e := range rl.cache {
		l.OnRefreshEvent(e)
	}

	return rl.cancelRefresh(e)
}

func (rl *refreshListeners) dispatch(event RefreshEvent) {
	rl.lock.Lock()
	defer rl.lock.Unlock()

	if rl.cache == nil {
		rl.cache = make(map[string]RefreshEvent, 1)
	}

	rl.cache[event.URI] = event
	for e := rl.listeners.Front(); e != nil; e = e.Next() {
		e.Value.(RefreshListener).OnRefreshEvent(event)
	}
}

// Refresher handles asynchronously refreshing sets of keys from one or more sources.
type Refresher interface {
	// Start bootstraps tasks that fetch keys and dispatch events to any listeners.
	// Keys will arrive asynchronously to any registered listener channels.
	Start(context.Context) error

	// Stop shuts down all refresh tasks.
	Stop(context.Context) error

	// AddListener registers a channel that receives refresh events.  If this refresher
	// was already started, the supplied channel immediately receives the most recent events
	// from each source.
	//
	// The returned closure can be used to cancel refreshes sent to the listener.  Clients
	// are not required to use this closure, particularly if the listener is active for the
	// life of the application.
	AddListener(l RefreshListener) CancelRefreshFunc
}

// NewRefresher constructs a Refresher using the supplied options.  Without any options,
// the DefaultLoader() and DefaultParser() are used.
func NewRefresher(options ...RefresherOption) (Refresher, error) {
	var err error
	r := &refresher{
		fetcher:        DefaultFetcher(),
		thumbprintHash: crypto.SHA256,
		clock:          chronon.SystemClock(),
	}

	for _, o := range options {
		err = multierr.Append(err, o.applyToRefresher(r))
	}

	var validationErr error
	r.sources, validationErr = validateAndSetDefaults(r.sources...)
	err = multierr.Append(err, validationErr)

	return r, err
}

// refresher is the internal Refresher implementation.
type refresher struct {
	fetcher        Fetcher
	sources        []RefreshSource
	listeners      refreshListeners
	thumbprintHash crypto.Hash

	clock chronon.Clock

	taskLock   sync.Mutex
	taskCancel context.CancelFunc
	tasks      []*refreshTask
}

func (r *refresher) Start(_ context.Context) error {
	r.taskLock.Lock()
	defer r.taskLock.Unlock()

	if r.taskCancel != nil {
		return ErrRefresherStarted
	}

	tasks := make([]*refreshTask, 0, len(r.sources))
	taskCtx, taskCancel := context.WithCancel(context.Background())
	for _, s := range r.sources {
		var (
			// precompute the jitter range for the configured interval
			jitterLo = int64((1.0 - s.Jitter) * float64(s.Interval))
			jitterHi = int64((1.0 + s.Jitter) * float64(s.Interval))

			task = &refreshTask{
				source:    s,
				fetcher:   r.fetcher,
				listeners: &r.listeners,
				clock:     r.clock,

				intervalBase:  jitterLo,
				intervalRange: jitterHi - jitterLo + 1,
			}
		)

		go task.run(taskCtx)
		tasks = append(tasks, task)
	}

	r.taskCancel = taskCancel
	r.tasks = tasks

	return nil
}

func (r *refresher) Stop(_ context.Context) error {
	r.taskLock.Lock()
	defer r.taskLock.Unlock()

	if r.taskCancel == nil {
		return ErrRefresherStopped
	}

	r.taskCancel()
	r.taskCancel = nil
	r.tasks = nil

	return nil
}

func (r *refresher) AddListener(l RefreshListener) CancelRefreshFunc {
	return r.listeners.addListener(l)
}

type refreshTask struct {
	source         RefreshSource
	fetcher        Fetcher
	listeners      *refreshListeners
	thumbprintHash crypto.Hash
	clock          chronon.Clock

	// precomputed jitter range
	intervalBase  int64
	intervalRange int64
}

func (rt *refreshTask) computeNextRefresh(meta ContentMeta, err error) (next time.Duration) {
	switch {
	case err != nil || meta.TTL <= 0:
		next = time.Duration(rt.intervalBase + rand.Int63n(rt.intervalRange))

	default:
		// adjust the jitter window down, so that we always pick a random interval
		// that is less than or equal to the TTL.
		base := int64(2.0 * (1.0 - rt.source.Jitter) * float64(meta.TTL))
		next = time.Duration(rand.Int63n(int64(meta.TTL) - base + 1))
	}

	// enforce our minimum interval regardless of how the next interval was calculated
	if next < rt.source.MinInterval {
		next = rt.source.MinInterval
	}

	return
}

func (rt *refreshTask) newKeyMap(keys []Key) (m map[string]Key, err error) {
	m = make(map[string]Key, len(keys))
	for _, k := range keys {
		keyID := k.KeyID()
		if len(keyID) == 0 {
			if h, hErr := k.Thumbprint(rt.thumbprintHash); hErr == nil {
				keyID = base64.RawURLEncoding.EncodeToString(h)
			} else {
				// NOTE: something wrong with this key, so report the error but
				// drop the key on the floor.
				err = multierr.Append(err, hErr)
				continue
			}
		}

		m[keyID] = k
	}

	return
}

func (rt *refreshTask) findChanges(next, prev map[string]Key) (newKeys, deletedKeys []Key) {
	for nkid, nkey := range next {
		if _, ok := prev[nkid]; !ok {
			// a key in the next map but not in the previous map is a new key
			newKeys = append(newKeys, nkey)
		}
	}

	for pkid, pkey := range prev {
		if _, ok := next[pkid]; !ok {
			// a key in the previous map but not in the next map is a deleted key
			deletedKeys = append(deletedKeys, pkey)
		}
	}

	return
}

func (rt *refreshTask) run(ctx context.Context) {
	var (
		prevKeys   []Key
		prevKeyMap map[string]Key
		prevMeta   ContentMeta
	)

	for {
		nextKeys, nextMeta, err := rt.fetcher.Fetch(ctx, rt.source.URI, prevMeta)
		event := RefreshEvent{
			URI: rt.source.URI,
			Err: err,
		}

		switch {
		case ctx.Err() != nil:
			// we were asked to shutdown, and this interrupted the fetch
			// we can't inspect err for this, because a child context may have
			// been used for the underlying operation, e.g. HTTP request
			return

		case err == nil:
			// TODO: handle the error somehow
			nextKeyMap, _ := rt.newKeyMap(nextKeys)

			event.Keys = make([]Key, len(nextKeys))
			copy(event.Keys, nextKeys)
			event.New, event.Deleted = rt.findChanges(nextKeyMap, prevKeyMap)

			prevKeys = nextKeys
			prevKeyMap = nextKeyMap
			prevMeta = nextMeta

		case err != nil:
			// reset the content metadata
			prevMeta = ContentMeta{}

			// send out the previous keys, and leave New/Deleted unset
			event.Keys = make([]Key, len(prevKeys))
			copy(event.Keys, prevKeys)
		}

		rt.listeners.dispatch(event)

		var (
			next  = rt.computeNextRefresh(prevMeta, err)
			timer = rt.clock.NewTimer(next)
		)

		select {
		case <-ctx.Done():
			timer.Stop()
			return

		case <-timer.C():
			// just wait to restart the loop
		}
	}
}
