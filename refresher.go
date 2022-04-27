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
	"context"
	"errors"
	"sort"
	"sync"

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
	Keys Keys

	// New are the keys that a brand new with this event.  These keys will be
	// included in the Keys field.
	New Keys

	// Deleted are the keys that are now missing from the refreshed keys.
	// These keys will not be in the Keys field.  These keys will have been present
	// in the previous event(s).
	Deleted Keys
}

// RefreshListener is a sink for RefreshEvents.
type RefreshListener interface {
	// OnRefreshEvent receives a refresh event.  This method must not panic.
	OnRefreshEvent(RefreshEvent)
}

// Refresher handles asynchronously refreshing sets of keys from one or more sources.
type Refresher interface {
	// Start bootstraps tasks that fetch keys and dispatch events to any listeners.
	// Keys will arrive asynchronously to any registered listeners.
	//
	// If this Refresher has already been started, this method returns ErrRefresherStarted.
	Start(context.Context) error

	// Stop shuts down all refresh tasks.
	//
	// If this Refresher is not running, this method returns ErrRefresherStopped.
	Stop(context.Context) error

	// AddListener registers a channel that receives refresh events.  No caching of events
	// is done.  The supplied listener will receive events the next time any of the key
	// sources are queried.
	//
	// The returned closure can be used to cancel refreshes sent to the listener.  Clients
	// are not required to use this closure, particularly if the listener is active for the
	// life of the application.
	AddListener(l RefreshListener) CancelListenerFunc
}

// NewRefresher constructs a Refresher using the supplied options.  Without any options,
// a default Loader and Parser are created and used.
func NewRefresher(options ...RefresherOption) (Refresher, error) {
	var err error
	r := &refresher{
		clock: chronon.SystemClock(),
	}

	for _, o := range options {
		err = multierr.Append(err, o.applyToRefresher(r))
	}

	if r.fetcher == nil {
		r.fetcher, _ = NewFetcher()
	}

	err = multierr.Append(err, validateRefreshSources(r.sources...))
	if err != nil {
		r = nil
	}

	return r, err
}

// refresher is the internal Refresher implementation.
type refresher struct {
	fetcher   Fetcher
	sources   []RefreshSource
	listeners listeners

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
			task = &refreshTask{
				source:   s,
				fetcher:  r.fetcher,
				jitterer: newJitterer(s),
				dispatch: r.dispatch,
				clock:    r.clock,
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

func (r *refresher) AddListener(l RefreshListener) CancelListenerFunc {
	return r.listeners.addListener(l)
}

func (r *refresher) dispatch(event RefreshEvent) {
	r.listeners.visit(func(l interface{}) {
		l.(RefreshListener).OnRefreshEvent(event)
	})
}

type refreshTask struct {
	source   RefreshSource
	fetcher  Fetcher
	jitterer jitterer

	dispatch func(RefreshEvent)
	clock    chronon.Clock
}

func (rt *refreshTask) newKeyMap(keys []Key) (m map[string]Key) {
	m = make(map[string]Key, len(keys))
	for _, k := range keys {
		m[k.KeyID()] = k
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
			nextKeyMap := rt.newKeyMap(nextKeys)

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

		sort.Sort(event.Keys)
		sort.Sort(event.New)
		sort.Sort(event.Deleted)
		rt.dispatch(event)

		var (
			next  = rt.jitterer.nextInterval(prevMeta, err)
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
