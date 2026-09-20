// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"sort"
	"sync"

	"github.com/xmidt-org/chronon"
)

var (
	// ErrRefresherStarted is returned by Refresher.Start if the Refresher is running.
	ErrRefresherStarted = errors.New("that refresher has already been started")

	// ErrRefresherStopped is returned by Refresher.Stop if the Refresher is not running.
	ErrRefresherStopped = errors.New("that refresher is not running")
)

// RefreshEvent represents a set of keys from a given URI that has been
// asynchronously fetched.
type RefreshEvent struct {
	// URI is the source of the keys.
	URI string

	// Err is the error that occurred while trying to interact with the URI.
	// This field can be nil to indicate no error.  When this field is non-nil,
	// the Keys field will be populated with the last known valid set of keys
	// from the given URI.
	Err error

	// Keys represents the complete set of keys from the URI.  When Err is not nil,
	// this field will be set to the last known valid set of keys.
	//
	// This field will be sorted by KeyID.
	Keys Keys

	// New are the keys that a brand new with this event.  These keys will be
	// included in the Keys field.
	//
	// This field will be sorted by KeyID.
	New Keys

	// Deleted are the keys that are now missing from the refreshed keys.
	// These keys will not be in the Keys field.  These keys will have been present
	// in the previous event(s).
	//
	// This field will be sorted by KeyID.
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
// a default Loader and Parser are created and used.  Whenever the returned error is
// non-nil, the returned Refresher is nil.
func NewRefresher(options ...RefresherOption) (Refresher, error) {
	errs := make([]error, 0, len(options)+1)
	r := &refresher{
		clock: chronon.SystemClock(),
	}

	for _, o := range options {
		errs = append(errs, o.applyToRefresher(r))
	}

	if r.fetcher == nil {
		r.fetcher = NewFetcher()
	}

	errs = append(errs, validateRefreshSources(r.sources...))
	if err := errors.Join(errs...); err != nil {
		// NOTE: an explicit nil, not a nil *refresher, so that a caller comparing the
		// returned interface against nil sees what it expects.
		return nil, err
	}

	return r, nil
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
	r.listeners.visit(func(l any) {
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

// run is the refresh loop for a single source.  It returns when ctx is canceled.
//
// Each cycle's context is derived from ctx, never from the previous cycle's
// context.  The ContentMeta from the last successful fetch is carried in a local
// and layered onto ctx fresh each time, so the context handed to the Fetcher
// stays one value deep for the life of the loop.
func (rt *refreshTask) run(ctx context.Context) {
	var (
		prevKeys   []Key
		prevKeyMap map[string]Key
		prevMeta   ContentMeta
	)

	for {
		event := RefreshEvent{URI: rt.source.URI}
		nextKeys, meta, err := rt.fetcher.Fetch(SetContentMeta(ctx, prevMeta), rt.source.URI)
		next := rt.jitterer.nextInterval(ContentMeta{}, err)
		if err == nil {
			nextKeyMap := rt.newKeyMap(nextKeys)
			event.New, event.Deleted = rt.findChanges(nextKeyMap, prevKeyMap)
			prevMeta = meta
			next = rt.jitterer.nextInterval(meta, nil)

			// send out the next keys
			prevKeys = nextKeys
			prevKeyMap = nextKeyMap
		}

		event.Err = err
		event.Keys = make([]Key, len(prevKeys))
		copy(event.Keys, prevKeys)
		sort.Sort(event.Keys)
		sort.Sort(event.New)
		sort.Sort(event.Deleted)
		rt.dispatch(event)

		timer := rt.clock.NewTimer(next)
		select {
		case <-ctx.Done():
			timer.Stop()
			return

		case <-timer.C():
			// just wait to restart the loop
		}
	}
}
