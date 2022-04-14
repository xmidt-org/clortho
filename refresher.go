package clortho

import (
	"context"
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

// refreshListeners holds a set of listener channels and a cached set of events
// that have been dispatched, one per source URI.
type refreshListeners struct {
	lock      sync.Mutex
	listeners map[chan<- RefreshEvent]bool
	cache     map[string]RefreshEvent
}

func (rl *refreshListeners) addListener(ch chan<- RefreshEvent) {
	rl.lock.Lock()
	defer rl.lock.Unlock()

	if rl.listeners == nil {
		rl.listeners = make(map[chan<- RefreshEvent]bool, 1)
	}

	rl.listeners[ch] = true

	// dispatch cached events to this new listener
	for _, e := range rl.cache {
		ch <- e
	}
}

func (rl *refreshListeners) removeListener(ch chan<- RefreshEvent) {
	rl.lock.Lock()
	defer rl.lock.Unlock()

	if rl.listeners != nil {
		delete(rl.listeners, ch)
	}
}

func (rl *refreshListeners) dispatch(e RefreshEvent) {
	rl.lock.Lock()
	defer rl.lock.Unlock()

	if rl.cache == nil {
		rl.cache = make(map[string]RefreshEvent, 1)
	}

	rl.cache[e.URI] = e
	for ch := range rl.listeners {
		ch <- e
	}
}

type RefreshEvent struct {
	URI  string
	Err  error
	Keys []Key
}

type RefresherOption interface {
	applyToRefresher(*refresher) error
}

type refresherOptionFunc func(*refresher) error

func (rof refresherOptionFunc) applyToRefresher(r *refresher) error {
	return rof(r)
}

func WithClock(c chronon.Clock) RefresherOption {
	return refresherOptionFunc(func(r *refresher) error {
		r.clock = c
		return nil
	})
}

func WithLoader(l Loader) RefresherOption {
	return refresherOptionFunc(func(r *refresher) error {
		r.loader = l
		return nil
	})
}

func WithParser(p Parser) RefresherOption {
	return refresherOptionFunc(func(r *refresher) error {
		r.parser = p
		return nil
	})
}

func WithSources(sources ...RefreshSource) RefresherOption {
	return refresherOptionFunc(func(r *refresher) error {
		r.sources = append(r.sources, sources...)
		return nil
	})
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
	AddListener(chan<- RefreshEvent)

	// RemoveListener deregisters a channel.  The supplied channel will no longer receive
	// events from this Refresher.
	RemoveListener(chan<- RefreshEvent)
}

// NewRefresher constructs a Refresher using the supplied options.  Without any options,
// a default Refresher is created.
func NewRefresher(options ...RefresherOption) (Refresher, error) {
	var err error
	r := &refresher{
		clock: chronon.SystemClock(),
	}

	for _, o := range options {
		err = multierr.Append(err, o.applyToRefresher(r))
	}

	var validationErr error
	r.sources, validationErr = validateAndSetDefaults(r.sources...)
	err = multierr.Append(err, validationErr)

	// delay creating the loader and parser, since it's slightly more
	// expensive to create them just for defaults

	if r.loader == nil {
		// when no options are passed, this never returns an error
		r.loader, _ = NewLoader()
	}

	if r.parser == nil {
		// when no options are passed, this never returns an error
		r.parser, _ = NewParser()
	}

	return r, err
}

// refresher is the internal Refresher implementation.
type refresher struct {
	loader    Loader
	parser    Parser
	sources   []RefreshSource
	listeners refreshListeners
	clock     chronon.Clock

	taskLock   sync.Mutex
	taskCancel context.CancelFunc
	tasks      []*refreshTask
}

func (r *refresher) fetchKeys(ctx context.Context, location string, prev ContentMeta) (keys []Key, next ContentMeta, err error) {
	var data []byte
	data, next, err = r.loader.LoadContent(ctx, location, prev)

	if err == nil {
		keys, err = r.parser.Parse(next.Format, data)
	}

	return
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
				fetchKeys: r.fetchKeys,
				dispatch:  r.listeners.dispatch,
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

func (r *refresher) AddListener(ch chan<- RefreshEvent) {
	r.listeners.addListener(ch)
}

func (r *refresher) RemoveListener(ch chan<- RefreshEvent) {
	r.listeners.removeListener(ch)
}

type refreshTask struct {
	source    RefreshSource
	fetchKeys func(context.Context, string, ContentMeta) ([]Key, ContentMeta, error)
	dispatch  func(RefreshEvent)
	clock     chronon.Clock

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

func (rt *refreshTask) run(ctx context.Context) {
	var (
		keys []Key
		meta ContentMeta
	)

	for {
		nextKeys, nextMeta, err := rt.fetchKeys(ctx, rt.source.URI, meta)
		switch {
		case ctx.Err() != nil:
			// we were asked to shutdown, and this interrupted the fetch
			// we can't inspect err for this, because a child context may have
			// been used for the underlying operation, e.g. HTTP request
			return

		case err == nil:
			keys = nextKeys
			meta = nextMeta

		case err != nil:
			// reset the content metadata
			meta = ContentMeta{}
		}

		rt.dispatch(RefreshEvent{
			URI:  rt.source.URI,
			Keys: keys,
			Err:  err,
		})

		var (
			next  = rt.computeNextRefresh(meta, err)
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
