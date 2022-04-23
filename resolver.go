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
	"sync"
	"sync/atomic"

	"github.com/jtacoma/uritemplates"
	"go.uber.org/multierr"
)

const (
	// KeyIDParameter is the name of the URI template parameter for expanding key URIs.
	KeyIDParameterName = "keyId"
)

var (
	// ErrNoTemplate indicates that no URI template is available for that Resolver's method.
	ErrNoTemplate = errors.New("No URI template expander has been configured for that method.")

	// ErrKeyNotFound indicates that a key could not be resolved, e.g. a key ID did not exist.
	ErrKeyNotFound = errors.New("No such key exists")
)

// ResolveEvent holds information about a key ID that has been resolved.
type ResolveEvent struct {
	// URI is the actual, expanded URI used to obtain the key material.
	URI string

	// KeyID is the key ID that was resolved.
	KeyID string

	// Key is the key material that was returned from the URI.
	Key Key

	// Err holds any error that occurred while trying to fetch key material.
	// If this field is set, Key will be nil.
	Err error
}

// ResolveListener is a sink for ResolveEvents.
type ResolveListener interface {
	// OnResolveEvent receives notifications for attempts to resolve keys.  This
	// method must not panic.
	OnResolveEvent(ResolveEvent)
}

// Expander is the strategy for expanding a URI template.
type Expander interface {
	// Expand takes a value map and returns the URI resulting from that expansion.
	Expand(interface{}) (string, error)
}

// NewExpander constructs an Expander from a URI template.
func NewExpander(rawTemplate string) (Expander, error) {
	return uritemplates.Parse(rawTemplate)
}

// Resolver allows synchronous resolution of keys.
type Resolver interface {
	// ResolveKeyID attempts to locate a key with a given keyID (kid).
	ResolveKeyID(ctx context.Context, keyID string) (Key, error)

	// AddListener attaches a sink for ResolveEvents.  Only events that
	// occur after this method call will be dispatched to the given listener.
	AddListener(ResolveListener) CancelListenerFunc
}

// NewResolver constructs a Resolver from a set of options.  By default, a Resolver
// uses the DefaultLoader() and DefaultParser().
//
// If no URI template is supplied, this function returns ErrNoTemplate.
func NewResolver(options ...ResolverOption) (Resolver, error) {
	var (
		err error

		r = &resolver{
			fetcher: DefaultFetcher(),
			pending: pendingResolverRequests{},
		}
	)

	for _, o := range options {
		err = multierr.Append(err, o.applyToResolver(r))
	}

	if r.keyIDExpander == nil {
		err = multierr.Append(err, ErrNoTemplate)
	}

	return r, err
}

// pendingResolverRequest represents a resolve operation that is inflight.  Concurrent
// code may use this to block on the results of a resolve operation happening in another
// goroutine.
type pendingResolverRequest struct {
	done  chan struct{}
	value atomic.Value
}

type pendingResolverRequests map[string]*pendingResolverRequest

func (prr pendingResolverRequests) requestFor(keyID string) (r *pendingResolverRequest, wait bool) {
	r, wait = prr[keyID]
	if !wait {
		r = &pendingResolverRequest{
			done: make(chan struct{}),
		}

		prr[keyID] = r
	}

	return
}

// resolver is the internal Resolver implementation.
type resolver struct {
	fetcher   Fetcher
	listeners listeners

	resolveLock sync.Mutex
	pending     pendingResolverRequests
	keyRing     KeyRing

	keyIDExpander Expander
}

func (r *resolver) dispatch(event ResolveEvent) {
	r.listeners.visit(func(l interface{}) {
		l.(ResolveListener).OnResolveEvent(event)
	})
}

func (r *resolver) checkKeyRing(keyID string) (k Key, ok bool) {
	if r.keyRing != nil {
		k, ok = r.keyRing.Get(keyID)
	}

	return
}

func (r *resolver) waitForKey(ctx context.Context, request *pendingResolverRequest) (k Key, err error) {
	select {
	case <-ctx.Done():
		err = ctx.Err()

	case <-request.done:
		var ok bool
		k, ok = request.value.Load().(Key)
		if !ok {
			err = ErrKeyNotFound
		}
	}

	return
}

func (r *resolver) fetchKey(ctx context.Context, keyID string, request *pendingResolverRequest) (location string, k Key, err error) {
	location, err = r.keyIDExpander.Expand(map[string]interface{}{
		KeyIDParameterName: keyID,
	})

	var keys []Key
	if err == nil {
		keys, _, err = r.fetcher.Fetch(ctx, location, ContentMeta{})
	}

	if err == nil {
		switch len(keys) {
		case 0:
			err = ErrKeyNotFound

		case 1:
			k = keys[0]

		default:
			// scan a key set looking for the key in question
			for _, candidate := range keys {
				if candidate.KeyID() == keyID {
					k = candidate
					break
				}
			}

			if k == nil {
				err = ErrKeyNotFound
			}
		}
	}

	return
}

func (r *resolver) ResolveKeyID(ctx context.Context, keyID string) (k Key, err error) {
	var ok bool
	if k, ok = r.checkKeyRing(keyID); ok {
		return
	}

	r.resolveLock.Lock()
	if k, ok = r.checkKeyRing(keyID); ok {
		r.resolveLock.Unlock()
		return
	}

	request, wait := r.pending.requestFor(keyID)
	r.resolveLock.Unlock()

	if wait {
		// another goroutine is currently fetching the key, so wait for it to be done
		k, err = r.waitForKey(ctx, request)
	} else {
		// this is the goroutine that is now responsible for fetching the key
		var location string
		location, k, err = r.fetchKey(ctx, keyID, request)

		// release the waiting goroutines before dispatching the event
		r.resolveLock.Lock()
		if k != nil {
			r.keyRing.Add(k)
			request.value.Store(k)
		}

		close(request.done)
		r.resolveLock.Unlock()

		r.dispatch(ResolveEvent{
			URI:   location,
			Key:   k,
			KeyID: keyID,
			Err:   err,
		})
	}

	return
}

func (r *resolver) AddListener(l ResolveListener) CancelListenerFunc {
	return r.listeners.addListener(l)
}
