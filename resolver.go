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

// resolver is the internal Resolver implementation.
type resolver struct {
	fetcher   Fetcher
	listeners listeners

	keyIDExpander Expander
}

func (r *resolver) dispatch(event ResolveEvent) {
	r.listeners.visit(func(l interface{}) {
		l.(ResolveListener).OnResolveEvent(event)
	})
}

func (r *resolver) ResolveKeyID(ctx context.Context, keyID string) (k Key, err error) {
	var location string
	if err == nil {
		location, err = r.keyIDExpander.Expand(map[string]interface{}{
			KeyIDParameterName: keyID,
		})
	}

	var keys []Key
	if err == nil {
		keys, _, err = r.fetcher.Fetch(ctx, location, ContentMeta{})
	}

	if err == nil {
		if len(keys) == 1 {
			k = keys[0]
		} else {
			err = errors.New("TODO")
		}
	}

	r.dispatch(ResolveEvent{
		URI:   location,
		Key:   k,
		KeyID: keyID,
		Err:   err,
	})

	return
}

func (r *resolver) AddListener(l ResolveListener) CancelListenerFunc {
	return r.listeners.addListener(l)
}
