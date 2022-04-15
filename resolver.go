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
)

const (
	// KeyIDParameter is the name of the URI template parameter for expanding key URIs.
	KeyIDParameterName = "keyId"
)

var (
	// ErrNoTemplate indicates that no URI template is available for that Resolver's method.
	ErrNoTemplate = errors.New("No URI template expander has been configured for that method.")
)

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
}

// NewResolver constructs a Resolver from a set of options.  By default, a Resolver
// uses the DefaultLoader() and DefaultParser().
//
// If no URI template is supplied, ResolveKeyID will return an error.
func NewResolver(options ...ResolverOption) (Resolver, error) {
	r := &resolver{
		fetcher: DefaultFetcher(),
	}

	return r, nil
}

// resolver is the internal Resolver implementation.
type resolver struct {
	fetcher Fetcher

	keyIDExpander Expander
}

func (r *resolver) ResolveKeyID(ctx context.Context, keyID string) (k Key, err error) {
	if r.keyIDExpander == nil {
		err = ErrNoTemplate
	}

	var location string
	if err == nil {
		location, err = r.keyIDExpander.Expand(map[string]interface{}{
			KeyIDParameterName: keyID,
		})
	}

	if err == nil {
		_ = location
	}

	return
}
