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

	"go.uber.org/multierr"
)

// Fetcher handles fetching keys from URI locations.  This is the typical application-layer interface.
// Generally, clients should use this interface over Loader and Parser.
type Fetcher interface {
	// Fetch grabs keys from a URI.  The prev ContentMeta may either be an empty struct, e.g. ContentMeta{},
	// or the ContentMeta from a previous call to Fetch.
	Fetch(ctx context.Context, location string, prev ContentMeta) (keys []Key, next ContentMeta, err error)
}

var defaultFetcher Fetcher

func init() {
	defaultFetcher, _ = NewFetcher()
}

// DefaultFetcher returns the singleton default Fetcher instance, which is equivalent to what would
// be created by calling NewFetcher with no options.
func DefaultFetcher() Fetcher {
	return defaultFetcher
}

// NewFetcher produces a Fetcher from a set of configuration options.
func NewFetcher(options ...FetcherOption) (Fetcher, error) {
	var (
		err error

		f = &fetcher{
			loader: DefaultLoader(),
			parser: DefaultParser(),
		}
	)

	for _, o := range options {
		err = multierr.Append(err, o.applyToFetcher(f))
	}

	return f, err
}

// fetcher is the internal Fetcher implementation.
type fetcher struct {
	loader Loader
	parser Parser
}

func (f *fetcher) Fetch(ctx context.Context, location string, prev ContentMeta) (keys []Key, next ContentMeta, err error) {
	var data []byte
	data, next, err = f.loader.LoadContent(ctx, location, prev)

	if err == nil {
		keys, err = f.parser.Parse(next.Format, data)
	}

	return
}
