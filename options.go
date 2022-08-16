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
	"crypto"
	"fmt"
	"strings"

	"go.uber.org/multierr"
)

// InvalidFormatError indicates that a format cannot be associated with a Parser
// because the format string is invalid.  For example, format strings that contain
// semi-colons (;) are invalid because matching a Parser by MIME parameters is
// not supported.
type InvalidFormatError struct {
	Format string
}

// Error satisfies the error interface.
func (ife InvalidFormatError) Error() string {
	return fmt.Sprintf(
		"Cannot register invalid format [%s]",
		ife.Format,
	)
}

// LoaderOption represents a configurable option for building a Loader.
type LoaderOption interface {
	applyToLoaders(*loaders) error
}

type loaderOptionFunc func(*loaders) error

func (lof loaderOptionFunc) applyToLoaders(ls *loaders) error { return lof(ls) }

// WithSchemes registers a loader as handling one or more URI schemes.  Use this
// to add custom schemes or to override one of the schemes a loader handles by default.
//
// By default, a Loader created with NewLoader handles the file, http, and https schemes,
// as well as file paths without a scheme.
func WithSchemes(l Loader, schemes ...string) LoaderOption {
	return loaderOptionFunc(func(ls *loaders) error {
		for _, s := range schemes {
			ls.l[s] = l
		}

		return nil
	})
}

// ParserOption allows tailoring of the Parser returned by NewParser.
type ParserOption interface {
	applyToParsers(*parsers) error
}

type parserOptionFunc func(*parsers) error

func (pof parserOptionFunc) applyToParsers(ps *parsers) error { return pof(ps) }

// WithFormats associates a Parsers with one or more formats.  Each format is an opaque
// string simply used as a way to look up a parsing algorithm.  Typically, a format is a
// file suffix (including the leading '.') or a media type such as application/json.
func WithFormats(p Parser, formats ...string) ParserOption {
	return parserOptionFunc(func(ps *parsers) (err error) {
		for _, f := range formats {
			if strings.IndexByte(f, ';') >= 0 {
				err = multierr.Append(
					err,
					InvalidFormatError{
						Format: f,
					},
				)

				continue
			}

			ps.p[f] = p
		}

		return
	})
}

// FetcherOption is a configuration option passed to NewFetcher.
type FetcherOption interface {
	applyToFetcher(*fetcher) error
}

type fetcherOptionFunc func(*fetcher) error

func (fof fetcherOptionFunc) applyToFetcher(f *fetcher) error {
	return fof(f)
}

// WithLoader defines the Loader strategy for a Fetcher.  By default,
// a Fetcher uses a Loader created with no options.
func WithLoader(l Loader) FetcherOption {
	return fetcherOptionFunc(func(f *fetcher) error {
		f.loader = l
		return nil
	})
}

// WithParser defines the Parser strategy for a Fetcher.  By default,
// a Fetcher uses a Parser created with no options.
func WithParser(p Parser) FetcherOption {
	return fetcherOptionFunc(func(f *fetcher) error {
		f.parser = p
		return nil
	})
}

// WithKeyIDHash sets the cryptographic hash used to generate key IDs for keys
// which do not have them.  By default, crypto.SHA256 is used.
func WithKeyIDHash(h crypto.Hash) FetcherOption {
	return fetcherOptionFunc(func(f *fetcher) error {
		f.keyIDHash = h
		return nil
	})
}

// ResolverOption represents a configurable option passed to NewResolver.
type ResolverOption interface {
	applyToResolver(*resolver) error
}

type resolverOptionFunc func(*resolver) error

func (rof resolverOptionFunc) applyToResolver(r *resolver) error {
	return rof(r)
}

// WithKeyIDExpander establishes the Expander strategy used for resolving
// individual keys.  Callers may use this option to associate a custom
// Expander with a Resolver.
func WithKeyIDExpander(e Expander) ResolverOption {
	return resolverOptionFunc(func(r *resolver) error {
		r.keyIDExpander = e
		return nil
	})
}

// WithKeyIDTemplate establishes the URI template used for resolving
// individual keys.
func WithKeyIDTemplate(t string) ResolverOption {
	return resolverOptionFunc(func(r *resolver) error {
		e, err := NewExpander(t)
		if err == nil {
			err = WithKeyIDExpander(e).applyToResolver(r)
		}

		return err
	})
}

// WithKeyRing sets a KeyRing to act as a cache for the Resolver.
// By default, a Resolver is not associated with any KeyRing.
func WithKeyRing(kr KeyRing) ResolverOption {
	return resolverOptionFunc(func(r *resolver) error {
		r.keyRing = kr
		return nil
	})
}

// RefresherOption is a configurable option passed to NewRefresher.
type RefresherOption interface {
	applyToRefresher(*refresher) error
}

type refresherOptionFunc func(*refresher) error

func (rof refresherOptionFunc) applyToRefresher(r *refresher) error {
	return rof(r)
}

// WithSources associates external sources of keys with a Refresher.
// This option is cumulative:  all sources from each call to WithSources
// will be added to the configured Refresher.
func WithSources(sources ...RefreshSource) RefresherOption {
	return refresherOptionFunc(func(r *refresher) error {
		r.sources = append(r.sources, sources...)
		return nil
	})
}

// ResolverRefresherOption is a configurable option that applies to both
// a Refresher and a Resolver.
type ResolverRefresherOption interface {
	ResolverOption
	RefresherOption
}

type setFetcherOption struct {
	f Fetcher
}

func (sfo setFetcherOption) applyToRefresher(r *refresher) error {
	r.fetcher = sfo.f
	return nil
}

func (sfo setFetcherOption) applyToResolver(r *resolver) error {
	r.fetcher = sfo.f
	return nil
}

// WithFetcher configures the Fetcher instance used by either a Resolver
// or a Refresher.  By default, DefaultFetcher() is used.
func WithFetcher(f Fetcher) ResolverRefresherOption {
	return setFetcherOption{
		f: f,
	}
}

type configOption struct {
	cfg Config
}

func (co configOption) applyToRefresher(r *refresher) error {
	return WithSources(co.cfg.Refresh.Sources...).applyToRefresher(r)
}

func (co configOption) applyToResolver(r *resolver) error {
	return WithKeyIDTemplate(co.cfg.Resolve.Template).applyToResolver(r)
}

// WithConfig uses a Config struct to configure a Refresher and/or Resolver.
func WithConfig(cfg Config) ResolverRefresherOption {
	return configOption{
		cfg: cfg,
	}
}
