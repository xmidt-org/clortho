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

import "github.com/xmidt-org/chronon"

// LoaderOption represents a configurable option for building a Loader.
type LoaderOption interface {
	applyToLoaders(*loaders) error
}

type loaderOptionFunc func(*loaders) error

func (lof loaderOptionFunc) applyToLoaders(ls *loaders) error { return lof(ls) }

// WithSchemes registers a loader as handling one or more URI schemes.  Use this
// to add custom schemes or to override one of the schemes a loader handles by default.
//
// By default, a Loader handles the file, http, and https schemes.
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

// WithFormats associates a Parsers with one or more formats.  Each format must be either
// a media type ("application/json") or a file suffix with leading period (".json").
func WithFormats(p Parser, formats ...string) ParserOption {
	return parserOptionFunc(func(ps *parsers) error {
		for _, f := range formats {
			ps.p[f] = p
		}

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

// RefresherOption is a configurable option passed to NewRefresher.
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

type setLoaderOption struct {
	l Loader
}

func (slo setLoaderOption) applyToRefresher(r *refresher) error {
	r.loader = slo.l
	return nil
}

func (slo setLoaderOption) applyToResolver(r *resolver) error {
	r.loader = slo.l
	return nil
}

// WithLoader is used to establish the Loader instance used by either
// a Resolver or Refresher.
func WithLoader(l Loader) ResolverRefresherOption {
	return setLoaderOption{
		l: l,
	}
}

type setParserOption struct {
	p Parser
}

func (spo setParserOption) applyToRefresher(r *refresher) error {
	r.parser = spo.p
	return nil
}

func (spo setParserOption) applyToResolver(r *resolver) error {
	r.parser = spo.p
	return nil
}

// WithParser establishes the Parser instance used by either a Resolver
// or Refresher.
func WithParser(p Parser) ResolverRefresherOption {
	return setParserOption{
		p: p,
	}
}
