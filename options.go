// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

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
	applyToFetcher(*fetcher)
}

type fetcherOptionFunc func(*fetcher)

func (fof fetcherOptionFunc) applyToFetcher(f *fetcher) {
	fof(f)
}

// WithLoader defines the Loader strategy for a Fetcher.  By default,
// a Fetcher uses a Loader created with no options.
func WithLoader(l Loader) FetcherOption {
	return fetcherOptionFunc(func(f *fetcher) {
		f.loader = l
	})
}

// WithParser defines the Parser strategy for a Fetcher.  By default,
// a Fetcher uses a Parser created with no options.
func WithParser(p Parser) FetcherOption {
	return fetcherOptionFunc(func(f *fetcher) {
		f.parser = p
	})
}

// WithKeyIDHash sets the cryptographic hash used to generate key IDs for keys
// which do not have them.  By default, crypto.SHA256 is used.
func WithKeyIDHash(h crypto.Hash) FetcherOption {
	return fetcherOptionFunc(func(f *fetcher) {
		f.keyIDHash = h
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
// individual keys.  An empty template yields a ring-only Resolver whose
// misses report ErrNoTemplate; see NewResolver.
func WithKeyIDTemplate(t string) ResolverOption {
	return resolverOptionFunc(func(r *resolver) error {
		if len(t) == 0 {
			return WithKeyIDExpander(noTemplateExpander{}).applyToResolver(r)
		}

		e, err := NewExpander(t)
		if err == nil {
			err = WithKeyIDExpander(e).applyToResolver(r)
		}

		return err
	})
}

// KeyRingOption is the return type of WithKeyRing, and nothing more.  It is an
// interface embedding both option types so that the one value can be passed to
// NewResolver or NewKeyProvider; see ConfigOption for the same pattern.
type KeyRingOption interface {
	ResolverOption
	KeyProviderOption
}

type keyRingOption struct {
	kr KeyRing
}

func (kro keyRingOption) applyToResolver(r *resolver) error {
	r.keyRing = kro.kr
	return nil
}

func (kro keyRingOption) apply(kp *keyProvider) error {
	kp.keyRing = kro.kr
	return nil
}

// WithKeyRing associates a KeyRing with a Resolver or a jws.KeyProvider.
//
// For a Resolver, the ring acts as a cache: keys found on it are returned
// without a fetch, and fetched keys are added to it.  By default, a Resolver
// has no ring.
//
// For a jws.KeyProvider, the ring is the only source of keys, and is required.
func WithKeyRing(kr KeyRing) KeyRingOption {
	return keyRingOption{
		kr: kr,
	}
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

// ConfigOption is the return type of WithConfig, and nothing more.  Each
// constructor takes its own option interface, and Go has no way to say "accepted
// by all three" except an interface that embeds all three.  This is the same
// pattern as ResolverRefresherOption, widened to include NewKeyProvider.
// Callers never implement, name, or call methods on it; they pass the value
// straight to a constructor.
type ConfigOption interface {
	ResolverOption
	RefresherOption
	KeyProviderOption
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

// apply validates that the Config can feed the provider's ring.  The provider
// never reads the Config otherwise: keys come from the ring, which a Refresher
// fills from Refresh.Sources.  With no sources the ring stays empty and every
// token fails with "key not found", so reject that at construction.
func (co configOption) apply(*keyProvider) error {
	if len(co.cfg.Refresh.Sources) == 0 {
		return ErrNoRefreshSources
	}

	return nil
}

// WithConfig uses a Config struct to configure a Resolver, a Refresher, or a
// jws.KeyProvider.
//
// For a Resolver, Config.Resolve supplies the key ID template.  For a Refresher,
// Config.Refresh supplies the sources.  For a jws.KeyProvider, the Config is not
// used to fetch anything; NewKeyProvider only checks that Config.Refresh has at
// least one source, and returns ErrNoRefreshSources otherwise.  Supply it there
// so that a deployment configured with only a resolve template fails at startup
// instead of rejecting every token.
func WithConfig(cfg Config) ConfigOption {
	return configOption{
		cfg: cfg,
	}
}

// KeyProviderOption represents a configurable option for building a jws.KeyProvider.
type KeyProviderOption interface {
	apply(*keyProvider) error
}

type keyProviderOptionFunc func(*keyProvider) error

func (kpof keyProviderOptionFunc) apply(kp *keyProvider) error { return kpof(kp) }

// WithRingKey associates a KeyRing with a jws.KeyProvider.
//
// Deprecated: the name is backwards; it takes a KeyRing.  Use WithKeyRing, which
// accepts the same argument and is also a ResolverOption.  This alias will be
// removed in a future release.
func WithRingKey(kr KeyRing) KeyProviderOption {
	return WithKeyRing(kr)
}
