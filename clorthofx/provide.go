// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthofx

import (
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/xmidt-org/clortho"
	"github.com/xmidt-org/clortho/clorthometrics"
	"github.com/xmidt-org/clortho/clorthozap"
	"github.com/xmidt-org/touchstone"
	"go.uber.org/fx"
	"go.uber.org/zap"
)

// Module is the name of the go.uber.org/fx module this package
// uses for its components.
const Module = "clortho"

// newKeyRing creates the key ring component.  This is in a separate function
// to make debugging easier, as it will show up in fx's logs.
func newKeyRing() clortho.KeyRing {
	return clortho.NewKeyRing()
}

// newFetcher takes the set of injected components and produces a clortho.Fetcher.
func newFetcher(opts ...clortho.FetcherOption) clortho.Fetcher {

	return clortho.NewFetcher(opts...)
}

// ZapIn holds the set of dependencies for creating a *clorthozap.Listener.
type ZapIn struct {
	fx.In

	Logger *zap.Logger `optional:"true"`
}

func decorateLogger(in ZapIn) (l *zap.Logger) {
	if in.Logger != nil {
		l = in.Logger.Named(Module)
	}

	return
}

func newZapListener(in ZapIn) (l *clorthozap.Listener, err error) {
	if in.Logger != nil {
		l, err = clorthozap.NewListener(
			clorthozap.WithLogger(in.Logger),
		)
	}

	return
}

// MetricsIn holds the set of dependencies for creating a *clorthometrics.Listener.
type MetricsIn struct {
	fx.In

	Factory *touchstone.Factory `optional:"true"`
}

func newMetricsListener(in MetricsIn) (l *clorthometrics.Listener, err error) {
	if in.Factory != nil {
		l, err = clorthometrics.NewListener(
			clorthometrics.WithFactory(in.Factory),
		)
	}

	return
}

// RefresherIn enumerates the set of components involved in the creation
// of a clortho.Refresher.
type RefresherIn struct {
	fx.In

	// KeyRing is the key ring to refresh.  This will be either supplied from the
	// enclosing application or internally created within this module.
	KeyRing clortho.KeyRing

	Fetcher         clortho.Fetcher
	Config          clortho.Config           `optional:"true"`
	ZapListener     *clorthozap.Listener     `optional:"true"`
	MetricsListener *clorthometrics.Listener `optional:"true"`

	Lifecycle fx.Lifecycle
}

func newRefresher(in RefresherIn) (r clortho.Refresher, err error) {
	r, err = clortho.NewRefresher(
		clortho.WithFetcher(in.Fetcher),
		clortho.WithConfig(in.Config),
	)

	if err == nil {
		if in.ZapListener != nil {
			r.AddListener(in.ZapListener)
		}

		if in.MetricsListener != nil {
			r.AddListener(in.MetricsListener)
		}

		r.AddListener(in.KeyRing)
		in.Lifecycle.Append(fx.Hook{
			OnStart: r.Start,
			OnStop:  r.Stop,
		})
	}

	return
}

// ResolverIn enumerates the set of components involved in the creation
// of a clortho.Resolver.
type ResolverIn RefresherIn

func newResolver(in ResolverIn) (r clortho.Resolver, err error) {
	r, err = clortho.NewResolver(
		clortho.WithFetcher(in.Fetcher),
		clortho.WithKeyRing(in.KeyRing),
		clortho.WithConfig(in.Config),
	)

	if err == nil {
		if in.ZapListener != nil {
			r.AddListener(in.ZapListener)
		}

		if in.MetricsListener != nil {
			r.AddListener(in.MetricsListener)
		}
	}

	return
}

// KeyProviderIn enumerates the set of components involved in the creation
// of a jws.KeyProvider.
type KeyProviderIn struct {
	fx.In

	// KeyRing is the ring the provider verifies against.  This is the same ring
	// the Refresher fills.
	KeyRing clortho.KeyRing

	// Config, when present and non-empty, is checked for at least one refresh
	// source.  The provider does not otherwise read it.
	Config clortho.Config `optional:"true"`
}

// isZeroConfig reports whether cfg has nothing set at all.  An application with
// no Config feeds the ring itself, so there is nothing to validate.
func isZeroConfig(cfg clortho.Config) bool {
	return len(cfg.Refresh.Sources) == 0 && cfg.Resolve == (clortho.ResolveConfig{})
}

// newKeyProvider creates the jws.KeyProvider component.  When a Config was
// supplied, it is passed along so that NewKeyProvider rejects a configuration
// with no refresh sources at startup, rather than leaving a ring that never fills.
func newKeyProvider(in KeyProviderIn) (jws.KeyProvider, error) {
	opts := []clortho.KeyProviderOption{
		clortho.WithKeyRing(in.KeyRing),
	}

	if !isZeroConfig(in.Config) {
		opts = append(opts, clortho.WithConfig(in.Config))
	}

	return clortho.NewKeyProvider(opts...)
}

// newKeyAccessor just returns the key ring as is for now.
// Future versions may do some kind of decoration.
func newKeyAccessor(kr clortho.KeyRing) clortho.KeyAccessor {
	return kr
}

// Provide bootstraps the clortho module.
//
// If a clortho.KeyRing is present in the enclosing application, it will be used as the
// cache for the resolver and refresher.  Otherwise, an internal key ring is created and used.
//
// This module provides the following components:
//
//   - clortho.KeyRing
//     Available as a component itself, this is also used as the cache for the resolver and
//     is refreshed using the injected clortho.Config configuration.
//
//   - clortho.Fetcher
//     An optional clortho.Parser and clortho.Loader may be supplied to tailor this component.
//     If no parser or loader are supplied, the package defaults are used.
//
//   - clorthozap.Listener
//     This will be non-nil only if a *zap.Logger is supplied.  If non-nil, it will automatically
//     listen for refresh and resolve events.
//
//   - clorthometrics.Listener
//     This will be non-nil only if a *touchstone.Factory is supplied.  If non-nil, it will
//
//   - clortho.Refresher
//     The refresher will be bound to the application lifecycle.
//
//   - clortho.Resolver
//
//   - clortho.KeyAccessor
//     This is the same component as the key ring, but may be decorated in future versions.
//     Clients that only need read access to the key ring should use this component.
//
//   - jws.KeyProvider
//     Verifies JWS signatures against the key ring.  This is what a bascule token parser
//     needs.  If a non-empty clortho.Config is supplied, it must have at least one refresh
//     source, since the ring is filled only by the Refresher; a Config with only a resolve
//     template fails at startup with clortho.ErrNoRefreshSources.  Like every fx
//     constructor, this one runs only if something injects the provider.  An application
//     that provides its own jws.KeyProvider will get a duplicate-provide error from fx;
//     use fx.Decorate or a named value to combine the two.
func Provide() fx.Option {
	return fx.Module(
		Module,
		fx.Decorate(
			decorateLogger,
		),
		fx.Provide(
			newKeyRing,
			newFetcher,
			newZapListener,
			newMetricsListener,
			newRefresher,
			newResolver,
			newKeyAccessor,
			newKeyProvider,
		),
		fx.Invoke(
			// eagerly load the refresher so that it's background
			// goroutine(s) start
			func(clortho.Refresher) {},
		),
	)
}
