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

package clorthofx

import (
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

// FetcherIn specifies the components that the clortho.Fetcher component depends upon.
type FetcherIn struct {
	fx.In

	// FetcherOptions is the optional slice of options used to create the clortho.Fetcher.
	FetcherOptions []clortho.FetcherOption `optional:"true"`

	// Parser is the optional clortho.Parser used to tailor how key material is parsed.
	// This will override any parser described in FetcherOptions.
	//
	// If no parser is injected, the clortho.Fetcher component will use a default
	// parser created via clortho.NewParser().
	Parser clortho.Parser `optional:"true"`

	// Loader is the optional clortho.Loader used to tailor how key material is loaded.
	// This will override any loader described in FetcherOptions.
	//
	// If no loader is injected, the clortho.Fetcher component will use a default
	// loader created via clortho.NewLoader().
	Loader clortho.Loader `optional:"true"`
}

// newFetcher takes the set of injected components and produces a clortho.Fetcher.
func newFetcher(in FetcherIn) (clortho.Fetcher, error) {
	options := append(
		[]clortho.FetcherOption{},
		in.FetcherOptions...,
	)

	if in.Parser != nil {
		options = append(options, clortho.WithParser(in.Parser))
	}

	if in.Loader != nil {
		options = append(options, clortho.WithParser(in.Parser))
	}

	return clortho.NewFetcher(options...)
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

	Fetcher         clortho.Fetcher
	KeyRing         clortho.KeyRing          `optional:"true"`
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

		if in.KeyRing != nil {
			r.AddListener(in.KeyRing)
		}

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

// KeyRingIn enumerates the set of components required to create the application's
// KeyRing.
type KeyRingIn struct {
	fx.In

	InitialKeys []clortho.Key `optional:"true"`
	Refresher   clortho.Refresher
}

func newKeyRing(in KeyRingIn) (kr clortho.KeyRing) {
	kr = clortho.NewKeyRing(in.InitialKeys...)
	in.Refresher.AddListener(kr)

	return
}

// newKeyAccessor just returns the key ring as is for now.
// Future versions may do some kind of decoration.
func newKeyAccessor(kr clortho.KeyRing) clortho.KeyAccessor {
	return kr
}

// Provide bootstraps the clortho module.  This module provides the following
// components:
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
//   - clortho.KeyRing
//
//   - clortho.KeyAccessor
//     This is the same component as the key ring, but may be decorated in future versions.
//     Clients that only need read access to the key ring should use this component.
//
// If any of the above components are not referred to, they will not be created as per
// the usual go.uber.org/fx behavior.
func Provide() fx.Option {
	return fx.Module(
		Module,
		fx.Decorate(
			decorateLogger,
		),
		fx.Provide(
			newFetcher,
			newZapListener,
			newMetricsListener,
			newRefresher,
			newResolver,
			newKeyRing,
			newKeyAccessor,
		),
	)
}
