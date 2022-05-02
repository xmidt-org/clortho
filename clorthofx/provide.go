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

type ZapIn struct {
	fx.In
	Logger *zap.Logger `optional:"true"`
}

func newZapListener(in ZapIn) (*clorthozap.Listener, error) {
	if in.Logger != nil {
		return clorthozap.NewListener(
			clorthozap.WithLogger(in.Logger),
		)
	}

	return nil, nil
}

type MetricsIn struct {
	fx.In
	Factory *touchstone.Factory `optional:"true"`
}

func newMetricsListener(in MetricsIn) (*clorthometrics.Listener, error) {
	if in.Factory != nil {
		// TODO
	}

	return nil, nil
}

type RefresherIn struct {
	fx.In

	Fetcher         clortho.Fetcher
	Config          clortho.Config           `optional:"true"`
	ZapListener     *clorthozap.Listener     `optional:"true"`
	MetricsListener *clorthometrics.Listener `optional:"true"`
}

func newRefresher(in RefresherIn, l fx.Lifecycle) (r clortho.Refresher, err error) {
	r, err = clortho.NewRefresher(
		clortho.WithFetcher(in.Fetcher),
		clortho.WithSources(in.Config.Refresh.Sources...),
	)

	if err == nil {
		if in.ZapListener != nil {
			r.AddListener(in.ZapListener)
		}

		if in.MetricsListener != nil {
			r.AddListener(in.MetricsListener)
		}

		l.Append(fx.Hook{
			OnStart: r.Start,
			OnStop:  r.Stop,
		})
	}

	return
}

type ResolverIn RefresherIn

func newResolver(in ResolverIn) (r clortho.Resolver, err error) {
	r, err = clortho.NewResolver(
		clortho.WithFetcher(in.Fetcher),
		clortho.WithKeyIDTemplate(in.Config.Resolve.Template), // TODO make this optional?
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

func Provide() fx.Option {
	return fx.Module(
		Module,
		fx.Options(
			fx.Provide(
				newFetcher,
				newZapListener,
				newMetricsListener,
				newRefresher,
				newResolver,
			),
		),
	)
}
