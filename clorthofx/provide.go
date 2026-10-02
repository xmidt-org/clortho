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

// ProviderIn enumerates the components involved in creating a
// *clortho.Provider.
type ProviderIn struct {
	fx.In

	// Config is required.  The application unmarshals its own settings and
	// maps them onto this, which is also where it hands each source the
	// *http.Client it wants.
	Config clortho.Config

	// Logger, when present, receives a log entry for every refresh through a
	// clorthozap.Listener.
	Logger *zap.Logger `optional:"true"`

	// Factory, when present, receives refresh metrics through a
	// clorthometrics.Listener.
	Factory *touchstone.Factory `optional:"true"`

	Lifecycle fx.Lifecycle
}

// newProvider creates the Provider, attaches the optional listeners, and
// binds Start and Stop to the application lifecycle.
func newProvider(in ProviderIn) (*clortho.Provider, error) {
	p, err := clortho.New(in.Config)
	if err != nil {
		return nil, err
	}

	if in.Logger != nil {
		l, err := clorthozap.NewListener(clorthozap.WithLogger(in.Logger.Named(Module)))
		if err != nil {
			return nil, err
		}

		p.AddListener(l)
	}

	if in.Factory != nil {
		l, err := clorthometrics.NewListener(clorthometrics.WithFactory(in.Factory))
		if err != nil {
			return nil, err
		}

		p.AddListener(l)
	}

	in.Lifecycle.Append(fx.Hook{
		OnStart: p.Start,
		OnStop:  p.Stop,
	})

	return p, nil
}

// newKeyProvider exposes the Provider under the interface a bascule token
// parser injects.
func newKeyProvider(p *clortho.Provider) jws.KeyProvider {
	return p
}

// Provide bootstraps the clortho module.  The application must supply a
// clortho.Config; an optional *zap.Logger and *touchstone.Factory enable
// logging and metrics for refreshes.
//
// This module provides:
//
//   - *clortho.Provider
//     Bound to the application lifecycle, so its sources are refreshed from
//     Start until Stop.  Inject it for Status and KeyIDs, e.g. from a health
//     endpoint.
//
//   - jws.KeyProvider
//     The same Provider, under the interface a basculejwt token parser takes
//     via jwt.WithKeyProvider.  An application that provides its own
//     jws.KeyProvider will get a duplicate-provide error from fx; use
//     fx.Decorate or a named value to combine the two.
//
// The Provider is constructed eagerly, so a Config problem fails the
// application at startup rather than when a token first arrives.
func Provide() fx.Option {
	return fx.Module(
		Module,
		fx.Provide(
			newProvider,
			newKeyProvider,
		),
		fx.Invoke(
			func(*clortho.Provider) {},
		),
	)
}
