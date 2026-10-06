// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthofx

import (
	"errors"
	"fmt"

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

// ErrNoProviders is returned when the Config asks for no providers at all.
// Such an application could not verify any token, so it fails at startup
// rather than at the first request.
var ErrNoProviders = errors.New("the clorthofx.Config asks for no providers")

// Config says which providers an application wants.  It holds one list for
// each kind of provider, and builds one provider for each entry.  Any list
// may be empty, but not all three.
//
// Like the configs it holds, it is a plain struct with no struct tags.  The
// application unmarshals its own settings and maps them onto this, which is
// also where it hands over each *http.Client.
type Config struct {
	// KeySets are the configs of the KeySetProviders to build.  One
	// KeySetProvider can already read several sources, so more than one is
	// needed only to keep key spaces apart.
	KeySets []clortho.KeySetConfig

	// PerKeys are the configs of the PerKeyProviders to build, one for each
	// server that serves single keys.
	PerKeys []clortho.PerKeyConfig

	// Fixed are the configs of the FixedKeyProviders to build.
	Fixed []clortho.FixedKeyConfig
}

// ProvidersIn enumerates the components involved in building the providers.
type ProvidersIn struct {
	fx.In

	// Config is required.
	Config Config

	// Logger, when present, receives a log entry for every refresh and every
	// fetch, through a clorthozap.Listener.
	Logger *zap.Logger `optional:"true"`

	// Factory, when present, receives the metrics for refreshes and fetches,
	// through a clorthometrics.Listener.
	Factory *touchstone.Factory `optional:"true"`

	Lifecycle fx.Lifecycle
}

// ProvidersOut enumerates what this module provides.
type ProvidersOut struct {
	fx.Out

	// KeyProvider is every provider the Config asked for, presented as one.
	// It is what a basculejwt token parser takes via jwt.WithKeyProvider.
	KeyProvider jws.KeyProvider

	// KeySets, PerKeys, and Fixed are the providers themselves, each list in
	// the order of its configs, for what the combined KeyProvider does not
	// offer: Status and KeyIDs for a health endpoint, for example.  A list is
	// empty when the Config asked for none of that kind.
	KeySets []*clortho.KeySetProvider
	PerKeys []*clortho.PerKeyProvider
	Fixed   []*clortho.FixedKeyProvider
}

// newProviders builds every provider the Config asks for, attaches the
// optional listeners, binds what has a lifecycle to the application's, and
// presents them all as one jws.KeyProvider.
func newProviders(in ProvidersIn) (ProvidersOut, error) {
	out, err := build(in.Config)
	if err != nil {
		return ProvidersOut{}, err
	}

	// one listener of each sort serves every provider.  the metrics listener
	// in particular registers its metrics once, and labels them by source.
	if in.Logger != nil {
		l, err := clorthozap.NewListener(clorthozap.WithLogger(in.Logger.Named(Module)))
		if err != nil {
			return ProvidersOut{}, err
		}

		out.listen(l, l)
	}

	if in.Factory != nil {
		l, err := clorthometrics.NewListener(clorthometrics.WithFactory(in.Factory))
		if err != nil {
			return ProvidersOut{}, err
		}

		out.listen(l, l)
	}

	// only a KeySetProvider has anything to start and stop
	for _, p := range out.KeySets {
		in.Lifecycle.Append(fx.Hook{
			OnStart: p.Start,
			OnStop:  p.Stop,
		})
	}

	out.KeyProvider = out.combine()
	return out, nil
}

// build makes one provider for each config.  Every config that cannot be used
// is reported, each naming its kind and its place in the list.
func build(cfg Config) (ProvidersOut, error) {
	if len(cfg.KeySets)+len(cfg.PerKeys)+len(cfg.Fixed) == 0 {
		return ProvidersOut{}, ErrNoProviders
	}

	var (
		out  ProvidersOut
		errs []error
	)

	for i, c := range cfg.Fixed {
		p, err := clortho.NewFixedKeyProvider(c)
		if err != nil {
			errs = append(errs, fmt.Errorf("fixed key provider %d: %w", i, err))
			continue
		}

		out.Fixed = append(out.Fixed, p)
	}

	for i, c := range cfg.KeySets {
		p, err := clortho.NewKeySetProvider(c)
		if err != nil {
			errs = append(errs, fmt.Errorf("key set provider %d: %w", i, err))
			continue
		}

		out.KeySets = append(out.KeySets, p)
	}

	for i, c := range cfg.PerKeys {
		p, err := clortho.NewPerKeyProvider(c)
		if err != nil {
			errs = append(errs, fmt.Errorf("per-key provider %d: %w", i, err))
			continue
		}

		out.PerKeys = append(out.PerKeys, p)
	}

	if err := errors.Join(errs...); err != nil {
		return ProvidersOut{}, err
	}

	return out, nil
}

// listen attaches a listener for refreshes to every KeySetProvider, and one
// for fetches to every PerKeyProvider.  A FixedKeyProvider does nothing to
// listen to.
func (out *ProvidersOut) listen(refreshes clortho.Listener, fetches clortho.FetchListener) {
	for _, p := range out.KeySets {
		p.AddListener(refreshes)
	}

	for _, p := range out.PerKeys {
		p.AddListener(fetches)
	}
}

// combine presents every provider as one, in the order they are to be asked:
// fixed keys, then key sets, then per-key.  A PerKeyProvider is the only kind
// a token can make send a request, so it is asked last, and only for a key
// nothing before it holds.
func (out *ProvidersOut) combine() jws.KeyProvider {
	all := make(combined, 0, len(out.Fixed)+len(out.KeySets)+len(out.PerKeys))
	for _, p := range out.Fixed {
		all = append(all, p)
	}

	for _, p := range out.KeySets {
		all = append(all, p)
	}

	for _, p := range out.PerKeys {
		all = append(all, p)
	}

	return all
}

// Provide bootstraps the clortho module.  The application must supply a
// Config; an optional *zap.Logger and *touchstone.Factory enable logging and
// metrics.
//
// This module provides:
//
//   - jws.KeyProvider
//     Every provider the Config asked for, presented as one, under the
//     interface a basculejwt token parser takes via jwt.WithKeyProvider.  It
//     asks the providers in a fixed order and stops at the first that offers
//     a key: fixed keys, then key sets, then per-key.  A key ID should
//     therefore be served by one provider only.  An application that provides
//     its own jws.KeyProvider will get a duplicate-provide error from fx; use
//     fx.Decorate or a named value to combine the two.
//
//   - []*clortho.KeySetProvider, []*clortho.PerKeyProvider, and
//     []*clortho.FixedKeyProvider
//     The providers themselves, each list in the order of its configs.
//     Inject one for Status and KeyIDs, e.g. from a health endpoint.  Each
//     KeySetProvider is bound to the application lifecycle, so its sources
//     are refreshed from Start until Stop.
//
// The providers are constructed eagerly, so a Config problem fails the
// application at startup rather than when a token first arrives.  Every
// problem is reported, each naming the provider it is about.
func Provide() fx.Option {
	return fx.Module(
		Module,
		fx.Provide(
			newProviders,
		),
		fx.Invoke(
			func(jws.KeyProvider) {},
		),
	)
}
