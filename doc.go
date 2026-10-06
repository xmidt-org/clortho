// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package clortho supplies the keys a service needs to verify JWS signatures,
// such as those on JWTs, as a jws.KeyProvider for github.com/lestrrat-go/jwx/v4.
//
// It makes three kinds of provider, for three ways a service can come by its
// keys.
//
// A KeySetProvider is for a server that publishes its keys as a set.  It
// polls each configured source for its complete key set, a JWK set or a single
// JWK, keeps the keys in one map by key ID, and answers jwx's FetchKeys from
// that map.  It never fetches a key on demand, so a token cannot cause it to
// contact anything; see KeySetConfig.RefreshOnUnknownKeyID for the one opt-in
// exception, which is rate-limited.
//
// A PerKeyProvider is for a server that serves one key per request and no key
// set, as themis does.  It fetches a key when a token names it, and then holds
// it.  The key ID it asks for comes from a token nobody has verified yet, so
// a token can make it send a request.  PerKeyConfig bounds what that can cost,
// and a service that can list its key IDs should.
//
// A FixedKeyProvider is for keys written into the service's own
// configuration, as PEM or as JWKs.  It never sends a request at all.
//
// Prefer a KeySetProvider wherever the server offers a key set.  A service
// that needs several providers, of any kind, passes each one to jwx, which
// asks them in the order given.  The package example shows all three kinds
// used together.
//
// # Configuration
//
// Each kind is configured by a plain struct with no options and no struct
// tags: KeySetConfig, PerKeyConfig, and FixedKeyConfig.  A service unmarshals
// its own settings and maps them onto one of these.  For the two kinds that
// reach a server, it also hands over the *http.Client to reach it with.  That
// client is required, and clortho uses it exactly as given; the example on
// NewKeySetProvider shows one suited to fetching keys.
//
//	p, err := clortho.NewKeySetProvider(clortho.KeySetConfig{
//		Sources: []clortho.RefreshSource{{
//			URI:    "https://issuer.example.com/keys",
//			Client: client,
//		}},
//	})
//	if err != nil {
//		return err
//	}
//
//	p.AddListener(zapListener)
//	if err := p.Start(ctx); err != nil {
//		return err
//	}
//	defer p.Stop(ctx)
//
//	parser, err := basculejwt.NewTokenParser(jwt.WithKeyProvider(p))
//
// # A KeySetProvider in service
//
// Start returns once the refresh loops are running; it does not wait for the
// first fetch.  Status reports each source's last outcome, so a readiness
// check can decide when the KeySetProvider has keys.  On a refresh failure the
// last good keys keep serving; Status exposes their age.  A failed refresh is
// retried well before the next scheduled one, and when a server asks for a
// pause with Retry-After that is the wait used; see RefreshSource.
//
// Every key a source serves must carry a kid.  A key ID served by two sources
// is an error, not a merge: a KeySetProvider is one map, and a deployment
// that needs separate key spaces builds separate KeySetProviders.
//
// # A PerKeyProvider in service
//
// A PerKeyProvider has nothing to start or stop, and holds no keys until a
// token asks, so it has no readiness to report.  The first token that names a
// key waits for that key to be fetched.  A key ID the operator listed in
// PerKeyConfig.AllowedKeyIDs may always be fetched; any other is fetched no
// more often than PerKeyConfig.FetchRateLimit allows, so that a flood of
// invented key IDs cannot become a flood of requests to the key server.  A
// key whose time is up keeps serving while the server cannot be reached, and
// is dropped as soon as the server says it is gone.
//
// # A FixedKeyProvider in service
//
// A FixedKeyProvider is complete as soon as it is built.  It has nothing to
// start, stop, or watch, and what it holds changes only when the service's
// configuration does.  Every key is given its key ID in the configuration,
// since a PEM has nowhere to carry one.
//
// # Every provider
//
// No key may be symmetric, and a private key is reduced to its public half.
// By default a key's "use" must be "sig" and its "alg", when present, must
// match the token; VerifyConfig turns either check off.
//
// Errors carry sentinels for errors.Is.  clorthozap and clorthometrics log and
// count what the two kinds of provider that reach a server do.  clorthofx
// builds any number of providers of every kind for a go.uber.org/fx
// application, and presents them to it as one.
package clortho
