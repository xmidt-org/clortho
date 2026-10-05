// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package clortho supplies the keys a service needs to verify JWS signatures,
// such as those on JWTs, as a jws.KeyProvider for github.com/lestrrat-go/jwx/v4.
//
// A KeySetProvider is the one thing this package makes.  It polls each
// configured source for its complete key set, a JWK set or a single JWK, keeps
// the keys in one map by key ID, and answers jwx's FetchKeys from that map.
// It never fetches a key on demand, so a token cannot cause the KeySetProvider
// to contact anything; see KeySetConfig.RefreshOnUnknownKeyID for the one
// opt-in exception, which is rate-limited.
//
// Configuration is a plain KeySetConfig struct with no options and no struct
// tags.  A service unmarshals its own settings, maps them onto a KeySetConfig,
// and hands each http or https source the *http.Client to reach it with.  That
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
// Start returns once the refresh loops are running; it does not wait for the
// first fetch.  Status reports each source's last outcome, so a readiness
// check can decide when the KeySetProvider has keys.  On a refresh failure the
// last good keys keep serving; Status exposes their age.  A failed refresh is
// retried well before the next scheduled one, and when a server asks for a
// pause with Retry-After that is the wait used; see RefreshSource.
//
// Every key a source serves must carry a kid, and none may be symmetric.  A
// key ID served by two sources is an error, not a merge: a KeySetProvider is
// one map, and a deployment that needs separate key spaces builds separate
// Providers.  By default a key's "use" must be "sig" and its "alg", when
// present, must match the token; VerifyConfig turns either check off.
//
// Errors carry sentinels for errors.Is.  clorthozap and clorthometrics
// implement Listener for logging and metrics, and clorthofx wires a
// KeySetProvider into a go.uber.org/fx application.
package clortho
