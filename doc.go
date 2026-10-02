// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package clortho supplies the keys a service needs to verify JWS signatures,
// such as those on JWTs, as a jws.KeyProvider for github.com/lestrrat-go/jwx/v4.
//
// A Provider is the one thing this package makes.  It polls each configured
// source for its complete key set, a JWK set or a single JWK, keeps the keys
// in one map by key ID, and answers jwx's FetchKeys from that map.  It never
// fetches a key on demand, so a token cannot cause the Provider to contact
// anything; see VerifyConfig.RefreshOnUnknownKeyID for the one opt-in
// exception, which is rate-limited.
//
// Configuration is a plain Config struct with no options and no struct tags.
// A service unmarshals its own settings, maps them onto a Config, and hands
// each source the *http.Client it wants:
//
//	p, err := clortho.New(clortho.Config{
//		Sources: []clortho.RefreshSource{{URI: "https://issuer.example.com/keys"}},
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
// check can decide when the Provider has keys.  On a refresh failure the last
// good keys keep serving; Status exposes their age.
//
// Every key a source serves must carry a kid, and none may be symmetric.  A
// key ID served by two sources is an error, not a merge: a Provider is one
// map, and a deployment that needs separate key spaces builds separate
// Providers.  By default a key's "use" must be "sig" and its "alg", when
// present, must match the token; VerifyConfig turns either check off.
//
// Errors carry sentinels for errors.Is.  clorthozap and clorthometrics
// implement Listener for logging and metrics, and clorthofx wires a Provider
// into a go.uber.org/fx application.
package clortho
