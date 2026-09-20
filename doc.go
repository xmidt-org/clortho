// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package clortho provides key management for clients, and in particular the
// keys needed to verify JWS signatures such as those on JWTs.
//
// The verification path is:
//
//   - A KeyRing holds keys, looked up by kid (key ID).
//   - A Refresher polls one or more sources, configured by Config.Refresh, on a
//     schedule and keeps the KeyRing current.
//   - NewKeyProvider wraps the KeyRing as a jws.KeyProvider for
//     github.com/lestrrat-go/jwx/v4, so that jws.Verify and jwt.Parse can find
//     the key named by a token's kid.
//
// The KeyRing is the only source of keys for verification.  The provider never
// fetches a key on demand, so an unverified token cannot cause an outbound
// request.  A deployment therefore needs at least one refresh source; passing
// WithConfig to NewKeyProvider makes a missing source a startup error.
//
// A Resolver is separate from that path.  It fetches individual keys by ID from a
// URI template, configured by Config.Resolve, optionally using a KeyRing as a
// cache.  It serves callers that need a specific key on demand and is not
// consulted during verification.
//
// Loaders and Parsers sit underneath both.  The default Loader handles http,
// https, and file URIs as well as plain file system paths, and the default
// Parser handles JWK, JWK sets, and PEM.  Both accept options for custom schemes
// and formats.
//
// NewKeyProvider, NewResolver, and NewRefresher return a nil value alongside a
// non-nil error.  Errors from the key provider carry sentinels such as
// ErrKeyProviderKeyNotFound, intended for errors.Is rather than message matching.
package clortho
