// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package clortho provides key management for clients.
//
// The two most important types in this package are the Resolver and the KeyRing.
// A KeyRing is essentially a local cache of keys, accessible via the key's kid (key ID)
// attribute.  A Resolver resolves keys by key ID from an external source, optionally
// using a KeyRing as a cache.
//
// A Refresher can be used to asynchronously update keys in one or more KeyRing instances
// or arbitrary client code that handles refresh events.
package clortho
