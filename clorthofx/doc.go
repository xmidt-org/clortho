// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package clorthofx provides integration with go.uber.org/fx.
//
// Provide supplies the components of a verification path from a single
// clortho.Config: a clortho.KeyRing, the clortho.Refresher that fills it and is
// bound to the application lifecycle, a jws.KeyProvider that verifies against
// it, and a clortho.Resolver for on-demand lookups.  See Provide for the full
// list and for what each component requires.
//
// An optional clortho.Parser and clortho.Loader can be provided to tailor how
// key material is loaded and parsed, and an optional *zap.Logger and
// *touchstone.Factory enable logging and metrics for refresh and resolve
// events.
package clorthofx
