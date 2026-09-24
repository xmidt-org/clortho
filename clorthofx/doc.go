// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package clorthofx provides integration with go.uber.org/fx.
//
// Provide builds a *clortho.Provider from the application's clortho.Config,
// binds it to the application lifecycle, and also provides it as a
// jws.KeyProvider for a bascule token parser.  An optional *zap.Logger and
// *touchstone.Factory enable logging and metrics for refreshes.  See Provide.
package clorthofx
