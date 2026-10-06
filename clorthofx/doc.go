// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package clorthofx provides integration with go.uber.org/fx.
//
// Provide builds every provider the application's Config asks for, of any of
// the three kinds clortho makes, and presents them to the application as one
// jws.KeyProvider for a bascule token parser.  It binds each KeySetProvider
// to the application lifecycle.  An optional *zap.Logger and
// *touchstone.Factory enable logging and metrics.  See Provide.
package clorthofx
