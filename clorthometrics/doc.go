// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package clorthometrics tallies clortho refresh events as Prometheus metrics.
//
// A Listener records, for each source, how many refreshes ran, how many
// failed and why, how many keys the source supplies, and the size of the key
// set those keys came from.
package clorthometrics
