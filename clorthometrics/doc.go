// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Package clorthometrics tallies what clortho's providers do as Prometheus
// metrics.
//
// For a KeySetProvider, a Listener records for each source how many refreshes
// ran, how many failed and why, how many keys the source supplies, and the
// size of the key set those keys came from.  For a PerKeyProvider, it records
// how many fetches of single keys ran, and how many failed and why.
package clorthometrics
