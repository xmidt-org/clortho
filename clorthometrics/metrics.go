// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthometrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xmidt-org/touchstone"
)

const (
	// MetricPrefix is prepended to all metrics exposed by this package.
	MetricPrefix = "keys_"

	// RefreshTotalName is the name of the counter for all refresh attempts,
	// both successful and unsuccessful, labeled by source.
	RefreshTotalName = MetricPrefix + "refresh_total"

	// RefreshTotalHelp is the help text for the refresh total metric.
	RefreshTotalHelp = "the total number of attempts to refresh keys, both successful and unsuccessful"

	// RefreshKeysName is the name of the gauge for the number of keys a
	// source currently supplies, labeled by source.
	RefreshKeysName = MetricPrefix + "refresh_keys"

	// RefreshKeysHelp is the help text for the refresh keys metric.
	RefreshKeysHelp = "the number of keys currently supplied by a source"

	// RefreshKeySetBytesName is the name of the gauge for the size, in bytes, of
	// the key set a source currently supplies, labeled by source.  A failed
	// refresh leaves it unchanged, so it reports what is being served from, not
	// what was last offered.
	RefreshKeySetBytesName = MetricPrefix + "refresh_key_set_bytes"

	// RefreshKeySetBytesHelp is the help text for the refresh key set bytes
	// metric.
	RefreshKeySetBytesHelp = "the size in bytes of the key set currently supplied by a source"

	// RefreshErrorTotalName is the name of the counter for key refreshes that
	// resulted in an error, labeled by source and by reason.
	RefreshErrorTotalName = MetricPrefix + "refresh_error_total"

	// RefreshErrorTotalHelp is the help text for the refresh error total metric.
	RefreshErrorTotalHelp = "the total number of failed attempts to refresh keys"

	// SourceLabel is the metric label carrying the source URI, with any
	// password redacted.
	SourceLabel = "source"

	// ReasonLabel is the label on the refresh error total that says why the
	// refresh failed.  Its value is always one of a fixed set:
	//
	//   - too_large: the body was larger than the source's MaxResponseBytes
	//   - symmetric_key: the key set held a symmetric key
	//   - missing_key_id: the key set held a key with no kid
	//   - duplicate_key_id: a key ID appeared twice in the key set, or another
	//     source already supplies it
	//   - http_NNN: the key set server answered with status NNN, such as
	//     http_429 or http_503, or http_other for a status outside 100 to 599
	//   - unreachable: no response arrived, because of a timeout or a DNS,
	//     connection, or TLS failure
	//   - unreadable_file: a file source could not be read
	//   - unparseable: the body was not a JWK or a JWK set
	//   - other: anything else
	ReasonLabel = "reason"
)

func newRefreshTotal(f *touchstone.Factory) (*prometheus.CounterVec, error) {
	return f.NewCounterVec(
		prometheus.CounterOpts{
			Name: RefreshTotalName,
			Help: RefreshTotalHelp,
		},
		SourceLabel,
	)
}

func newRefreshKeys(f *touchstone.Factory) (*prometheus.GaugeVec, error) {
	return f.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: RefreshKeysName,
			Help: RefreshKeysHelp,
		},
		SourceLabel,
	)
}

func newRefreshKeySetBytes(f *touchstone.Factory) (*prometheus.GaugeVec, error) {
	return f.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: RefreshKeySetBytesName,
			Help: RefreshKeySetBytesHelp,
		},
		SourceLabel,
	)
}

func newRefreshErrorTotal(f *touchstone.Factory) (*prometheus.CounterVec, error) {
	return f.NewCounterVec(
		prometheus.CounterOpts{
			Name: RefreshErrorTotalName,
			Help: RefreshErrorTotalHelp,
		},
		SourceLabel,
		ReasonLabel,
	)
}
