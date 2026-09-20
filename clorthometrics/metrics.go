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

	// RefreshErrorTotalName is the name of the counter for key refreshes that
	// resulted in an error, labeled by source.
	RefreshErrorTotalName = MetricPrefix + "refresh_error_total"

	// RefreshErrorTotalHelp is the help text for the refresh error total metric.
	RefreshErrorTotalHelp = "the total number of failed attempts to refresh keys"

	// SourceLabel is the metric label carrying the source URI, with any
	// password redacted.
	SourceLabel = "source"
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

func newRefreshErrorTotal(f *touchstone.Factory) (*prometheus.CounterVec, error) {
	return f.NewCounterVec(
		prometheus.CounterOpts{
			Name: RefreshErrorTotalName,
			Help: RefreshErrorTotalHelp,
		},
		SourceLabel,
	)
}
