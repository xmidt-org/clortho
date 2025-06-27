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
	// both successful and unsuccessful.
	RefreshTotalName = MetricPrefix + "refresh_total"

	// RefreshTotalHelp is the help text for the refresh total metric.
	RefreshTotalHelp = "the total number of attempts to refresh keys, both successful and unsuccessful"

	// RefreshKeysName is the name of the gauge for the number of keys from a particular
	// source URI.
	RefreshKeysName = MetricPrefix + "refresh_keys"

	// RefreshKeysHelp is the help text for the refresh keys metric.
	RefreshKeysHelp = "the number of keys for a particular source URI"

	// RefreshErrorTotalName is the name of the counter for key refreshes that
	// resulted in an error.
	RefreshErrorTotalName = MetricPrefix + "refresh_error_total"

	// RefreshErrorTotalHelp is the help text for the refresh error total metric.
	RefreshErrorTotalHelp = "the total number of failed attempts to refresh keys"

	// ResolveTotalName is the name of the counter for all resolve attempts,
	// both successful and unsuccessful.  Individual keys, rather than key sets,
	// are resolved.  In contrast, the refresh metrics track key set refreshes.
	ResolveTotalName = MetricPrefix + "resolve_total"

	// ResolveTotalHelp is the help text for the resolve total metric.
	ResolveTotalHelp = "the total attempts to resolve individual keys by key id, both successful and unsuccessful"

	// ResolveErrorTotalName is the name of the counter for failed resolve attempts
	// for individual keys.
	ResolveErrorTotalName = MetricPrefix + "resolve_error_total"

	// ResolveErrorTotalHelp is the help text for the resolve error metric.
	ResolveErrorTotalHelp = "the total failed attempts to resolve individual keys"

	// SourceLabel is the metric label indicating the URI source of the key(s).
	SourceLabel = "source"

	// KeyIDLabel is the metric label indicating the key ID that was resolved.
	KeyIDLabel = "keyID"
)

func newRefreshTotal(f *touchstone.Factory) (m *prometheus.CounterVec, err error) {
	return f.NewCounterVec(
		prometheus.CounterOpts{
			Name: RefreshTotalName,
			Help: RefreshTotalHelp,
		},
		SourceLabel,
	)
}

func newRefreshKeys(f *touchstone.Factory) (m *prometheus.GaugeVec, err error) {
	return f.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: RefreshKeysName,
			Help: RefreshKeysHelp,
		},
		SourceLabel,
	)
}

func newRefreshErrorTotal(f *touchstone.Factory) (m *prometheus.CounterVec, err error) {
	return f.NewCounterVec(
		prometheus.CounterOpts{
			Name: RefreshErrorTotalName,
			Help: RefreshErrorTotalHelp,
		},
		SourceLabel,
	)
}

func newResolveTotal(f *touchstone.Factory) (m *prometheus.CounterVec, err error) {
	return f.NewCounterVec(
		prometheus.CounterOpts{
			Name: ResolveTotalName,
			Help: ResolveTotalHelp,
		},
		SourceLabel,
		KeyIDLabel,
	)
}

func newResolveErrorTotal(f *touchstone.Factory) (m *prometheus.CounterVec, err error) {
	return f.NewCounterVec(
		prometheus.CounterOpts{
			Name: ResolveErrorTotalName,
			Help: ResolveErrorTotalHelp,
		},
		SourceLabel,
		KeyIDLabel,
	)
}
