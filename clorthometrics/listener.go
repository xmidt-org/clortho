// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthometrics

import (
	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/xmidt-org/clortho"
	"github.com/xmidt-org/touchstone"
)

// ListenerOption is a configurable option passed to NewListener that
// can tailor the created Listener.
type ListenerOption interface {
	applyToListener(*Listener) error
}

type listenerOptionFunc func(*Listener) error

func (lof listenerOptionFunc) applyToListener(l *Listener) error {
	return lof(l)
}

// WithFactory populates a listener with metrics created via the given factory.
func WithFactory(f *touchstone.Factory) ListenerOption {
	return listenerOptionFunc(func(l *Listener) error {
		var (
			errs      = make([]error, 0, 6)
			metricErr error
		)

		l.refreshTotal, metricErr = newRefreshTotal(f)
		errs = append(errs, metricErr)

		l.refreshKeys, metricErr = newRefreshKeys(f)
		errs = append(errs, metricErr)

		l.refreshKeySetBytes, metricErr = newRefreshKeySetBytes(f)
		errs = append(errs, metricErr)

		l.refreshErrorTotal, metricErr = newRefreshErrorTotal(f)
		errs = append(errs, metricErr)

		l.fetchTotal, metricErr = newFetchTotal(f)
		errs = append(errs, metricErr)

		l.fetchErrorTotal, metricErr = newFetchErrorTotal(f)
		errs = append(errs, metricErr)

		return errors.Join(errs...)
	})
}

// Listener tallies what clortho's providers do as metrics, labeled by source.
// It is a clortho.Listener, for the refreshes of a KeySetProvider, and a
// clortho.FetchListener, for the fetches of a PerKeyProvider.  Each error
// total is also labeled by the reason for the failure; see ReasonLabel.
type Listener struct {
	refreshTotal       *prometheus.CounterVec
	refreshKeys        *prometheus.GaugeVec
	refreshKeySetBytes *prometheus.GaugeVec
	refreshErrorTotal  *prometheus.CounterVec

	fetchTotal      *prometheus.CounterVec
	fetchErrorTotal *prometheus.CounterVec
}

var (
	_ clortho.Listener      = (*Listener)(nil)
	_ clortho.FetchListener = (*Listener)(nil)
)

// NewListener creates a metrics Listener using the supplied set of options.
// A Listener created with no options records nothing.
func NewListener(options ...ListenerOption) (l *Listener, err error) {
	l = &Listener{}

	errs := make([]error, 0, len(options))
	for _, o := range options {
		errs = append(errs, o.applyToListener(l))
	}

	if err = errors.Join(errs...); err != nil {
		l = nil
	}

	return
}

// OnRefreshEvent tallies metrics for one refresh of one source.
func (l *Listener) OnRefreshEvent(event clortho.RefreshEvent) {
	if l.refreshTotal == nil {
		return
	}

	labels := prometheus.Labels{SourceLabel: event.URI}
	l.refreshTotal.With(labels).Add(1.0)
	l.refreshKeys.With(labels).Set(float64(len(event.KeyIDs)))
	l.refreshKeySetBytes.With(labels).Set(float64(event.KeySetBytes))

	if event.Err != nil {
		l.refreshErrorTotal.With(prometheus.Labels{
			SourceLabel: event.URI,
			ReasonLabel: reason(event.Err),
		}).Add(1.0)
	}
}

// OnFetchEvent tallies metrics for one fetch of one key by a PerKeyProvider.
// The label is the provider's URL template, never the key ID, so that a flood
// of invented key IDs cannot become a flood of metric series.
func (l *Listener) OnFetchEvent(event clortho.FetchEvent) {
	if l.fetchTotal == nil {
		return
	}

	l.fetchTotal.With(prometheus.Labels{SourceLabel: event.URI}).Add(1.0)
	if event.Err != nil {
		l.fetchErrorTotal.With(prometheus.Labels{
			SourceLabel: event.URI,
			ReasonLabel: reason(event.Err),
		}).Add(1.0)
	}
}
