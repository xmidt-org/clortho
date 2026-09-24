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
			errs      = make([]error, 0, 3)
			metricErr error
		)

		l.refreshTotal, metricErr = newRefreshTotal(f)
		errs = append(errs, metricErr)

		l.refreshKeys, metricErr = newRefreshKeys(f)
		errs = append(errs, metricErr)

		l.refreshErrorTotal, metricErr = newRefreshErrorTotal(f)
		errs = append(errs, metricErr)

		return errors.Join(errs...)
	})
}

// Listener is a clortho.Listener that tallies refresh metrics, labeled by
// source URI.
type Listener struct {
	refreshTotal      *prometheus.CounterVec
	refreshKeys       *prometheus.GaugeVec
	refreshErrorTotal *prometheus.CounterVec
}

var _ clortho.Listener = (*Listener)(nil)

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

	if event.Err != nil {
		l.refreshErrorTotal.With(labels).Add(1.0)
	}
}
