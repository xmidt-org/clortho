/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package clorthometrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/xmidt-org/clortho"
	"github.com/xmidt-org/touchstone"
	"go.uber.org/multierr"
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
	return listenerOptionFunc(func(l *Listener) (err error) {
		var metricErr error
		l.refreshTotal, metricErr = newRefreshTotal(f)
		err = multierr.Append(err, metricErr)

		l.refreshKeys, metricErr = newRefreshKeys(f)
		err = multierr.Append(err, metricErr)

		l.refreshErrorTotal, metricErr = newRefreshErrorTotal(f)
		err = multierr.Append(err, metricErr)

		l.resolveTotal, metricErr = newResolveTotal(f)
		err = multierr.Append(err, metricErr)

		l.resolveErrorTotal, metricErr = newResolveErrorTotal(f)
		err = multierr.Append(err, metricErr)

		return
	})
}

// Listener handles refresh and resolve events, tallying metrics for both.
type Listener struct {
	refreshTotal      *prometheus.CounterVec
	refreshKeys       *prometheus.GaugeVec
	refreshErrorTotal *prometheus.CounterVec

	resolveTotal      *prometheus.CounterVec
	resolveErrorTotal *prometheus.CounterVec
}

var _ clortho.RefreshListener = (*Listener)(nil)
var _ clortho.ResolveListener = (*Listener)(nil)

// NewListener creates a metrics Listener using the supplied set of options.
// If no options are passed, the returned Listener will be a no-op.
func NewListener(options ...ListenerOption) (l *Listener, err error) {
	l = &Listener{}

	for _, o := range options {
		err = o.applyToListener(l)
	}

	if err != nil {
		l = nil
	}

	return
}

// OnRefreshEvent tallies metrics for the given RefreshEvent.
func (l *Listener) OnRefreshEvent(event clortho.RefreshEvent) {
	labels := prometheus.Labels{
		SourceLabel: event.URI,
	}

	l.refreshTotal.With(labels).Add(1.0)
	l.refreshKeys.With(labels).Set(float64(event.Keys.Len()))

	if event.Err != nil {
		l.refreshErrorTotal.With(labels).Add(1.0)
	}
}

// OnResolveEvent tallies metrics for the given ResolveEvent.
func (l *Listener) OnResolveEvent(event clortho.ResolveEvent) {
	labels := prometheus.Labels{
		SourceLabel: event.URI,
		KeyIDLabel:  event.KeyID,
	}

	l.resolveTotal.With(labels).Add(1.0)

	if event.Err != nil {
		l.resolveErrorTotal.With(labels).Add(1.0)
	}
}
