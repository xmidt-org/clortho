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
	"go.uber.org/multierr"
)

const (
	// SourceLabel is the metric label indicating the URI source of the key(s).
	SourceLabel = "source"

	// KeyIDLabel is the metric label indicating the key ID that was resolved.
	KeyIDLabel = "keyID"
)

// ListenerOption is a configuration option for creating a Listener.
type ListenerOption interface {
	applyToListener(*Listener) error
}

type listenerOptionFunc func(*Listener) error

func (lof listenerOptionFunc) applyToListener(l *Listener) error {
	return lof(l)
}

// WithRefreshes sets the counter for refresh events.  The given counter must
// have exactly (1) label: SourceLabel.
func WithRefreshes(c *prometheus.CounterVec) ListenerOption {
	return listenerOptionFunc(func(l *Listener) error {
		l.refreshes = c
		return nil
	})
}

// WithRefreshKeys sets the gauge for refresh events.  The given counter must
// have exactly (1) label: SourceLabel.
func WithRefreshKeys(g *prometheus.GaugeVec) ListenerOption {
	return listenerOptionFunc(func(l *Listener) error {
		l.refreshKeys = g
		return nil
	})
}

// WithRefreshErrors sets the counter for refresh errors.  The given counter must
// have exactly (1) label: SourceLabel.
func WithRefreshErrors(c *prometheus.CounterVec) ListenerOption {
	return listenerOptionFunc(func(l *Listener) error {
		l.refreshErrors = c
		return nil
	})
}

// WithResolves sets the counter for resolve events.  The given counter must
// have exactly (2) labels: SourceLabel and KeyIDLabel.
func WithResolves(c *prometheus.CounterVec) ListenerOption {
	return listenerOptionFunc(func(l *Listener) error {
		l.resolves = c
		return nil
	})
}

// WithResolveErrors sets the counter for resolve errors.  The given counter must
// have exactly (2) labels: SourceLabel and KeyIDLabel.
func WithResolveErrors(c *prometheus.CounterVec) ListenerOption {
	return listenerOptionFunc(func(l *Listener) error {
		l.resolveErrors = c
		return nil
	})
}

// Listener handle refresh and resolve events, tallying metrics for both.
type Listener struct {
	refreshes     *prometheus.CounterVec
	refreshKeys   *prometheus.GaugeVec
	refreshErrors *prometheus.CounterVec

	resolves      *prometheus.CounterVec
	resolveErrors *prometheus.CounterVec
}

// NewListener constructs a new metrics Listener from a set of options.
// No metrics are defaulted.  If no options are passed, the returned
// Listener will track nothing.
func NewListener(options ...ListenerOption) (l *Listener, err error) {
	l = &Listener{}

	for _, o := range options {
		err = multierr.Append(err, o.applyToListener(l))
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

	if l.refreshes != nil {
		l.refreshes.With(labels).Add(1.0)
	}

	if l.refreshKeys != nil {
		l.refreshKeys.With(labels).Set(float64(event.Keys.Len()))
	}

	if event.Err != nil && l.refreshErrors != nil {
		l.refreshErrors.With(labels).Add(1.0)
	}
}

// OnResolveEvent tallies metrics for the given ResolveEvent.
func (l *Listener) OnResolveEvent(event clortho.ResolveEvent) {
	labels := prometheus.Labels{
		SourceLabel: event.URI,
		KeyIDLabel:  event.KeyID,
	}

	if l.resolves != nil {
		l.resolves.With(labels).Add(1.0)
	}

	if event.Err != nil && l.resolveErrors != nil {
		l.resolveErrors.With(labels).Add(1.0)
	}
}
