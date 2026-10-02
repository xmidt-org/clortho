// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthometrics

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/clortho"
	"github.com/xmidt-org/touchstone"
	"github.com/xmidt-org/touchstone/touchtest"
	"go.uber.org/zap"
)

// errorListenerOption is a ListenerOption that returns an error, since no
// real option can fail without a broken factory.
type errorListenerOption struct {
	err error
}

func (elo errorListenerOption) applyToListener(*Listener) error { return elo.err }

func newFactory() (*prometheus.Registry, *touchstone.Factory) {
	r := prometheus.NewPedanticRegistry()
	return r, touchstone.NewFactory(touchstone.Config{}, zap.NewNop(), r)
}

func newListener(t *testing.T, f *touchstone.Factory) *Listener {
	l, err := NewListener(WithFactory(f))
	require.NoError(t, err)
	require.NotNil(t, l)
	return l
}

func TestNewListenerOptionError(t *testing.T) {
	expected := errors.New("expected")
	l, err := NewListener(errorListenerOption{err: expected})
	assert.Nil(t, l)
	assert.ErrorIs(t, err, expected)
}

func TestNewListenerNoOptionsRecordsNothing(t *testing.T) {
	l, err := NewListener()
	require.NoError(t, err)
	require.NotNil(t, l)

	assert.NotPanics(t, func() {
		l.OnRefreshEvent(clortho.RefreshEvent{URI: "https://keys.example.com/jwks", KeyIDs: []string{"a"}})
	})
}

func TestWithFactoryFailsWhenAMetricIsAlreadyRegistered(t *testing.T) {
	_, f := newFactory()
	_, err := f.NewCounterVec(prometheus.CounterOpts{Name: RefreshTotalName, Help: "taken"}, SourceLabel)
	require.NoError(t, err)

	l, err := NewListener(WithFactory(f))
	assert.Nil(t, l)
	assert.Error(t, err)
}

func TestOnRefreshEventSuccess(t *testing.T) {
	actual, actualFactory := newFactory()
	actualListener := newListener(t, actualFactory)
	expected, expectedFactory := newFactory()
	expectedListener := newListener(t, expectedFactory)

	labels := prometheus.Labels{SourceLabel: "https://keys.example.com/jwks"}
	expectedListener.refreshTotal.With(labels).Add(1.0)
	expectedListener.refreshKeys.With(labels).Set(2.0)
	assertions := touchtest.New(t)
	assertions.Expect(expected)

	actualListener.OnRefreshEvent(clortho.RefreshEvent{
		URI:    "https://keys.example.com/jwks",
		KeyIDs: []string{"a", "b"},
	})

	assertions.GatherAndCompare(actual)
}

func TestOnRefreshEventError(t *testing.T) {
	actual, actualFactory := newFactory()
	actualListener := newListener(t, actualFactory)
	expected, expectedFactory := newFactory()
	expectedListener := newListener(t, expectedFactory)

	labels := prometheus.Labels{SourceLabel: "https://keys.example.com/jwks"}
	expectedListener.refreshTotal.With(labels).Add(1.0)
	expectedListener.refreshErrorTotal.With(labels).Add(1.0)
	expectedListener.refreshKeys.With(labels).Set(1.0)
	assertions := touchtest.New(t)
	assertions.Expect(expected)

	actualListener.OnRefreshEvent(clortho.RefreshEvent{
		URI:    "https://keys.example.com/jwks",
		Err:    errors.New("expected"),
		KeyIDs: []string{"a"},
	})

	assertions.GatherAndCompare(actual)
}

func TestOnRefreshEventKeepsSourcesApart(t *testing.T) {
	actual, actualFactory := newFactory()
	actualListener := newListener(t, actualFactory)
	expected, expectedFactory := newFactory()
	expectedListener := newListener(t, expectedFactory)

	one := prometheus.Labels{SourceLabel: "https://one.example.com/jwks"}
	two := prometheus.Labels{SourceLabel: "https://two.example.com/jwks"}
	expectedListener.refreshTotal.With(one).Add(1.0)
	expectedListener.refreshKeys.With(one).Set(3.0)
	expectedListener.refreshTotal.With(two).Add(1.0)
	expectedListener.refreshKeys.With(two).Set(0.0)
	expectedListener.refreshErrorTotal.With(two).Add(1.0)
	assertions := touchtest.New(t)
	assertions.Expect(expected)

	actualListener.OnRefreshEvent(clortho.RefreshEvent{URI: "https://one.example.com/jwks", KeyIDs: []string{"a", "b", "c"}})
	actualListener.OnRefreshEvent(clortho.RefreshEvent{URI: "https://two.example.com/jwks", Err: errors.New("expected")})

	assertions.GatherAndCompare(actual)
}
