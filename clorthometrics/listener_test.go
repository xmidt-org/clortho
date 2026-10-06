// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthometrics

import (
	"errors"
	"fmt"
	"net/http"
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
	expectedListener.refreshKeySetBytes.With(labels).Set(812.0)
	assertions := touchtest.New(t)
	assertions.Expect(expected)

	actualListener.OnRefreshEvent(clortho.RefreshEvent{
		URI:         "https://keys.example.com/jwks",
		KeyIDs:      []string{"a", "b"},
		KeySetBytes: 812,
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
	expectedListener.refreshErrorTotal.With(prometheus.Labels{
		SourceLabel: "https://keys.example.com/jwks",
		ReasonLabel: "other",
	}).Add(1.0)
	expectedListener.refreshKeys.With(labels).Set(1.0)
	expectedListener.refreshKeySetBytes.With(labels).Set(406.0)
	assertions := touchtest.New(t)
	assertions.Expect(expected)

	// a failed refresh still reports the keys, and the size of the key set,
	// that the source supplied before
	actualListener.OnRefreshEvent(clortho.RefreshEvent{
		URI:         "https://keys.example.com/jwks",
		Err:         errors.New("expected"),
		KeyIDs:      []string{"a"},
		KeySetBytes: 406,
	})

	assertions.GatherAndCompare(actual)
}

func TestOnRefreshEventCountsErrorsByReason(t *testing.T) {
	actual, actualFactory := newFactory()
	actualListener := newListener(t, actualFactory)
	expected, expectedFactory := newFactory()
	expectedListener := newListener(t, expectedFactory)

	const source = "https://keys.example.com/jwks"
	labels := prometheus.Labels{SourceLabel: source}
	expectedListener.refreshTotal.With(labels).Add(4.0)
	expectedListener.refreshKeys.With(labels).Set(0.0)
	expectedListener.refreshKeySetBytes.With(labels).Set(0.0)
	expectedListener.refreshErrorTotal.With(prometheus.Labels{SourceLabel: source, ReasonLabel: "too_large"}).Add(1.0)
	expectedListener.refreshErrorTotal.With(prometheus.Labels{SourceLabel: source, ReasonLabel: "http_503"}).Add(2.0)
	expectedListener.refreshErrorTotal.With(prometheus.Labels{SourceLabel: source, ReasonLabel: "http_429"}).Add(1.0)
	assertions := touchtest.New(t)
	assertions.Expect(expected)

	for _, err := range []error{
		fmt.Errorf("%w: too big", clortho.ErrResponseTooLarge),
		&clortho.HTTPError{Location: source, StatusCode: http.StatusServiceUnavailable},
		&clortho.HTTPError{Location: source, StatusCode: http.StatusServiceUnavailable},
		&clortho.HTTPError{Location: source, StatusCode: http.StatusTooManyRequests},
	} {
		actualListener.OnRefreshEvent(clortho.RefreshEvent{URI: source, Err: err})
	}

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
	expectedListener.refreshKeySetBytes.With(one).Set(1200.0)
	expectedListener.refreshTotal.With(two).Add(1.0)
	expectedListener.refreshKeys.With(two).Set(0.0)
	expectedListener.refreshKeySetBytes.With(two).Set(0.0)
	expectedListener.refreshErrorTotal.With(prometheus.Labels{
		SourceLabel: "https://two.example.com/jwks",
		ReasonLabel: "other",
	}).Add(1.0)
	assertions := touchtest.New(t)
	assertions.Expect(expected)

	actualListener.OnRefreshEvent(clortho.RefreshEvent{URI: "https://one.example.com/jwks", KeyIDs: []string{"a", "b", "c"}, KeySetBytes: 1200})
	actualListener.OnRefreshEvent(clortho.RefreshEvent{URI: "https://two.example.com/jwks", Err: errors.New("expected")})

	assertions.GatherAndCompare(actual)
}

func TestOnFetchEvent(t *testing.T) {
	actual, actualFactory := newFactory()
	actualListener := newListener(t, actualFactory)
	expected, expectedFactory := newFactory()
	expectedListener := newListener(t, expectedFactory)

	const source = "https://keys.example.com/keys/{keyID}"
	expectedListener.fetchTotal.With(prometheus.Labels{SourceLabel: source}).Add(4.0)
	expectedListener.fetchErrorTotal.With(prometheus.Labels{SourceLabel: source, ReasonLabel: "http_404"}).Add(2.0)
	expectedListener.fetchErrorTotal.With(prometheus.Labels{SourceLabel: source, ReasonLabel: "key_id_mismatch"}).Add(1.0)
	assertions := touchtest.New(t)
	assertions.Expect(expected)

	// the key IDs differ, and none of them becomes a label
	actualListener.OnFetchEvent(clortho.FetchEvent{URI: source, KeyID: "docker"})
	actualListener.OnFetchEvent(clortho.FetchEvent{URI: source, KeyID: "invented-1", Err: &clortho.HTTPError{StatusCode: http.StatusNotFound}})
	actualListener.OnFetchEvent(clortho.FetchEvent{URI: source, KeyID: "invented-2", Err: &clortho.HTTPError{StatusCode: http.StatusNotFound}})
	actualListener.OnFetchEvent(clortho.FetchEvent{URI: source, KeyID: "a", Err: fmt.Errorf("%w: b", clortho.ErrKeyIDMismatch)})

	assertions.GatherAndCompare(actual)
}

func TestOnFetchEventKeepsSourcesApart(t *testing.T) {
	actual, actualFactory := newFactory()
	actualListener := newListener(t, actualFactory)
	expected, expectedFactory := newFactory()
	expectedListener := newListener(t, expectedFactory)

	expectedListener.fetchTotal.With(prometheus.Labels{SourceLabel: "https://one.example.com/{keyID}"}).Add(1.0)
	expectedListener.fetchTotal.With(prometheus.Labels{SourceLabel: "https://two.example.com/{keyID}"}).Add(1.0)
	assertions := touchtest.New(t)
	assertions.Expect(expected)

	actualListener.OnFetchEvent(clortho.FetchEvent{URI: "https://one.example.com/{keyID}", KeyID: "a"})
	actualListener.OnFetchEvent(clortho.FetchEvent{URI: "https://two.example.com/{keyID}", KeyID: "a"})

	assertions.GatherAndCompare(actual)
}

func TestOnFetchEventNoOptionsRecordsNothing(t *testing.T) {
	l, err := NewListener()
	require.NoError(t, err)

	assert.NotPanics(t, func() {
		l.OnFetchEvent(clortho.FetchEvent{URI: "https://keys.example.com/keys/{keyID}", KeyID: "a"})
	})
}
