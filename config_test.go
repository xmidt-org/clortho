// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewRequiresASource(t *testing.T) {
	p, err := New(Config{})
	assert.ErrorIs(t, err, ErrNoKeySources)
	assert.Nil(t, p)
}

func TestNewRejectsAnEmptyURI(t *testing.T) {
	p, err := New(Config{Sources: []RefreshSource{{}}})
	assert.Error(t, err)
	assert.Nil(t, p)
}

func TestNewRejectsAnUnsupportedScheme(t *testing.T) {
	p, err := New(Config{Sources: []RefreshSource{{URI: "ftp://keys.example.com/jwks"}}})
	assert.ErrorIs(t, err, ErrUnsupportedScheme)
	assert.Nil(t, p)
}

func TestNewRejectsADuplicateSource(t *testing.T) {
	p, err := New(Config{Sources: []RefreshSource{
		{URI: "https://keys.example.com/jwks"},
		{URI: "https://keys.example.com/jwks"},
	}})
	assert.Error(t, err)
	assert.Nil(t, p)
}

func TestNewReportsEveryProblemAtOnce(t *testing.T) {
	_, err := New(Config{Sources: []RefreshSource{
		{URI: "ftp://keys.example.com/jwks"},
		{},
	}})
	assert.ErrorIs(t, err, ErrUnsupportedScheme)
	assert.ErrorContains(t, err, "URI is required")
}

func TestNewRedactsACredentialedURIInErrors(t *testing.T) {
	uri := "ftp://user:" + "hunter2" + "@keys.example.com/jwks"
	_, err := New(Config{Sources: []RefreshSource{{URI: uri}}})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hunter2")
	assert.Contains(t, err.Error(), "user:xxxxx@")
}

func TestNewAcceptsFileHTTPAndHTTPS(t *testing.T) {
	p, err := New(Config{Sources: []RefreshSource{
		{URI: "file:///etc/keys.json"},
		{URI: "/etc/other-keys.json"},
		{URI: "http://keys.example.com/jwks"},
		{URI: "https://keys.example.com/jwks"},
	}})
	require.NoError(t, err)
	require.NotNil(t, p)

	status := p.Status()
	require.Len(t, status, 4)
	assert.Equal(t, "file:///etc/keys.json", status[0].URI)
	assert.Equal(t, "/etc/other-keys.json", status[1].URI)
	assert.Equal(t, "http://keys.example.com/jwks", status[2].URI)
	assert.Equal(t, "https://keys.example.com/jwks", status[3].URI)
}

func TestNewFillsDefaults(t *testing.T) {
	p, err := New(Config{Sources: []RefreshSource{{URI: "https://keys.example.com/jwks"}}})
	require.NoError(t, err)

	src := p.sources[0]
	assert.Equal(t, DefaultRefreshInterval, src.RefreshInterval)
	assert.Equal(t, DefaultMinRefreshInterval, src.MinRefreshInterval)
	assert.Equal(t, DefaultMaxRefreshInterval, src.MaxRefreshInterval)
	assert.Equal(t, DefaultJitterPercentage, src.JitterPercentage)
	assert.Equal(t, DefaultMaxResponseBytes, src.MaxResponseBytes)
	require.NotNil(t, src.Client)
	assert.Equal(t, DefaultHTTPTimeout, src.Client.Timeout)
	require.NotNil(t, src.Client.CheckRedirect)
	assert.ErrorIs(t, src.Client.CheckRedirect(nil, nil), http.ErrUseLastResponse)
}

func TestNewKeepsExplicitValues(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	p, err := New(Config{Sources: []RefreshSource{{
		URI:                "https://keys.example.com/jwks",
		RefreshInterval:    time.Hour,
		MinRefreshInterval: time.Minute,
		MaxRefreshInterval: 2 * time.Hour,
		JitterPercentage:   25,
		Client:             client,
		MaxResponseBytes:   1024,
	}}})
	require.NoError(t, err)

	src := p.sources[0]
	assert.Equal(t, time.Hour, src.RefreshInterval)
	assert.Equal(t, time.Minute, src.MinRefreshInterval)
	assert.Equal(t, 2*time.Hour, src.MaxRefreshInterval)
	assert.Equal(t, 25.0, src.JitterPercentage)
	assert.Same(t, client, src.Client)
	assert.Equal(t, int64(1024), src.MaxResponseBytes)
}

func TestNewReplacesAnOutOfRangeJitter(t *testing.T) {
	p, err := New(Config{Sources: []RefreshSource{{URI: "https://keys.example.com/jwks", JitterPercentage: 150}}})
	require.NoError(t, err)
	assert.Equal(t, DefaultJitterPercentage, p.sources[0].JitterPercentage)
}

func TestNewRaisesAMaxBelowTheMin(t *testing.T) {
	p, err := New(Config{Sources: []RefreshSource{{
		URI:                "https://keys.example.com/jwks",
		MinRefreshInterval: time.Hour,
		MaxRefreshInterval: time.Minute,
	}}})
	require.NoError(t, err)
	assert.Equal(t, time.Hour, p.sources[0].MaxRefreshInterval)
}

func TestNewDoesNotShareTheCallersSlice(t *testing.T) {
	sources := []RefreshSource{{URI: "https://keys.example.com/jwks"}}
	p, err := New(Config{Sources: sources})
	require.NoError(t, err)

	sources[0].URI = "changed"
	assert.Equal(t, "https://keys.example.com/jwks", p.Status()[0].URI)
}

func TestNewRejectsAnUnparseableURI(t *testing.T) {
	p, err := New(Config{Sources: []RefreshSource{{URI: "http://[::1"}}})
	assert.ErrorIs(t, err, ErrUnsupportedScheme)
	assert.Nil(t, p)
}

func TestRedactURIWithoutAPassword(t *testing.T) {
	assert.Equal(t, "https://user@keys.example.com/jwks", redactURI("https://user@keys.example.com/jwks"))
	assert.Equal(t, "/etc/keys.json", redactURI("/etc/keys.json"))
}

func TestRedactURIThatDoesNotParse(t *testing.T) {
	uri := "https://user:" + "hunter2" + "@keys.example.com/{bad}/[::1"
	redacted := redactURI(uri)
	assert.NotContains(t, redacted, "hunter2")
	assert.Contains(t, redacted, "user:xxxxx@")
}
