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

func TestNewKeySetProviderRequiresASource(t *testing.T) {
	p, err := NewKeySetProvider(KeySetConfig{})
	assert.ErrorIs(t, err, ErrNoKeySources)
	assert.Nil(t, p)
}

func TestNewKeySetProviderRejectsAnEmptyURI(t *testing.T) {
	p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{}}})
	assert.Error(t, err)
	assert.Nil(t, p)
}

func TestNewKeySetProviderRejectsAnUnsupportedScheme(t *testing.T) {
	p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{URI: "ftp://keys.example.com/jwks"}}})
	assert.ErrorIs(t, err, ErrUnsupportedScheme)
	assert.Nil(t, p)
}

func TestNewKeySetProviderRejectsADuplicateSource(t *testing.T) {
	p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{
		{URI: "https://keys.example.com/jwks", Client: testClient()},
		{URI: "https://keys.example.com/jwks", Client: testClient()},
	}})
	assert.ErrorContains(t, err, "duplicate source URI")
	assert.NotErrorIs(t, err, ErrMissingClient)
	assert.Nil(t, p)
}

func TestNewKeySetProviderRequiresAClientForAnHTTPSource(t *testing.T) {
	for _, uri := range []string{"http://keys.example.com/jwks", "https://keys.example.com/jwks"} {
		p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{URI: uri}}})
		assert.ErrorIs(t, err, ErrMissingClient, uri)
		assert.ErrorContains(t, err, uri)
		assert.Nil(t, p)
	}
}

func TestNewKeySetProviderRedactsACredentialedURIWhenTheClientIsMissing(t *testing.T) {
	uri := "https://user:" + "hunter2" + "@keys.example.com/jwks"
	_, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{URI: uri}}})
	require.ErrorIs(t, err, ErrMissingClient)
	assert.NotContains(t, err.Error(), "hunter2")
	assert.Contains(t, err.Error(), "user:xxxxx@")
}

func TestNewKeySetProviderRejectsAClientOnAFileSource(t *testing.T) {
	for _, uri := range []string{"file:///etc/keys.json", "/etc/other-keys.json"} {
		p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{URI: uri, Client: testClient()}}})
		assert.ErrorIs(t, err, ErrUnusedClient, uri)
		assert.ErrorContains(t, err, uri)
		assert.Nil(t, p)
	}
}

func TestNewKeySetProviderCatchesAnHTTPURIWrittenWithoutItsScheme(t *testing.T) {
	// with no scheme this reads as a file path.  the client that came with it is
	// what gives the mistake away, at NewKeySetProvider instead of at the first
	// refresh.
	p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{URI: "keys.example.com/jwks", Client: testClient()}}})
	assert.ErrorIs(t, err, ErrUnusedClient)
	assert.Nil(t, p)
}

func TestNewKeySetProviderNeedsNoClientForAFileSource(t *testing.T) {
	p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{
		{URI: "file:///etc/keys.json"},
		{URI: "/etc/other-keys.json"},
	}})
	require.NoError(t, err)
	require.NotNil(t, p)

	// and none is made up for it
	assert.Nil(t, p.sources[0].Client)
	assert.Nil(t, p.sources[1].Client)
}

func TestNewKeySetProviderReportsEveryProblemAtOnce(t *testing.T) {
	_, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{
		{URI: "ftp://keys.example.com/jwks"},
		{},
		{URI: "https://keys.example.com/other"},
	}})
	assert.ErrorIs(t, err, ErrUnsupportedScheme)
	assert.ErrorContains(t, err, "source 1: a URI is required")
	assert.ErrorIs(t, err, ErrMissingClient)
}

func TestNewKeySetProviderRedactsACredentialedURIInErrors(t *testing.T) {
	uri := "ftp://user:" + "hunter2" + "@keys.example.com/jwks"
	_, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{URI: uri}}})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hunter2")
	assert.Contains(t, err.Error(), "user:xxxxx@")
}

func TestNewKeySetProviderAcceptsFileHTTPAndHTTPS(t *testing.T) {
	p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{
		{URI: "file:///etc/keys.json"},
		{URI: "/etc/other-keys.json"},
		{URI: "http://keys.example.com/jwks", Client: testClient()},
		{URI: "https://keys.example.com/jwks", Client: testClient()},
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

func TestNewKeySetProviderFillsDefaults(t *testing.T) {
	client := &http.Client{}
	p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{URI: "https://keys.example.com/jwks", Client: client}}})
	require.NoError(t, err)

	src := p.sources[0]
	assert.Equal(t, DefaultRefreshInterval, src.RefreshInterval)
	assert.Equal(t, DefaultMinRefreshInterval, src.MinRefreshInterval)
	assert.Equal(t, DefaultMaxRefreshInterval, src.MaxRefreshInterval)
	assert.Equal(t, DefaultJitterPercentage, src.JitterPercentage)
	assert.Equal(t, DefaultMaxResponseBytes, src.MaxResponseBytes)

	// the client is the caller's, as given: nothing about it is filled in
	assert.Same(t, client, src.Client)
	assert.Equal(t, http.Client{}, *src.Client)
}

func TestNewKeySetProviderKeepsExplicitValues(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{
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

func TestNewKeySetProviderReplacesAnOutOfRangeJitter(t *testing.T) {
	p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{URI: "https://keys.example.com/jwks", Client: testClient(), JitterPercentage: 150}}})
	require.NoError(t, err)
	assert.Equal(t, DefaultJitterPercentage, p.sources[0].JitterPercentage)
}

func TestNewKeySetProviderRaisesAMaxBelowTheMin(t *testing.T) {
	p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{
		URI:                "https://keys.example.com/jwks",
		Client:             testClient(),
		MinRefreshInterval: time.Hour,
		MaxRefreshInterval: time.Minute,
	}}})
	require.NoError(t, err)
	assert.Equal(t, time.Hour, p.sources[0].MaxRefreshInterval)
}

func TestNewKeySetProviderDoesNotShareTheCallersSlice(t *testing.T) {
	sources := []RefreshSource{{URI: "https://keys.example.com/jwks", Client: testClient()}}
	p, err := NewKeySetProvider(KeySetConfig{Sources: sources})
	require.NoError(t, err)

	sources[0].URI = "changed"
	assert.Equal(t, "https://keys.example.com/jwks", p.Status()[0].URI)
}

func TestNewKeySetProviderRejectsAnUnparseableURI(t *testing.T) {
	uri := "http://user:" + "hunter2" + "@[::1"
	p, err := NewKeySetProvider(KeySetConfig{Sources: []RefreshSource{{URI: uri}}})
	assert.ErrorIs(t, err, ErrUnsupportedScheme)
	assert.ErrorContains(t, err, "source 0")
	assert.NotContains(t, err.Error(), "hunter2")
	assert.Nil(t, p)
}

func TestRedactURIWithoutAPassword(t *testing.T) {
	assert.Equal(t, "https://user@keys.example.com/jwks", redactURI("https://user@keys.example.com/jwks"))
	assert.Equal(t, "/etc/keys.json", redactURI("/etc/keys.json"))
}

func TestRedactURIThatDoesNotParse(t *testing.T) {
	// url.Parse is strict about the host, not the path
	uri := "https://user:" + "hunter2" + "@[::1"
	assert.Equal(t, "<unparseable URI>", redactURI(uri))
}
