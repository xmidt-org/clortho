// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// httpSource returns a normalized source pointing at a test server.
func httpSource(uri string) RefreshSource {
	return RefreshSource{URI: uri}.withDefaults()
}

func TestLoadHTTPOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		w.Header().Set("Cache-Control", "no-transform, max-age=120")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	c, err := load(context.Background(), httpSource(server.URL), time.Time{})
	require.NoError(t, err)
	assert.Equal(t, `{"keys":[]}`, string(c.data))
	assert.False(t, c.notModified)
	assert.Equal(t, http.StatusOK, c.statusCode)
	assert.Equal(t, 2*time.Minute, c.ttl)
	assert.Equal(t, time.Date(2015, time.October, 21, 7, 28, 0, 0, time.UTC), c.lastModified.UTC())
}

func TestLoadHTTPSendsAcceptAndIfModifiedSince(t *testing.T) {
	var accept, since string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		since = r.Header.Get("If-Modified-Since")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	when := time.Date(2015, time.October, 21, 7, 28, 0, 0, time.UTC)
	_, err := load(context.Background(), httpSource(server.URL), when)
	require.NoError(t, err)
	assert.Contains(t, accept, "application/jwk-set+json")
	assert.Contains(t, accept, "application/jwk+json")
	assert.Equal(t, "Wed, 21 Oct 2015 07:28:00 GMT", since)
}

func TestLoadHTTPOmitsIfModifiedSinceOnAFirstLoad(t *testing.T) {
	var since string
	var present bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		since, present = r.Header.Get("If-Modified-Since"), r.Header.Values("If-Modified-Since") != nil
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	_, err := load(context.Background(), httpSource(server.URL), time.Time{})
	require.NoError(t, err)
	assert.Empty(t, since)
	assert.False(t, present)
}

func TestLoadHTTPNotModified(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer server.Close()

	c, err := load(context.Background(), httpSource(server.URL), time.Now())
	require.NoError(t, err)
	assert.True(t, c.notModified)
	assert.Nil(t, c.data)
	assert.Equal(t, http.StatusNotModified, c.statusCode)
	assert.Equal(t, time.Minute, c.ttl)
}

func TestLoadHTTPStatusError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	c, err := load(context.Background(), httpSource(server.URL), time.Time{})
	var httpErr *HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusInternalServerError, httpErr.StatusCode)
	assert.Equal(t, server.URL, httpErr.Location)
	assert.Equal(t, http.StatusInternalServerError, c.statusCode)
}

func TestLoadHTTPDoesNotFollowRedirectsByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://elsewhere.invalid/keys", http.StatusFound)
	}))
	defer server.Close()

	_, err := load(context.Background(), httpSource(server.URL), time.Time{})
	var httpErr *HTTPError
	require.ErrorAs(t, err, &httpErr)
	assert.Equal(t, http.StatusFound, httpErr.StatusCode)
}

func TestLoadHTTPUsesTheSourcesClient(t *testing.T) {
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		followed = true
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer server.Close()

	src := RefreshSource{URI: server.URL, Client: &http.Client{}}.withDefaults()
	c, err := load(context.Background(), src, time.Time{})
	require.NoError(t, err)
	assert.True(t, followed)
	assert.Equal(t, `{"keys":[]}`, string(c.data))
}

func TestLoadHTTPTooLarge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	src := RefreshSource{URI: server.URL, MaxResponseBytes: 10}.withDefaults()
	c, err := load(context.Background(), src, time.Time{})
	assert.ErrorIs(t, err, ErrResponseTooLarge)
	assert.Equal(t, http.StatusOK, c.statusCode)
}

func TestLoadHTTPExactlyAtTheLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	src := RefreshSource{URI: server.URL, MaxResponseBytes: 11}.withDefaults()
	c, err := load(context.Background(), src, time.Time{})
	require.NoError(t, err)
	assert.Equal(t, `{"keys":[]}`, string(c.data))
}

func TestLoadHTTPChunkedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		flusher := w.(http.Flusher)
		_, _ = w.Write([]byte(`{"keys":`))
		flusher.Flush()
		_, _ = w.Write([]byte(`[]}`))
	}))
	defer server.Close()

	c, err := load(context.Background(), httpSource(server.URL), time.Time{})
	require.NoError(t, err)
	assert.Equal(t, `{"keys":[]}`, string(c.data))
}

func TestLoadHTTPIgnoresABadCacheControl(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=-5")
		w.Header().Set("Last-Modified", "not a date")
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	defer server.Close()

	c, err := load(context.Background(), httpSource(server.URL), time.Time{})
	require.NoError(t, err)
	assert.Zero(t, c.ttl)
	assert.True(t, c.lastModified.IsZero())
}

func TestLoadHTTPTransportError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	uri := server.URL
	server.Close()

	c, err := load(context.Background(), httpSource(uri), time.Time{})
	assert.Error(t, err)
	assert.Zero(t, c.statusCode)
}

func TestLoadHTTPRedactsCredentialsInErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	uri := "http://user:hunter2@" + server.Listener.Addr().String() + "/keys"
	_, err := load(context.Background(), httpSource(uri), time.Time{})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "hunter2")
	assert.Contains(t, err.Error(), "user:xxxxx@")
}

func TestLoadHTTPHonorsTheContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := load(ctx, httpSource(server.URL), time.Time{})
	assert.ErrorIs(t, err, context.Canceled)
}

func TestLoadFileByPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"keys":[]}`), 0o600))
	fi, err := os.Stat(path)
	require.NoError(t, err)

	c, err := load(context.Background(), httpSource(path), time.Time{})
	require.NoError(t, err)
	assert.Equal(t, `{"keys":[]}`, string(c.data))
	assert.False(t, c.notModified)
	assert.Zero(t, c.statusCode)
	assert.Zero(t, c.ttl)
	assert.Equal(t, fi.ModTime(), c.lastModified)
}

func TestLoadFileByURI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.json")
	require.NoError(t, os.WriteFile(path, []byte(`{"keys":[]}`), 0o600))

	c, err := load(context.Background(), httpSource("file://"+path), time.Time{})
	require.NoError(t, err)
	assert.Equal(t, `{"keys":[]}`, string(c.data))
}

func TestLoadFileMissing(t *testing.T) {
	_, err := load(context.Background(), httpSource(filepath.Join(t.TempDir(), "nope.json")), time.Time{})
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestLoadFileNotARegularFile(t *testing.T) {
	_, err := load(context.Background(), httpSource(t.TempDir()), time.Time{})
	require.Error(t, err)
	assert.False(t, errors.Is(err, os.ErrNotExist))
}
