// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"bytes"
	"context"
	"errors"
	"math"
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

func TestLoadHTTPReadsRetryAfterOnA429OrA503(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(status)
		}))

		c, err := load(context.Background(), httpSource(server.URL), time.Time{})
		server.Close()

		var httpErr *HTTPError
		require.ErrorAs(t, err, &httpErr)
		assert.Equal(t, status, httpErr.StatusCode)
		assert.Equal(t, 2*time.Minute, c.retryWait(time.Now()))
	}
}

func TestLoadHTTPIgnoresRetryAfterOnAnyOtherStatus(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusNotFound, http.StatusMovedPermanently} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Retry-After", "120")
			w.WriteHeader(status)
		}))

		c, err := load(context.Background(), httpSource(server.URL), time.Time{})
		server.Close()

		require.Error(t, err)
		assert.Zero(t, c.retryWait(time.Now()), "status %d", status)
	}
}

func TestParseRetryAfter(t *testing.T) {
	when := time.Date(2015, time.October, 21, 7, 28, 0, 0, time.UTC)
	tests := []struct {
		value string
		delay time.Duration
		date  time.Time
	}{
		{value: ""},
		{value: "30", delay: 30 * time.Second},
		{value: " 30 ", delay: 30 * time.Second},
		{value: "0", delay: time.Second},
		{value: "-5"},
		{value: "soon"},
		{value: "1.5"},
		{value: "9223372036854775807", delay: math.MaxInt64},
		{value: "99999999999999999999999"},
		{value: "Wed, 21 Oct 2015 07:28:00 GMT", date: when},
	}

	for _, test := range tests {
		delay, date := parseRetryAfter(test.value)
		assert.Equal(t, test.delay, delay, "value %q", test.value)
		assert.True(t, test.date.Equal(date), "value %q", test.value)
	}
}

func TestContentRetryWait(t *testing.T) {
	now := time.Date(2015, time.October, 21, 7, 28, 0, 0, time.UTC)

	assert.Zero(t, content{}.retryWait(now))
	assert.Equal(t, time.Minute, content{retryDelay: time.Minute}.retryWait(now))
	assert.Equal(t, 90*time.Second, content{retryDate: now.Add(90 * time.Second)}.retryWait(now))

	// a date that has passed, or is passing, is no instruction
	assert.Zero(t, content{retryDate: now}.retryWait(now))
	assert.Zero(t, content{retryDate: now.Add(-time.Hour)}.retryWait(now))

	// a date a moment away is still a wait of at least a second
	assert.Equal(t, time.Second, content{retryDate: now.Add(time.Millisecond)}.retryWait(now))
}

func TestLoadHTTPDefaultLimitAllowsABodyExactlyAtTheLimit(t *testing.T) {
	body := bytes.Repeat([]byte("k"), int(DefaultMaxResponseBytes))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()

	c, err := load(context.Background(), httpSource(server.URL), time.Time{})
	require.NoError(t, err)
	assert.Len(t, c.data, len(body))
}

func TestLoadHTTPDefaultLimitRejectsABodyOneByteOver(t *testing.T) {
	body := bytes.Repeat([]byte("k"), int(DefaultMaxResponseBytes)+1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()

	c, err := load(context.Background(), httpSource(server.URL), time.Time{})
	assert.ErrorIs(t, err, ErrResponseTooLarge)
	assert.Nil(t, c.data)
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
