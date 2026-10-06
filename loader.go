// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// acceptHeader lists the formats a source may answer with, most specific
// first.  A server that routes on Accept, as themis does, sees a key set
// requested rather than whatever its default is.
const acceptHeader = "application/jwk-set+json, application/jwk+json, application/json;q=0.9"

// content is what one load of a source produced.
type content struct {
	// data is the body.  It is nil when notModified is set.
	data []byte

	// notModified is set when an HTTP source answered 304: the content the
	// KeySetProvider already has is still current.
	notModified bool

	// lastModified is the Last-Modified of an HTTP response, or the
	// modification time of a file.  Zero if unknown.
	lastModified time.Time

	// ttl is how long the server said the content is good for, from
	// Cache-Control max-age.  Zero if it did not say.
	ttl time.Duration

	// statusCode is the HTTP status, including on an HTTPError.  Zero for a
	// file source or when no response arrived.
	statusCode int

	// retryDelay and retryDate hold the Retry-After of a 429 or 503 response,
	// which is either a number of seconds or a date.  At most one is set.  Both
	// are zero for any other status, and when the header is missing or
	// invalid.  See retryWait.
	retryDelay time.Duration
	retryDate  time.Time
}

// minRetryAfter is the shortest wait taken from a Retry-After header.  A
// server may say zero, meaning at once; one second keeps the refresh loop
// from spinning against a server that says so on every response.
const minRetryAfter = time.Second

// retryWait returns how long the key set server asked clortho to wait before
// it tries again, measured from now, or zero if it did not ask.  A date that has
// already passed is treated as no instruction at all.
func (c content) retryWait(now time.Time) time.Duration {
	if c.retryDelay > 0 {
		return c.retryDelay
	}

	if c.retryDate.After(now) {
		return max(c.retryDate.Sub(now), minRetryAfter)
	}

	return 0
}

// load fetches a source once.  since, when non-zero, is the lastModified of
// the previous successful load and makes an HTTP request conditional.  The
// source must have been normalized by NewKeySetProvider.
func load(ctx context.Context, src RefreshSource, since time.Time) (content, error) {
	if isHTTP(src.URI) {
		return loadHTTP(ctx, httpGet{
			client:   src.Client,
			uri:      src.URI,
			accept:   acceptHeader,
			since:    since,
			maxBytes: src.MaxResponseBytes,
		})
	}

	return loadFile(src.URI)
}

// filePath converts a file URI or bare path into a path.
func filePath(uri string) string {
	if u, err := url.Parse(uri); err == nil && u.Scheme == "file" {
		return u.Path
	}

	return uri
}

func loadFile(uri string) (content, error) {
	path := filePath(uri)
	fi, err := os.Stat(path)
	if err != nil {
		return content{}, err
	}

	if !fi.Mode().IsRegular() {
		return content{}, fmt.Errorf("%s is not a regular file", redactURI(uri))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return content{}, err
	}

	return content{data: data, lastModified: fi.ModTime()}, nil
}

// httpGet is one GET request for key material: who sends it, where, what it
// asks for, and how much of the answer it will read.
type httpGet struct {
	client *http.Client
	uri    string

	// accept is the Accept header to send.
	accept string

	// since, when non-zero, makes the request conditional on the content
	// having changed since then.
	since time.Time

	// maxBytes caps the body read.
	maxBytes int64
}

func loadHTTP(ctx context.Context, get httpGet) (content, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, get.uri, nil)
	if err != nil {
		return content{}, err
	}

	req.Header.Set("Accept", get.accept)
	if !get.since.IsZero() {
		req.Header.Set("If-Modified-Since", get.since.UTC().Format(http.TimeFormat))
	}

	resp, err := get.client.Do(req)
	if err != nil {
		return content{}, err
	}

	defer func() {
		// drain what is left so the connection can be reused.  a failure here is
		// irrelevant, since the body is about to be closed anyway.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, get.maxBytes))
		resp.Body.Close()
	}()

	c := content{statusCode: resp.StatusCode}
	switch resp.StatusCode {
	case http.StatusNotModified:
		c.notModified = true

	case http.StatusOK:
		// read one byte past the limit: that is what distinguishes a body exactly
		// at the limit from one that exceeds it, and works for a chunked body
		// with no Content-Length.
		c.data, err = io.ReadAll(io.LimitReader(resp.Body, get.maxBytes+1))
		if err != nil {
			return c, err
		}

		if int64(len(c.data)) > get.maxBytes {
			c.data = nil
			return c, fmt.Errorf("%w: %s allows %d bytes", ErrResponseTooLarge, redactURI(get.uri), get.maxBytes)
		}

	default:
		// these two statuses are how a server asks for a pause, and Retry-After
		// is where it says for how long
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
			c.retryDelay, c.retryDate = parseRetryAfter(resp.Header.Get("Retry-After"))
		}

		return c, &HTTPError{Location: redactURI(get.uri), StatusCode: resp.StatusCode}
	}

	c.lastModified = parseLastModified(resp.Header.Get("Last-Modified"))
	c.ttl = parseMaxAge(resp.Header.Get("Cache-Control"))
	return c, nil
}

// parseLastModified treats an invalid Last-Modified as missing.
func parseLastModified(value string) time.Time {
	if value == "" {
		return time.Time{}
	}

	t, err := http.ParseTime(value)
	if err != nil {
		return time.Time{}
	}

	return t
}

// parseRetryAfter reads a Retry-After header, which is either a number of
// seconds or an HTTP date.  A number is returned as delay, raised to
// minRetryAfter if it is shorter, and a date as date.  An invalid value,
// including a negative number, is treated as absent: both results are zero.
func parseRetryAfter(value string) (delay time.Duration, date time.Time) {
	value = strings.TrimSpace(value)
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		switch {
		case seconds < 0:
			return 0, time.Time{}

		case seconds > math.MaxInt64/int64(time.Second):
			// too long to hold in a Duration.  the wait is capped at the source's
			// maximum before it is used, so the longest Duration stands in for it.
			return math.MaxInt64, time.Time{}
		}

		return max(time.Duration(seconds)*time.Second, minRetryAfter), time.Time{}
	}

	if date, err := http.ParseTime(value); err == nil {
		return 0, date
	}

	return 0, time.Time{}
}

// parseMaxAge extracts max-age from a Cache-Control header.  An invalid
// directive, including a negative value or one too large to hold in a
// Duration, is treated as absent.
func parseMaxAge(cacheControl string) time.Duration {
	for directive := range strings.SplitSeq(cacheControl, ",") {
		name, value, _ := strings.Cut(directive, "=")
		if strings.TrimSpace(name) != "max-age" {
			continue
		}

		seconds, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		if err != nil || seconds < 0 || seconds > math.MaxInt64/int64(time.Second) {
			return 0
		}

		// only the first max-age counts, in case of duplicates
		return time.Duration(seconds) * time.Second
	}

	return 0
}
