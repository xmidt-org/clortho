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
	// Provider already has is still current.
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
}

// load fetches a source once.  since, when non-zero, is the lastModified of
// the previous successful load and makes an HTTP request conditional.  The
// source must have been normalized by New.
func load(ctx context.Context, src RefreshSource, since time.Time) (content, error) {
	if isHTTP(src.URI) {
		return loadHTTP(ctx, src, since)
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

func loadHTTP(ctx context.Context, src RefreshSource, since time.Time) (content, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URI, nil)
	if err != nil {
		return content{}, err
	}

	req.Header.Set("Accept", acceptHeader)
	if !since.IsZero() {
		req.Header.Set("If-Modified-Since", since.UTC().Format(http.TimeFormat))
	}

	resp, err := src.Client.Do(req)
	if err != nil {
		return content{}, err
	}

	defer func() {
		// drain what is left so the connection can be reused.  a failure here is
		// irrelevant, since the body is about to be closed anyway.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, src.MaxResponseBytes))
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
		c.data, err = io.ReadAll(io.LimitReader(resp.Body, src.MaxResponseBytes+1))
		if err != nil {
			return c, err
		}

		if int64(len(c.data)) > src.MaxResponseBytes {
			c.data = nil
			return c, fmt.Errorf("%w: %s allows %d bytes", ErrResponseTooLarge, redactURI(src.URI), src.MaxResponseBytes)
		}

	default:
		return c, &HTTPError{Location: redactURI(src.URI), StatusCode: resp.StatusCode}
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
