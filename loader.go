// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// userinfoPassword matches the password of a URI's userinfo in text, for
// strings that url.Parse rejects, such as a template with braces in its host.
var userinfoPassword = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*://[^/?#@]*:)[^/?#@]*@`)

// redactURI returns location with any userinfo password replaced by "xxxxx",
// as url.URL.Redacted does.  A location that does not parse is redacted
// textually instead, so that a malformed template or an unparseable expansion
// still does not leak a password.  Errors and events carry redacted locations
// so that a source configured with credentials in its URI does not put them in
// logs.
func redactURI(location string) string {
	if u, err := url.Parse(location); err == nil {
		// leave a location with nothing to redact exactly as written, rather than
		// re-encoding it
		if _, hasPassword := u.User.Password(); !hasPassword {
			return location
		}

		return u.Redacted()
	}

	return userinfoPassword.ReplaceAllString(location, "${1}xxxxx@")
}

// ErrInvalidLocation indicates that a location could not be parsed as a URL and
// so no request was made for it.  The message quotes the location with any
// password redacted.
var ErrInvalidLocation = errors.New("location is not a valid URL")

// UnsupportedSchemeError indicates that a URI's scheme was not registered
// and couldn't be handled by a Loader.  Location has any password redacted.
type UnsupportedSchemeError struct {
	Location string
}

func (use *UnsupportedSchemeError) Error() string {
	return fmt.Sprintf("Scheme is not supported for location: %s", use.Location)
}

// NotAFileError indicates that a file URI didn't refer to a system file, but instead
// referred to a directory, pipe, etc.  Location has any password redacted.
type NotAFileError struct {
	Location string
}

func (nafe *NotAFileError) Error() string {
	return fmt.Sprintf("Location does not refer to a file: %s", nafe.Location)
}

// HTTPLoaderError indicates that an error occurred when transacting with a HTTP-based
// source of key material.  Location has any password redacted.
type HTTPLoaderError struct {
	Location   string
	StatusCode int
}

func (hle *HTTPLoaderError) Error() string {
	return fmt.Sprintf("Status code %d received from %s", hle.StatusCode, hle.Location)
}

// ContentMeta holds metadata about a piece of content.
type ContentMeta struct {
	// Format describes the type of key content.  This will typically be either
	// a file suffix (e.g. .pem, .jwk) or a media type (e.g. application/json, application/json+jwk).
	// A custom Loader is free to produce its own format values, which must be
	// understood by a corresponding Parser.
	Format string

	// TTL is the length of time this content is considered current.  A Refresher will
	// use this value to determine when to load content again.
	TTL time.Duration

	// LastModified is the modification timestamp of the content.  For files, this will be
	// the FileInfo.ModTime() value.  For HTTP responses, this will be the Last-Modified header.
	//
	// In the case of HTTP, this field is also used to supply a Last-Modified header in the
	// request.
	LastModified time.Time
}

// HTTPClient is the minimal interface required by a component which can handle
// HTTP transactions with a server.  *http.Client implements this interface.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// ErrNilHTTPClient is returned by NewLoader when WithHTTPClient is given a nil client.
var ErrNilHTTPClient = errors.New("WithHTTPClient requires a non-nil client")

// newDefaultHTTPClient returns the client an HTTPLoader uses when none is set.
// It does not follow redirects.  A redirect lets the server, rather than the
// configured location, decide where key material comes from, so the redirect
// response is handed back as is and surfaces as an HTTPLoaderError with its
// 3xx status.  The client shares the process's default transport, so
// connection pooling is unaffected; only the redirect policy differs from
// http.DefaultClient, along with not being a global that other packages can
// alter.
func newDefaultHTTPClient() *http.Client {
	return &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// HTTPEncoder is a strategy closure type for modifying an HTTP request
// prior to issuing it through a client.
type HTTPEncoder func(context.Context, *http.Request) error

// Loader handles the retrieval of content from an external location.
type Loader interface {
	// LoadContent retrieves the key content from location.  Location must be a URL parseable
	// with url.Parse.
	//
	// This method returns a ContentMeta describing useful characteristics of the content, mostly around
	// caching.  This returned metadata can be passed to subsequent calls to make key retrieval more
	// efficient.
	LoadContent(ctx context.Context, location string) ([]byte, ContentMeta, error)
}

// NewLoader builds a Loader from a set of options.
//
// By default, the returned Loader handles http, https, and file locations.  The default
// loader, when there is no scheme, is a file loader.  The http and https loaders do not
// follow redirects; see WithHTTPClient to supply a client that does.
func NewLoader(options ...LoaderOption) (Loader, error) {
	ls := defaultLoader()

	errs := make([]error, 0, len(options))
	for _, o := range options {
		errs = append(errs, o.applyToLoaders(ls))
	}

	return ls, errors.Join(errs...)
}

func defaultLoader() *loaders {
	hl := HTTPLoader{
		Client:       newDefaultHTTPClient(),
		MaxReadLimit: int64(1 * 1024 * 25),
		Timeout:      30 * time.Second,
	}

	fl := FileLoader{
		Root: os.DirFS("/"),
	}

	return &loaders{
		l: map[string]Loader{
			"http":  hl,
			"https": hl,
			"file":  fl,
			"":      fl, // the default, when no scheme is present in the URI
		},
	}
}

// loaders is the primary, internal implementation of the Loader interface.  This type dispatches
// to Loaders based on scheme in the URI.
type loaders struct {
	l map[string]Loader
}

func (ls *loaders) LoadContent(ctx context.Context, location string) ([]byte, ContentMeta, error) {
	k := ""
	// optimization: rather than do a full parse, just split on ':'
	if p := strings.IndexByte(location, ':'); p > 0 {
		k = location[0:p]
	}

	if l, ok := ls.l[k]; ok {
		return l.LoadContent(ctx, location)
	}

	return nil, ContentMeta{}, &UnsupportedSchemeError{
		Location: redactURI(location),
	}
}

// HTTPLoader is a Loader strategy for obtaining content from HTTP servers.
type HTTPLoader struct {
	// Client is the HTTP client used to transact with HTTP servers.  If unset, a
	// client that does not follow redirects is used.  To follow redirects, supply
	// an *http.Client with a CheckRedirect of your own, or a plain &http.Client{}
	// for the net/http default of up to ten.
	Client HTTPClient

	// Encoders holds an optional slice of HTTPEncoder instances that are used
	// to modify requests prior to sending them to the Client.
	Encoders []HTTPEncoder

	// Timeout is an optional timeout for each HTTP operation.  If unset,
	// no timeout is used.
	Timeout time.Duration

	// MaxReadLimit limits how many bytes are read from responses.  A body larger
	// than this results in a ResponseTooLargeError.  If unset, no limit is applied.
	MaxReadLimit int64
}

// readLimit returns the effective read limit, treating an unset MaxReadLimit as
// unlimited.  The unlimited value leaves room for the one extra byte transact
// reads to detect an oversized body.
func (hl *HTTPLoader) readLimit() int64 {
	if hl.MaxReadLimit > 0 {
		return hl.MaxReadLimit
	}

	return math.MaxInt64 - 1
}

// client returns the configured client, or the no-redirect default when none was set.
func (hl *HTTPLoader) client() HTTPClient {
	if hl.Client != nil {
		return hl.Client
	}

	return newDefaultHTTPClient()
}

func (hl *HTTPLoader) newContext(parentCtx context.Context) (context.Context, context.CancelFunc) {
	if hl.Timeout > 0 {
		return context.WithTimeout(parentCtx, hl.Timeout)
	}

	return parentCtx, func() {}
}

func (hl *HTTPLoader) newRequest(ctx context.Context, location string) (*http.Request, error) {
	// parse first: the standard library's error quotes the raw location, which
	// may carry a password
	u, err := url.Parse(location)
	if err != nil {
		return nil, fmt.Errorf("%w: %q", ErrInvalidLocation, redactURI(location))
	}

	// with the URL already parsed, the only remaining failure is a nil context,
	// whose error does not mention the URL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}

	for i := range hl.Encoders {
		if err := hl.Encoders[i](ctx, req); err != nil {
			return nil, err
		}
	}

	// an encoder is allowed to change the HTTP method, so we guard against sending
	// conditional headers for methods other than those that support them
	switch req.Method {
	case http.MethodGet, http.MethodHead:
	default:
		return req, nil
	}
	// a context with no ContentMeta is an ordinary first request: there is no
	// previous response to be conditional about, so the zero value is exactly right.
	// The Refresher seeds this value between refreshes; the Resolver and direct
	// callers do not, and must not have to.
	meta, _ := GetContentMeta(ctx)
	if !meta.LastModified.IsZero() {
		req.Header.Set("If-Modified-Since", meta.LastModified.Format(time.RFC1123))
	}

	return req, nil
}

func (hl *HTTPLoader) transact(req *http.Request) (*http.Response, []byte, error) {
	resp, err := hl.client().Do(req)
	if err != nil {
		return nil, nil, err
	}

	defer func() {
		// drain the body so the connection can be reused.  a failure here is
		// irrelevant, since the body is about to be closed anyway.
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, hl.readLimit()))
		resp.Body.Close()
		resp.Body = nil
	}()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// because we honor the Last-Modified header, the server
		// can legitimately response with this status code.  we can
		// just ignore anything in the body.

	case http.StatusOK:
		// read the body regardless of Content-Length, since a chunked response
		// has none.  reading one byte past the limit is what distinguishes a body
		// that is exactly at the limit from one that exceeds it.
		limit := hl.readLimit()
		data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, nil, err
		}

		if int64(len(data)) > limit {
			return nil, nil, &ResponseTooLargeError{
				Location: resp.Request.URL.Redacted(),
				Limit:    limit,
			}
		}

		return resp, data, nil

	default:
		return nil, nil, &HTTPLoaderError{
			Location:   resp.Request.URL.Redacted(),
			StatusCode: resp.StatusCode,
		}
	}

	return resp, nil, nil
}

func (hl *HTTPLoader) newMeta(resp *http.Response) ContentMeta {
	meta := ContentMeta{Format: resp.Header.Get("Content-Type")}
	if lastModified := resp.Header.Get("Last-Modified"); len(lastModified) > 0 {
		// treat an invalid Last-Modified as if it were missing
		if lm, err := time.Parse(time.RFC1123, lastModified); err == nil {
			meta.LastModified = lm
		}
	}

	// Cache-Control takes precedence over Expires, even if Cache-Control was invalid for some reason
	if cacheControl := resp.Header.Get("Cache-Control"); len(cacheControl) > 0 {
		for cacheDirective := range strings.SplitSeq(cacheControl, ",") {
			nv := strings.Split(cacheDirective, "=")
			if strings.TrimSpace(nv[0]) == "max-age" && len(nv) > 1 {
				// ignore an invalid max-age directive, just treat it as if there were no
				// Cache-Control header.  that includes a negative value and one too large
				// to hold in a time.Duration, which would otherwise wrap to a negative TTL.
				if seconds, err := strconv.ParseInt(strings.TrimSpace(nv[1]), 10, 64); err == nil {
					if seconds >= 0 && seconds <= math.MaxInt64/int64(time.Second) {
						meta.TTL = time.Duration(seconds) * time.Second
					}
				}

				// only use the first max-age directive, in case of duplicates
				break
			}
		}
	}

	return meta
}

func (hl HTTPLoader) LoadContent(ctx context.Context, location string) ([]byte, ContentMeta, error) {
	reqCtx, cancel := hl.newContext(ctx)
	defer cancel()

	req, err := hl.newRequest(reqCtx, location)
	if err != nil {
		return nil, ContentMeta{}, err
	}

	// nolint: bodyclose
	// Body already closed in hl.transact
	resp, data, err := hl.transact(req)
	if err != nil {
		return nil, ContentMeta{}, err
	}

	return data, hl.newMeta(resp), nil
}

// FileLoader is a Loader implementation that reads content from a file system.
// All location paths are relative to a supplied root.
type FileLoader struct {
	// Root is the relative root against which all location paths are resolved.
	// This field is required.
	//
	// The Loader created by NewLoader uses os.DirFS("/") for this field, so
	// that absolute paths and file:// URIs resolve naturally.
	Root fs.FS
}

func (fl *FileLoader) toPath(location string) (string, error) {
	u, err := url.Parse(location)
	if err != nil {
		return "", err
	}

	// paths passed to an FS cannot begin or end with slashes.
	// however, we want to allow natural locations, such as /var/foo/key.pem,
	// resolved against a root FS.
	path := filepath.Clean(u.Path)
	if path[0] == filepath.Separator {
		path = path[1:]
	}

	return path, nil
}

func (fl *FileLoader) readContent(location, path string, fi fs.FileInfo) ([]byte, error) {
	// an FS doesn't complain if several non-regular file types are read
	if fi.Mode()&fs.ModeType != 0 {
		return nil, &NotAFileError{
			Location: redactURI(location), // use location instead of path, since that will help debugging
		}
	}

	return fs.ReadFile(fl.Root, path)
}

func (fl *FileLoader) newMeta(path string, fi fs.FileInfo) (meta ContentMeta) {
	meta.Format = filepath.Ext(path)
	meta.LastModified = fi.ModTime()
	return
}

func (fl FileLoader) LoadContent(ctx context.Context, location string) ([]byte, ContentMeta, error) {
	path, err := fl.toPath(location)
	if err != nil {
		return nil, ContentMeta{}, err
	}

	fi, err := fs.Stat(fl.Root, path)
	if err != nil {
		return nil, ContentMeta{}, err
	}

	data, err := fl.readContent(location, path, fi)
	if err != nil {
		return nil, ContentMeta{}, err
	}

	return data, fl.newMeta(path, fi), nil
}

// ResponseTooLargeError indicates that an HTTP response body exceeded the
// loader's MaxReadLimit.  Location has any password redacted.
type ResponseTooLargeError struct {
	Location string
	Limit    int64
}

func (rtle *ResponseTooLargeError) Error() string {
	return fmt.Sprintf("Response from %s exceeded the read limit of %d bytes", rtle.Location, rtle.Limit)
}
