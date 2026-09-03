// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/multierr"
)

var (
	errNoContentMeta = errors.New("previous request metadata was not found")
)

// UnsupportedSchemeError indicates that a URI's scheme was not registered
// and couldn't be handled by a Loader.
type UnsupportedSchemeError struct {
	Location string
}

func (use *UnsupportedSchemeError) Error() string {
	return fmt.Sprintf("Scheme is not supported for location: %s", use.Location)
}

// NotAFileError indicates that a file URI didn't refer to a system file, but instead
// referred to a directory, pipe, etc.
type NotAFileError struct {
	Location string
}

func (nafe *NotAFileError) Error() string {
	return fmt.Sprintf("Location does not refer to a file: %s", nafe.Location)
}

// HTTPLoaderError indicates that an error occurred when transacting with a HTTP-based
// source of key material.
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
// loader, when there is no scheme, is a file loader.
func NewLoader(options ...LoaderOption) (Loader, error) {
	ls := defaultLoader()

	var errs error
	for _, o := range options {
		errs = multierr.Append(errs, o.applyToLoaders(ls))
	}

	return ls, errs
}

func defaultLoader() *loaders {
	hl := HTTPLoader{
		Client:       http.DefaultClient,
		MaxReadLimit: int64(1 * 1024 * 25),
		Timeout:      200 * time.Millisecond,
	}

	return &loaders{
		l: map[string]Loader{
			"http":  hl,
			"https": hl,
			"":      hl, // the default, when no scheme is present in the URI
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
		Location: location,
	}
}

// HTTPLoader is a Loader strategy for obtaining content from HTTP servers.
type HTTPLoader struct {
	// Client is the HTTP client used to transact with HTTP servers.
	// If unset, http.DefaultClient is used.
	Client HTTPClient

	// Encoders holds an optional slice of HTTPEncoder instances that are used
	// to modify requests prior to sending them to the Client.
	Encoders []HTTPEncoder

	// Timeout is an optional timeout for each HTTP operation.  If unset,
	// no timeout is used.
	Timeout time.Duration

	// MaxReadLimit limits how many bytes are read from responses.
	MaxReadLimit int64
}

func (hl *HTTPLoader) newContext(parentCtx context.Context) (context.Context, context.CancelFunc) {
	if hl.Timeout > 0 {
		return context.WithTimeout(parentCtx, hl.Timeout)
	}

	return parentCtx, func() {}
}

func (hl *HTTPLoader) newRequest(ctx context.Context, location string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
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
	meta, ok := GetContentMeta(ctx)
	if !ok {
		panic(errNoContentMeta)
	}

	if !meta.LastModified.IsZero() {
		req.Header.Set("If-Modified-Since", meta.LastModified.Format(time.RFC1123))
	}

	return req, nil
}

func (hl *HTTPLoader) transact(req *http.Request) (*http.Response, []byte, error) {
	resp, err := hl.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}

	defer func() {
		io.Copy(io.Discard, io.LimitReader(resp.Body, hl.MaxReadLimit))
		resp.Body.Close()
		resp.Body = nil
	}()

	switch resp.StatusCode {
	case http.StatusNotModified:
		// because we honor the Last-Modified header, the server
		// can legitimately response with this status code.  we can
		// just ignore anything in the body.

	case http.StatusOK:
		// NOTE: Content-Length is required for HTTP/1.1+
		// we explicitly require that header here
		cl := resp.ContentLength
		if cl > 0 {
			data := make([]byte, cl)
			_, err = io.ReadFull(io.LimitReader(resp.Body, hl.MaxReadLimit), data)

			return resp, data, err
		}

	default:
		return nil, nil, &HTTPLoaderError{
			Location:   resp.Request.URL.String(),
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
				// ignore an invalid max-age directive, just treat it as if there were no Cache-Control header
				if seconds, err := strconv.Atoi(nv[1]); err == nil {
					meta.TTL = time.Duration(seconds) * time.Second
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
			Location: location, // use location instead of path, since that will help debugging
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
