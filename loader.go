/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package clortho

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/multierr"
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
	LoadContent(ctx context.Context, location string, meta ContentMeta) ([]byte, ContentMeta, error)
}

// NewLoader builds a Loader from a set of options.
//
// By default, the returned Loader handles http, https, and file locations.  The default
// loader, when there is no scheme, is a file loader.
func NewLoader(options ...LoaderOption) (Loader, error) {
	var (
		err error

		hl = HTTPLoader{
			Client: http.DefaultClient,
		}

		fl = FileLoader{
			Root: os.DirFS("/"),
		}

		ls = &loaders{
			l: map[string]Loader{
				"http":  hl,
				"https": hl,
				"file":  fl,
				"":      fl, // the default, when no scheme is present in the URI
			},
		}
	)

	for _, o := range options {
		err = multierr.Append(err, o.applyToLoaders(ls))
	}

	return ls, err
}

// loaders is the primary, internal implementation of the Loader interface.  This type dispatches
// to Loaders based on scheme in the URI.
type loaders struct {
	l map[string]Loader
}

func (ls *loaders) LoadContent(ctx context.Context, location string, meta ContentMeta) ([]byte, ContentMeta, error) {
	var (
		l  Loader
		ok bool
	)

	// optimization: rather than do a full parse, just split on ':'
	if p := strings.IndexByte(location, ':'); p > 0 {
		l, ok = ls.l[location[0:p]]
	} else {
		l, ok = ls.l[""] // default
	}

	if ok {
		return l.LoadContent(ctx, location, meta)
	}

	return nil, meta, &UnsupportedSchemeError{
		Location: location,
	}
}

type HTTPLoader struct {
	Client   HTTPClient
	Encoders []HTTPEncoder
	Timeout  time.Duration
}

func nopCancel() {}

func (hl *HTTPLoader) newContext(parentCtx context.Context) (context.Context, context.CancelFunc) {
	if hl.Timeout > 0 {
		return context.WithTimeout(parentCtx, hl.Timeout)
	}

	return parentCtx, nopCancel
}

func (hl *HTTPLoader) newRequest(ctx context.Context, location string, meta ContentMeta) (request *http.Request, err error) {
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	for i := 0; err == nil && i < len(hl.Encoders); i++ {
		err = hl.Encoders[i](ctx, request)
	}

	// an encoder is allowed to change the HTTP method, so we guard against sending
	// conditional headers for methods other than those that support them
	if err == nil && (request.Method == http.MethodGet || request.Method == http.MethodHead) {
		if !meta.LastModified.IsZero() {
			request.Header.Set("If-Modified-Since", meta.LastModified.Format(time.RFC1123))
		}
	}

	return
}

func (hl *HTTPLoader) transact(request *http.Request, meta ContentMeta) (response *http.Response, data []byte, err error) {
	client := hl.Client
	if client == nil {
		client = http.DefaultClient
	}

	response, err = client.Do(request)
	if err != nil {
		return
	}

	defer func() {
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		response.Body = nil
	}()

	switch response.StatusCode {
	case http.StatusNotModified:
		// because we honor the Last-Modified header, the server
		// can legitimately response with this status code.  we can
		// just ignore anything in the body.

	case http.StatusOK:
		// NOTE: Content-Length is required for HTTP/1.1+
		// we explicitly require that header here
		cl := response.ContentLength
		if cl > 0 {
			data = make([]byte, cl)
			_, err = io.ReadFull(response.Body, data)
		}

	default:
		err = &HTTPLoaderError{
			Location:   response.Request.URL.String(),
			StatusCode: response.StatusCode,
		}
	}

	return
}

func (hl *HTTPLoader) newMeta(response *http.Response) (meta ContentMeta) {
	meta.Format = response.Header.Get("Content-Type")
	var err error

	if lastModified := response.Header.Get("Last-Modified"); len(lastModified) > 0 {
		meta.LastModified, err = time.Parse(time.RFC1123, lastModified)
		if err != nil {
			// treat an invalid Last-Modified as if it were missing
			meta.LastModified = time.Time{}
		}
	}

	// Cache-Control takes precedence over Expires, even if Cache-Control was invalid for some reason
	if cacheControl := response.Header.Get("Cache-Control"); len(cacheControl) > 0 {
		for _, cacheDirective := range strings.Split(cacheControl, ",") {
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

	return
}

func (hl HTTPLoader) LoadContent(ctx context.Context, location string, meta ContentMeta) ([]byte, ContentMeta, error) {
	requestCtx, cancel := hl.newContext(ctx)
	defer cancel()

	request, err := hl.newRequest(requestCtx, location, meta)
	if err != nil {
		return nil, meta, err
	}

	response, data, err := hl.transact(request, meta)
	if err != nil {
		return nil, meta, err
	}

	return data, hl.newMeta(response), nil
}

type FileLoader struct {
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

func (fl FileLoader) LoadContent(_ context.Context, location string, meta ContentMeta) ([]byte, ContentMeta, error) {
	path, err := fl.toPath(location)
	if err != nil {
		return nil, meta, err
	}

	fi, err := fs.Stat(fl.Root, path)
	if err != nil {
		return nil, meta, err
	}

	data, err := fl.readContent(location, path, fi)
	if err != nil {
		return nil, meta, err
	}

	return data, fl.newMeta(path, fi), nil
}
