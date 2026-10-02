// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"errors"
	"fmt"
)

var (
	// ErrNoKeySources is returned by New when the Config has no sources.
	ErrNoKeySources = errors.New("at least one source is required")

	// ErrUnsupportedScheme is returned by New when a source URI is not a file
	// path or a file, http, or https URI.
	ErrUnsupportedScheme = errors.New("source URI scheme is not supported; use file, http, or https")

	// ErrAlreadyStarted is returned by Start when the Provider is already running.
	ErrAlreadyStarted = errors.New("the provider has already been started")

	// ErrNotStarted is returned by Stop when the Provider is not running.
	ErrNotStarted = errors.New("the provider is not running")

	// ErrDuplicateKeyID is a refresh error: a source served a key ID that is
	// already on the ring from another source, or served the same key ID twice.
	// A Provider is one map, so a key ID names exactly one key; a deployment
	// that needs separate key spaces builds separate Providers.  The refresh
	// that would introduce the duplicate fails and leaves the ring untouched.
	ErrDuplicateKeyID = errors.New("key ID is already supplied by another source")

	// ErrMissingKeyID is returned by FetchKeys when the protected header has no
	// kid, and is a refresh error when a source serves a key with no kid.
	ErrMissingKeyID = errors.New("no key ID")

	// ErrSymmetricKey is a refresh error: a source served a symmetric (oct)
	// key.  Such keys are never accepted, since a secret published in a key set
	// is known to everyone who fetched it.  The refresh fails and leaves the
	// ring untouched.
	ErrSymmetricKey = errors.New("symmetric keys are not accepted")

	// ErrResponseTooLarge is a refresh error: an HTTP response body exceeded
	// the source's MaxResponseBytes.
	ErrResponseTooLarge = errors.New("response body exceeds the source's maximum")

	// ErrKeyNotFound is returned by FetchKeys when no key on the ring has the
	// protected header's kid.
	ErrKeyNotFound = errors.New("no key with that key ID")

	// ErrMissingAlgorithm is returned by FetchKeys when the protected header has
	// no alg.
	ErrMissingAlgorithm = errors.New(`protected header must contain an "alg" field`)

	// ErrKeyUsage is returned by FetchKeys when the key's "use" member is set to
	// something other than "sig".  See VerifyConfig.IgnoreKeyUsage.
	ErrKeyUsage = errors.New("key is not marked for signature use")

	// ErrKeyAlgorithm is returned by FetchKeys when the key's "alg" member is set
	// and does not match the protected header's alg.  See
	// VerifyConfig.IgnoreKeyAlgorithm.
	ErrKeyAlgorithm = errors.New("key algorithm does not match the protected header")
)

// HTTPError is a refresh error: an http or https source answered with a status
// other than 200 or 304.  Location has any password redacted.
type HTTPError struct {
	Location   string
	StatusCode int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("status code %d received from %s", e.StatusCode, e.Location)
}
