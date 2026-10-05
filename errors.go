// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"errors"
	"fmt"
)

var (
	// ErrNoKeySources is returned by NewKeySetProvider when the KeySetConfig has
	// no sources.
	ErrNoKeySources = errors.New("at least one source is required")

	// ErrUnsupportedScheme is returned by NewKeySetProvider when a source URI is
	// not a file path or a file, http, or https URI.  That includes a source
	// whose URI cannot be parsed at all, since no supported scheme can be read
	// from it.  NewPerKeyProvider returns it for a template that is not http or
	// https.
	ErrUnsupportedScheme = errors.New("source URI scheme is not supported; use file, http, or https")

	// ErrMissingClient is returned by NewKeySetProvider when an http or https
	// source has no Client, and by NewPerKeyProvider when the config has none.
	// clortho does not supply one: the client decides the timeout, redirects,
	// TLS, and proxies, and those are the caller's to choose.
	ErrMissingClient = errors.New("an http or https source requires a Client")

	// ErrUnusedClient is returned by NewKeySetProvider when a file source has a
	// Client, which it would never use.  The usual cause is an http or https URI
	// written without its scheme, such as keys.example.com/jwks, which reads as a
	// file path.
	ErrUnusedClient = errors.New("a file source does not use a Client")

	// ErrInvalidTemplate is returned by NewPerKeyProvider when the URL template
	// cannot be used: it does not hold the {keyID} placeholder exactly once,
	// or holds it where a key ID could change which server is asked.
	ErrInvalidTemplate = errors.New("the URL template is not usable")

	// ErrInvalidKeyID marks a key ID that may not be put into a URL.  A key ID
	// is letters, digits, '-', '_', and '.', at most 128 characters, with no
	// "..".  NewPerKeyProvider returns it for such an ID in AllowedKeyIDs.  A
	// PerKeyProvider's FetchKeys returns it, together with ErrKeyNotFound, for
	// such an ID in a token, and makes no request.
	ErrInvalidKeyID = errors.New("key ID is not valid")

	// ErrNoAllowedKeyIDs is returned by NewPerKeyProvider when
	// AllowedKeyIDsOnly is set and AllowedKeyIDs is empty, since such a
	// provider could never fetch anything.
	ErrNoAllowedKeyIDs = errors.New("AllowedKeyIDsOnly requires at least one allowed key ID")

	// ErrKeyIDMismatch marks a key that carries a key ID other than the one it
	// was wanted under.  It is a fetch error when a server returns such a key
	// for the key ID it was asked for, and NewFixedKeyProvider returns it when
	// a fixed key written as a JWK carries a kid other than its FixedKey.KeyID.
	ErrKeyIDMismatch = errors.New("the key is not the one asked for")

	// ErrNoFixedKeys is returned by NewFixedKeyProvider when the config has no
	// keys.
	ErrNoFixedKeys = errors.New("at least one fixed key is required")

	// ErrInvalidFixedKey is returned by NewFixedKeyProvider when a fixed key's
	// text cannot be used: it is empty, it is neither PEM nor a JWK, it holds
	// more than one PEM block, or it does not parse.
	ErrInvalidFixedKey = errors.New("fixed key is not usable")

	// ErrAlreadyStarted is returned by Start when the KeySetProvider is already
	// running.
	ErrAlreadyStarted = errors.New("the provider has already been started")

	// ErrNotStarted is returned by Stop when the KeySetProvider is not running.
	ErrNotStarted = errors.New("the provider is not running")

	// ErrDuplicateKeyID is a refresh error: a source served a key ID that is
	// already on the ring from another source, or served the same key ID twice.
	// A KeySetProvider is one map, so a key ID names exactly one key; a
	// deployment that needs separate key spaces builds separate
	// KeySetProviders.  The refresh that would introduce the duplicate fails
	// and leaves the ring untouched.
	//
	// NewFixedKeyProvider returns it when two fixed keys are given the same
	// KeyID.
	ErrDuplicateKeyID = errors.New("key ID is already supplied by another source")

	// ErrMissingKeyID is returned by FetchKeys when the protected header has no
	// kid, and is a refresh error when a source serves a key with no kid.
	// NewFixedKeyProvider returns it for a fixed key with no KeyID.
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
