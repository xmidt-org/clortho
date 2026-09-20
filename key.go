// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"errors"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// Thumbprinter is implemented by anything that can produce a secure thumbprint of itself.
type Thumbprinter interface {
	// Thumbprint produces the RFC 7638 thumbprint hash, using the supplied algorithm.  The
	// typical value to pass to this method is crypto.SHA256.
	//
	// The returned byte slice contains the raw bytes of the hash.  To convert it to a string
	// conforming to RFC 7638, use base64.RawURLEncoding.EncodeToString.
	Thumbprint(crypto.Hash) ([]byte, error)
}

// Key is the minimal interface for cryptographic keys.  Once created, a Key is immutable.
type Key interface {
	Thumbprinter

	// KeyID is the identifier for this Key.  This method corresponds to the kid field of a JWK.
	// Note that a KeyID is entirely optional.  This method can return the empty string.
	KeyID() string

	// KeyType is the type of this Key, e.g. EC, RSA, etc.  This method corresponds to
	// the kty field of a JWK.
	//
	// A KeyType is required.  This method always returns a non-empty string.
	KeyType() string

	// KeyUsage describes how this key is allowed to be used.  This method corresponds to
	// the use field of a JWK.
	//
	// A KeyUsage is optional.  This method can return the empty string.
	KeyUsage() string

	// Raw is the raw key, e.g. *rsa.PublicKey, *rsa.PrivateKey, etc.  This is the actual underlying
	// cryptographic key that should be used.
	Raw() any

	// Public is the public portion of the raw key.  If this key is already a public key, this method
	// returns the same key as Raw.
	Public() crypto.PublicKey
}

type key struct {
	Thumbprinter
	keyID    string
	keyType  string
	keyUsage string
	raw      any
	public   crypto.PublicKey

	// keyIDGenerated records that keyID was assigned by EnsureKeyID rather than
	// present in the source material.  A Resolver uses it to tell a key that has
	// a different kid from one that never had a kid at all.
	keyIDGenerated bool
}

// keyIDOverride gives a Key implementation other than this package's own a
// different key ID, leaving everything else to the wrapped Key.  It is how
// EnsureKeyID assigns a thumbprint to a custom Parser's key, and how a Resolver
// adopts such a key under a requested kid, without knowing the key's type.
type keyIDOverride struct {
	Key
	keyID     string
	generated bool
}

func (ko keyIDOverride) KeyID() string { return ko.keyID }

// keyIDGenerated reports whether k's key ID was assigned by EnsureKeyID.  For a
// Key implementation this package has never touched, the answer is false: its
// kid is taken to be authoritative.
func keyIDGenerated(k Key) bool {
	switch kk := k.(type) {
	case *key:
		return kk.keyIDGenerated

	case keyIDOverride:
		return kk.generated
	}

	return false
}

// withKeyID returns a copy of k carrying the given key ID, marked as not
// generated.  This package's own keys are cloned; any other Key is wrapped.
func withKeyID(k Key, keyID string) Key {
	return replaceKeyID(k, keyID, false)
}

// replaceKeyID is withKeyID with control over the generated marker.
func replaceKeyID(k Key, keyID string, generated bool) Key {
	switch kk := k.(type) {
	case *key:
		clone := new(key)
		*clone = *kk
		clone.keyID = keyID
		clone.keyIDGenerated = generated
		return clone

	case keyIDOverride:
		// re-wrap the original rather than nesting wrappers
		return keyIDOverride{Key: kk.Key, keyID: keyID, generated: generated}
	}

	return keyIDOverride{Key: k, keyID: keyID, generated: generated}
}

func (k *key) KeyID() string            { return k.keyID }
func (k *key) KeyType() string          { return k.keyType }
func (k *key) KeyUsage() string         { return k.keyUsage }
func (k *key) Raw() any                 { return k.raw }
func (k *key) Public() crypto.PublicKey { return k.public }
func (k *key) String() string           { return k.keyID }

func convertJWKKey(jk jwk.Key) (Key, error) {
	keyID, ok := jk.KeyID()
	if !ok {
		keyID = ""
	}

	keyUsage, ok := jk.KeyUsage()
	if !ok {
		keyUsage = ""
	}

	k := &key{
		Thumbprinter: jk,
		keyID:        keyID,
		keyType:      jk.KeyType().String(),
		keyUsage:     keyUsage,
	}

	var err error
	if k.raw, err = jwk.Export[any](jk); err != nil {
		return nil, err
	}

	type publicer interface {
		Public() crypto.PublicKey
	}

	switch rt := k.raw.(type) {
	case publicer:
		// save a bit of memory by storing a reference to the raw key's public key
		k.public = rt.Public()

	case *rsa.PublicKey:
		k.public = rt

	case *ecdsa.PublicKey:
		k.public = rt

	default:
		// fallback to just making a copy of the public key, since we
		// don't know how to handle it.  this default case will also
		// get executed for octet keys, which makes a safe copy of the
		// public key.
		if pub, err := jk.PublicKey(); err != nil {
			return nil, err
		} else if k.public, err = jwk.Export[any](pub); err != nil {
			return nil, err
		}
	}

	return k, nil
}

func appendJWKKey(jk jwk.Key, keys []Key) ([]Key, error) {
	k, err := convertJWKKey(jk)
	if err == nil {
		keys = append(keys, k)
	}

	return keys, err
}

func appendJWKSet(js jwk.Set, keys []Key) ([]Key, error) {
	var errs []error
	for i := 0; i < js.Len(); i++ {
		jk, _ := js.Key(i)
		var keyErr error
		keys, keyErr = appendJWKKey(jk, keys)
		errs = append(errs, keyErr)
	}

	return keys, errors.Join(errs...)
}

// EnsureKeyID conditionally assigns a key ID to a given key.  The updated
// Key is returned, along with any error from the hash.
//
// If k already has a key ID, it is returned as is with no error.
//
// If k does not have a key ID, a thumbprint is generated using the supplied
// hash.  The returned key will be a copy of k with the newly generated key ID,
// and it remembers that the key ID was generated, which a Resolver relies on.
// A Key implementation other than this package's own is wrapped rather than
// copied; everything but its key ID is still served by the original, but the
// returned value is the wrapper, so a type assertion to the original's type
// will not succeed on it.  A custom Key that already has a key ID is never
// wrapped.
// If an error occurred, then k is returned as is.
func EnsureKeyID(k Key, h crypto.Hash) (updated Key, err error) {
	updated = k
	if len(k.KeyID()) == 0 {
		var t []byte
		t, err = k.Thumbprint(h)

		if err == nil {
			updated = replaceKeyID(k, base64.RawURLEncoding.EncodeToString(t), true)
		}
	}

	return
}
