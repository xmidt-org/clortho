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
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"go.uber.org/multierr"
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
	Raw() interface{}

	// Public is the public portion of the raw key.  If this key is already a public key, this method
	// returns the same key as Raw.
	Public() crypto.PublicKey
}

type key struct {
	Thumbprinter
	keyID    string
	keyType  string
	keyUsage string
	raw      interface{}
	public   crypto.PublicKey
}

func (k *key) KeyID() string            { return k.keyID }
func (k *key) KeyType() string          { return k.keyType }
func (k *key) KeyUsage() string         { return k.keyUsage }
func (k *key) Raw() interface{}         { return k.raw }
func (k *key) Public() crypto.PublicKey { return k.public }
func (k *key) String() string           { return k.keyID }

func convertJWKKey(jk jwk.Key) (Key, error) {
	k := &key{
		Thumbprinter: jk,
		keyID:        jk.KeyID(),
		keyType:      string(jk.KeyType()),
		keyUsage:     jk.KeyUsage(),
	}

	if err := jk.Raw(&k.raw); err != nil {
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
		} else if err := pub.Raw(&k.public); err != nil {
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
	var err error
	for i := 0; i < js.Len(); i++ {
		jk, _ := js.Key(i)
		var keyErr error
		keys, keyErr = appendJWKKey(jk, keys)
		err = multierr.Append(err, keyErr)
	}

	return keys, err
}

// EnsureKeyID conditionally assigns a key ID to a given key.  The updated
// Key is returned, along with any error from the hash.
//
// If k already has a key ID, it is returned as is with no error.
//
// If k does not have a key ID, a thumbprint is generated using the supplied
// hash.  The returned key will be a copy of k with the newly generated key ID.
// If an error occurred, then k is returned as is.
func EnsureKeyID(k Key, h crypto.Hash) (updated Key, err error) {
	updated = k
	if len(k.KeyID()) == 0 {
		var t []byte
		t, err = k.Thumbprint(h)

		if err == nil {
			clone := new(key)
			*clone = *(k.(*key))
			clone.keyID = base64.RawURLEncoding.EncodeToString(t)
			updated = clone
		}
	}

	return
}
