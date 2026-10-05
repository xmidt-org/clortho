// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// parseKey parses the single JWK a server returned when asked for one key by
// its key ID, and adopts it under that key ID.
func parseKey(data []byte, keyID string) (jwk.Key, error) {
	k, err := jwk.ParseKey(data)
	if err != nil {
		return nil, err
	}

	return adoptKey(k, keyID)
}

// parseFixedKey parses a key written into configuration, as PEM or as a JWK,
// and adopts it under the key ID the configuration gives it.  The form is
// told from how the text starts, once the white space a configuration file
// tends to wrap around a block of text is gone.
//
// The text is never quoted in an error.  It ought to be a public key, but a
// mistake could put a private one here, and an error is likely to be logged.
func parseFixedKey(text, keyID string) (jwk.Key, error) {
	text = strings.TrimSpace(text)

	var (
		k   jwk.Key
		err error
	)

	switch {
	case text == "":
		return nil, fmt.Errorf("%w: it is empty", ErrInvalidFixedKey)

	case strings.HasPrefix(text, "{"):
		k, err = jwk.ParseKey([]byte(text))

	case strings.HasPrefix(text, pemBegin):
		// only the first block would be read, and the rest silently ignored
		if strings.Count(text, pemBegin) > 1 {
			return nil, fmt.Errorf("%w: it holds more than one PEM block", ErrInvalidFixedKey)
		}

		// a block pasted into a configuration file or a Go string is often
		// indented, and PEM does not allow that
		lines := strings.Split(text, "\n")
		for i, line := range lines {
			lines[i] = strings.TrimSpace(line)
		}

		k, err = jwk.ParseKey([]byte(strings.Join(lines, "\n")), jwk.WithX509(true))

	default:
		return nil, fmt.Errorf("%w: it is neither PEM nor a JWK", ErrInvalidFixedKey)
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFixedKey, err)
	}

	return adoptKey(k, keyID)
}

// pemBegin is how every PEM block starts.
const pemBegin = "-----BEGIN"

// adoptKey applies the rules every key must meet before a provider will hold
// it, and gives the key the ID it is to be known by.  The key must not be
// symmetric, and is reduced to its public form.  A key need not say what its
// own key ID is: a server that serves one key per request need not repeat the
// ID in the key, and a PEM has nowhere to put one.  A key that does carry an
// ID must carry the one it is being adopted under, since anything else means
// it is not the key that was meant.
func adoptKey(k jwk.Key, keyID string) (jwk.Key, error) {
	if k.KeyType() == jwa.OctetSeq() {
		return nil, fmt.Errorf("%w: %q", ErrSymmetricKey, keyID)
	}

	if kid, ok := k.KeyID(); ok && kid != "" && kid != keyID {
		return nil, fmt.Errorf("%w: wanted %q, the key says %q", ErrKeyIDMismatch, keyID, kid)
	}

	pub, err := k.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("key %q: %w", keyID, err)
	}

	if err := pub.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("key %q: %w", keyID, err)
	}

	return pub, nil
}

// parseKeys parses a JWK set or a single JWK into the keys the ring will hold.
// Every key must carry a kid and must not be symmetric, and no kid may appear
// twice.  Each key is reduced to its public form, so that a private key which
// found its way into a published set never sits on the ring.  Any bad key
// fails the whole parse: a source that serves a misconfigured set is treated
// as a failed refresh rather than partially trusted.
func parseKeys(data []byte) ([]jwk.Key, error) {
	set, err := jwk.Parse(data)
	if err != nil {
		return nil, err
	}

	var (
		keys = make([]jwk.Key, 0, set.Len())
		seen = make(map[string]bool, set.Len())
		errs []error
	)

	for i := range set.Len() {
		k, _ := set.Key(i)
		kid, ok := k.KeyID()
		if !ok || kid == "" {
			errs = append(errs, fmt.Errorf("%w: key %d in the set", ErrMissingKeyID, i))
			continue
		}

		if k.KeyType() == jwa.OctetSeq() {
			errs = append(errs, fmt.Errorf("%w: %q", ErrSymmetricKey, kid))
			continue
		}

		if seen[kid] {
			errs = append(errs, fmt.Errorf("%w: %q appears more than once in the set", ErrDuplicateKeyID, kid))
			continue
		}

		pub, err := k.PublicKey()
		if err != nil {
			errs = append(errs, fmt.Errorf("key %q: %w", kid, err))
			continue
		}

		seen[kid] = true
		keys = append(keys, pub)
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return keys, nil
}
