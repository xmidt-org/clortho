// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

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
