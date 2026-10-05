// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// offer applies the checks to a key a provider found for a token and, if the
// key passes, offers it to jwx under the token's algorithm.  jwx then decides
// whether the key can serve that algorithm.  Every kind of provider ends a
// lookup here, so the checks mean the same thing for all of them.
func (v VerifyConfig) offer(sink jws.KeySink, headers jws.Headers, keyID string, key jwk.Key) error {
	if !v.IgnoreKeyUsage {
		if usage, ok := key.KeyUsage(); ok && usage != "" && usage != jwk.ForSignature.String() {
			return fmt.Errorf("%w: key %q has use %q", ErrKeyUsage, keyID, usage)
		}
	}

	alg, ok := headers.Algorithm()
	if !ok {
		return ErrMissingAlgorithm
	}

	if !v.IgnoreKeyAlgorithm {
		if keyAlg, ok := key.Algorithm(); ok && keyAlg.String() != "" && keyAlg.String() != alg.String() {
			return fmt.Errorf("%w: key %q has alg %q, header has %q", ErrKeyAlgorithm, keyID, keyAlg.String(), alg.String())
		}
	}

	sink.Key(alg, key)
	return nil
}
