// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

var (
	// ErrKeyProviderKeyNotFound indicates that the kid in the protected header is not
	// on the key ring.
	ErrKeyProviderKeyNotFound = errors.New("key provider failed to find the request kid in its keyring")

	// ErrKeyProviderMissingKeyID indicates that the protected header has no kid, so
	// there is nothing to look up on the ring.
	ErrKeyProviderMissingKeyID = errors.New(`payload must contain a "kid" field in its protected header`)

	// ErrKeyProviderMissingAlg indicates that the protected header has no alg, so the
	// key cannot be offered for verification under any algorithm.
	ErrKeyProviderMissingAlg = errors.New(`protected header must contain an "alg" field`)

	// ErrKeyProviderKeyUsage indicates that the key found on the ring is marked, via
	// its JWK "use" member, for something other than signature verification.  This
	// check is on by default; see WithIgnoreKeyUsage.
	ErrKeyProviderKeyUsage = errors.New("key is not marked for signature use")

	// ErrKeyProviderKeyImport indicates that the key found on the ring could not be
	// converted into a form jwx can verify with.  It is joined with the jwx error.
	ErrKeyProviderKeyImport = errors.New("key provider could not import the key from its keyring")

	// ErrKeyProviderNoKeyRing indicates that no KeyRing was supplied to NewKeyProvider.
	// A key ring is required, as it is the only source of keys for verification.
	ErrKeyProviderNoKeyRing = errors.New("key provider requires a key ring; see WithKeyRing")

	// ErrNoRefreshSources indicates that a Config supplied to NewKeyProvider has no
	// refresh sources.  Keys are served to the verifier from the refreshed key ring,
	// not resolved per request, so without sources the ring never fills and every
	// token fails.  Config.Resolve plays no part in verification.
	ErrNoRefreshSources = errors.New("at least one refresh source is required; keys are served to the verifier from the refreshed key ring, not resolved per request")
)

// NewKeyProvider constructs a jws.KeyProvider that draws keys from a KeyRing, matching
// the kid in a JWS protected header against the keys the ring currently holds.
//
// A KeyRing is required; supply one with WithKeyRing.  Note that the ring is the only
// source of keys for verification: a Resolver is deliberately not consulted, so that an
// unverified kid cannot trigger an outbound fetch.  Keys reach the ring by way of a
// Refresher configured from Config.Refresh.Sources.  Config.Resolve is not involved.
//
// Passing WithConfig makes this function check that the Config has at least one refresh
// source, returning ErrNoRefreshSources otherwise.  That turns the most common
// misconfiguration, a resolve template with no refresh sources, into a startup error
// rather than a "key not found" on every token.
//
// If no key ring is supplied, or if any option returns an error, this function returns
// a nil jws.KeyProvider along with a non-nil error.  Callers must not use the returned
// provider when the error is non-nil.
func NewKeyProvider(opts ...KeyProviderOption) (jws.KeyProvider, error) {
	kp := keyProvider{}

	var errs []error
	for _, opt := range opts {
		errs = append(errs, opt.apply(&kp))
	}

	if kp.keyRing == nil {
		errs = append(errs, ErrKeyProviderNoKeyRing)
	}

	if err := errors.Join(errs...); err != nil {
		// NOTE: an explicit nil, not a nil *keyProvider, so that a caller comparing the
		// returned interface against nil sees what it expects.
		return nil, err
	}

	return &kp, nil
}

type keyProvider struct {
	keyRing KeyRing

	// ignoreKeyUsage accepts keys whose "use" is set to anything other than sig.
	// The zero value enforces the check, matching RFC 7517 and jwx's own key set
	// provider; see WithIgnoreKeyUsage.
	ignoreKeyUsage bool
}

func (kp keyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	// NewKeyProvider rejects a missing ring, but keyProvider is constructible as a zero
	// value within this package, so guard rather than dereference a nil interface.
	if kp.keyRing == nil {
		return ErrKeyProviderNoKeyRing
	}

	kid, ok := sig.ProtectedHeaders().KeyID()
	if !ok {
		return ErrKeyProviderMissingKeyID
	}

	ckey, ok := kp.keyRing.Get(kid)
	if !ok {
		return fmt.Errorf("%w: kid `%q` not found in keyring", ErrKeyProviderKeyNotFound, kid)
	}

	// The "use" member lives on the clortho Key, which kept it from the JWKS.  The
	// jwx key rebuilt below from raw material never carries one, so the check has
	// to happen here.
	if !kp.ignoreKeyUsage {
		if usage := ckey.KeyUsage(); usage != "" && usage != jwk.ForSignature.String() {
			return fmt.Errorf(`%w: key with kid %q is marked use=%q (expected %q)`, ErrKeyProviderKeyUsage, kid, usage, jwk.ForSignature.String())
		}
	}

	key, err := jwk.Import[jwk.Key](ckey.Raw())
	if err != nil {
		return errors.Join(ErrKeyProviderKeyImport, err)
	}

	hdrAlg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return ErrKeyProviderMissingAlg
	}

	// Offer the key under the header's algorithm and let jws.Verify decide whether
	// the pair is usable.  jwx owns that check: it rejects a key whose type cannot
	// serve the algorithm, and it refuses to verify under any algorithm other than
	// the one in the protected header.  A pre-check here would have to reproduce
	// those rules, and jws.AlgorithmsForKey, the only exported helper for it, is
	// deprecated with a warning that its answer is wider than RFC 7518 allows.
	sink.Key(hdrAlg, key)
	return nil
}
