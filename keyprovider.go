// SPDX-FileCopyrightText: 2019 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"go.uber.org/multierr"
)

var (
	ErrKeyProviderKeyNotFound = errors.New("key provider failed to find the request kid in its keyring")
)

func NewKeyProvider(opts ...KeyProviderOption) (jws.KeyProvider, error) {
	kp := keyProvider{}

	var errs error
	for _, opt := range opts {
		errs = multierr.Append(errs, opt.apply(&kp))
	}

	return &kp, errs
}

type keyProvider struct {
	keyRing KeyRing
}

func (kp keyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	kid, ok := sig.ProtectedHeaders().KeyID()
	if !ok {
		return fmt.Errorf(`payload must contain a "kid" field in its protected header`)
	}

	ckey, ok := kp.keyRing.Get(kid)
	if !ok {
		return fmt.Errorf("%w: kid `%q` not found in keyring", ErrKeyProviderKeyNotFound, kid)
	}

	key, err := jwk.Import[jwk.Key](ckey.Raw())
	if err != nil {
		return err
	}

	if uk, ok := key.(jwk.UnsupportedKey); ok {
		return fmt.Errorf(`key with "kid" %q from clortho keyring has unsupported key type %q and cannot be used for signature verification; an extension module may be required to parse it: %w`, kid, uk.KeyType().String(), uk.Reason())
	}

	if usage, ok := key.KeyUsage(); ok {
		if usage != "" && usage != jwk.ForSignature.String() {
			return fmt.Errorf(`key with kid %q is marked use=%q, not usable for signature verification (expected %q)`, kid, usage, jwk.ForSignature.String())
		}
	}

	// nolint: staticcheck
	algs, err := jws.AlgorithmsForKey(key)
	if err != nil {
		return fmt.Errorf(`failed to get a list of signature methods for key type %s: %w`, key.KeyType(), err)
	}

	hdrAlg, ok := sig.ProtectedHeaders().Algorithm()
	if !ok {
		return fmt.Errorf(`protected header must contain an "alg" field`)
	}

	for _, alg := range algs {
		if hdrAlg != alg {
			continue
		}

		sink.Key(alg, key)
		return nil
	}

	return fmt.Errorf(`algorithm %q in JWS header does not match any algorithm for key type %s from jku`, hdrAlg, key.KeyType())
}
