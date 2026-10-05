// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// FixedKey is one key written into a service's own configuration.
type FixedKey struct {
	// KeyID is the key ID that tokens name this key by.  Required: a PEM has
	// nowhere to carry one, and a JWK may not.  If Key is a JWK that does carry
	// a kid, it must be this one.
	KeyID string

	// Key is the key itself, as text: either PEM, starting with
	// "-----BEGIN", or a JWK, starting with "{".  Which it is does not have to
	// be said.  White space around it, and indentation on each line of a PEM,
	// are ignored, so it can be an indented block in a configuration file.
	//
	// It should be a public key.  A private key is reduced to its public half,
	// and a symmetric key is refused.
	Key string
}

// FixedKeyConfig is the only way to configure a FixedKeyProvider.  Like the
// other configs it is a plain struct with no struct tags.
type FixedKeyConfig struct {
	// Keys are the keys to serve.  At least one is required, and no two may
	// share a KeyID.
	Keys []FixedKey

	// Verify is the set of checks applied to a key before it is offered to
	// jwx.
	Verify VerifyConfig
}

// FixedKeyProvider supplies verification keys that were written into the
// service's own configuration.  It never sends a request, for any reason, and
// what it holds changes only when the configuration does.
//
// It suits a service whose keys are few and seldom change, and one that must
// verify tokens without depending on a key server being reachable.  Rotating
// a key means changing the configuration of every such service.
//
// A FixedKeyProvider has nothing to start, stop, or watch: once built, it is
// complete.
type FixedKeyProvider struct {
	verify VerifyConfig

	// keys never changes after NewFixedKeyProvider returns, so it needs no
	// lock.
	keys map[string]jwk.Key
}

var _ jws.KeyProvider = (*FixedKeyProvider)(nil)

// NewFixedKeyProvider builds a FixedKeyProvider from a FixedKeyConfig.  It
// rejects a config with no keys (ErrNoFixedKeys), a key with no KeyID
// (ErrMissingKeyID), two keys with the same KeyID (ErrDuplicateKeyID), a key
// whose text cannot be used (ErrInvalidFixedKey), a symmetric key
// (ErrSymmetricKey), and a JWK that carries a kid other than its KeyID
// (ErrKeyIDMismatch).  Every problem is reported, joined, rather than just the
// first.
//
// No error quotes the text of a key.
func NewFixedKeyProvider(cfg FixedKeyConfig) (*FixedKeyProvider, error) {
	if len(cfg.Keys) == 0 {
		return nil, ErrNoFixedKeys
	}

	var (
		errs = make([]error, 0, len(cfg.Keys))
		keys = make(map[string]jwk.Key, len(cfg.Keys))
	)

	for i, fixed := range cfg.Keys {
		if fixed.KeyID == "" {
			errs = append(errs, fmt.Errorf("fixed key %d: %w", i, ErrMissingKeyID))
			continue
		}

		if _, taken := keys[fixed.KeyID]; taken {
			errs = append(errs, fmt.Errorf("fixed key %d: %w: %q", i, ErrDuplicateKeyID, fixed.KeyID))
			continue
		}

		key, err := parseFixedKey(fixed.Key, fixed.KeyID)
		if err != nil {
			errs = append(errs, fmt.Errorf("fixed key %d, %q: %w", i, fixed.KeyID, err))
			continue
		}

		keys[fixed.KeyID] = key
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return &FixedKeyProvider{verify: cfg.Verify, keys: keys}, nil
}

// KeyIDs lists the key IDs of the keys held, sorted, for health endpoints.
// The list never changes.
func (p *FixedKeyProvider) KeyIDs() []string {
	keyIDs := make([]string, 0, len(p.keys))
	for keyID := range p.keys {
		keyIDs = append(keyIDs, keyID)
	}

	slices.Sort(keyIDs)
	return keyIDs
}

// FetchKeys satisfies jws.KeyProvider, and is the only way a key leaves the
// FixedKeyProvider.  It finds the key for the protected header's kid, applies
// the VerifyConfig checks, and offers the key to jwx under the header's alg.
//
// Errors carry sentinels for errors.Is: ErrMissingKeyID, ErrKeyNotFound,
// ErrMissingAlgorithm, ErrKeyUsage, and ErrKeyAlgorithm.
func (p *FixedKeyProvider) FetchKeys(_ context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	headers := sig.ProtectedHeaders()
	keyID, ok := headers.KeyID()
	if !ok || keyID == "" {
		return fmt.Errorf(`%w: protected header has no "kid"`, ErrMissingKeyID)
	}

	key, ok := p.keys[keyID]
	if !ok {
		return fmt.Errorf("%w: %q", ErrKeyNotFound, keyID)
	}

	return p.verify.offer(sink, headers, keyID, key)
}
