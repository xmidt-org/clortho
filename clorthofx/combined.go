// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthofx

import (
	"context"
	"errors"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
)

// combined is several providers presented to jwx as one.  It asks each in
// turn and stops at the first that offers a key.
//
// Stopping there is the point of the order.  The providers that a token cannot
// make send a request are asked first, so a token whose key one of them holds
// never reaches a provider that might fetch for it.
//
// It also means a key ID should be served by one provider only.  If two hold
// different keys under one key ID, only the first is ever tried.
type combined []jws.KeyProvider

var _ jws.KeyProvider = combined(nil)

// FetchKeys asks each provider in order for the key a token names.  A provider
// that fails, or offers nothing, is passed over.  If none offers a key, the
// error is everything the providers said, joined, so that errors.Is still
// finds a sentinel such as clortho.ErrKeyNotFound.
func (c combined) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	errs := make([]error, 0, len(c))
	for _, provider := range c {
		offers := offerCounter{sink: sink}
		err := provider.FetchKeys(ctx, &offers, sig, msg)
		if offers.count > 0 {
			return nil
		}

		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

// offerCounter passes keys through to a sink, and counts them, so that
// combined can tell whether a provider offered one.
type offerCounter struct {
	sink  jws.KeySink
	count int
}

func (o *offerCounter) Key(alg jwa.SignatureAlgorithm, key any) {
	o.count++
	o.sink.Key(alg, key)
}
