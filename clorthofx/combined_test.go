// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthofx

import (
	"context"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubProvider answers a lookup with a fixed error, or by offering its keys,
// and remembers that it was asked.
type stubProvider struct {
	keys  []string
	err   error
	asked *[]string
	name  string
}

func (s stubProvider) FetchKeys(_ context.Context, sink jws.KeySink, _ *jws.Signature, _ *jws.Message) error {
	*s.asked = append(*s.asked, s.name)
	for _, key := range s.keys {
		sink.Key(jwa.RS256(), key)
	}

	return s.err
}

// keyList is a sink that remembers what it was offered.
type keyList []any

func (kl *keyList) Key(_ jwa.SignatureAlgorithm, key any) { *kl = append(*kl, key) }

func TestCombinedStopsAtTheFirstProviderThatOffersAKey(t *testing.T) {
	var asked []string
	notFound := errors.New("not found")
	c := combined{
		stubProvider{name: "first", err: notFound, asked: &asked},
		stubProvider{name: "second", keys: []string{"key from second"}, asked: &asked},
		stubProvider{name: "third", keys: []string{"key from third"}, asked: &asked},
	}

	var offered keyList
	require.NoError(t, c.FetchKeys(context.Background(), &offered, nil, nil))
	assert.Equal(t, []string{"first", "second"}, asked, "the third is never asked")
	assert.Equal(t, keyList{"key from second"}, offered)
}

func TestCombinedPassesOnEveryKeyAProviderOffers(t *testing.T) {
	var asked []string
	c := combined{stubProvider{name: "only", keys: []string{"a", "b"}, asked: &asked}}

	var offered keyList
	require.NoError(t, c.FetchKeys(context.Background(), &offered, nil, nil))
	assert.Equal(t, keyList{"a", "b"}, offered)
}

func TestCombinedReportsWhatEveryProviderSaid(t *testing.T) {
	var asked []string
	first, second := errors.New("first has no such key"), errors.New("second has no such key")
	c := combined{
		stubProvider{name: "first", err: first, asked: &asked},
		stubProvider{name: "second", err: second, asked: &asked},
	}

	var offered keyList
	err := c.FetchKeys(context.Background(), &offered, nil, nil)
	assert.ErrorIs(t, err, first)
	assert.ErrorIs(t, err, second)
	assert.Equal(t, []string{"first", "second"}, asked)
	assert.Empty(t, offered)
}

func TestCombinedPassesOverAProviderThatOffersNothing(t *testing.T) {
	// a provider may decline without an error; it is still passed over
	var asked []string
	c := combined{
		stubProvider{name: "silent", asked: &asked},
		stubProvider{name: "second", keys: []string{"key"}, asked: &asked},
	}

	var offered keyList
	require.NoError(t, c.FetchKeys(context.Background(), &offered, nil, nil))
	assert.Equal(t, []string{"silent", "second"}, asked)
	assert.Equal(t, keyList{"key"}, offered)
}

func TestCombinedWithNoProviders(t *testing.T) {
	var offered keyList
	assert.NoError(t, combined{}.FetchKeys(context.Background(), &offered, nil, nil))
	assert.Empty(t, offered)
}
