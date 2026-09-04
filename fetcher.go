// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"crypto"
	_ "crypto/sha256"

	"go.uber.org/multierr"
)

// Fetcher handles fetching keys from URI locations.  This is the typical application-layer interface.
// Generally, clients should use this interface over Loader and Parser.
type Fetcher interface {
	// This method ensures that each key has a key ID.  For keys that do not have a key ID from their source,
	// a key ID is generated using a thumbprint hash.
	Fetch(ctx context.Context, location string) (keys []Key, metadata ContentMeta, err error)
}

// NewFetcher produces a Fetcher from a set of configuration options.
func NewFetcher(options ...FetcherOption) Fetcher {
	f := fetcher{
		keyIDHash: crypto.SHA256,
		loader:    defaultLoader(),
		parser:    defaultParser(),
	}

	for _, o := range options {
		o.applyToFetcher(&f)
	}

	return &f
}

// fetcher is the internal Fetcher implementation.
type fetcher struct {
	loader    Loader
	parser    Parser
	keyIDHash crypto.Hash
}

func (f *fetcher) Fetch(ctx context.Context, location string) ([]Key, ContentMeta, error) {
	data, nextMeta, err := f.loader.LoadContent(ctx, location)
	if err != nil {
		return nil, ContentMeta{}, err
	}

	keys, err := f.parser.Parse(nextMeta.Format, data)
	if err != nil {
		return nil, ContentMeta{}, err
	}

	var errs error
	for i, k := range keys {
		updated, hashErr := EnsureKeyID(k, f.keyIDHash)
		keys[i] = updated
		errs = multierr.Append(errs, hashErr)
	}

	if errs != nil {
		return nil, ContentMeta{}, err
	}

	return keys, nextMeta, nil
}
