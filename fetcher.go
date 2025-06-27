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
	// Fetch grabs keys from a URI.  The prev ContentMeta may either be an empty struct, e.g. ContentMeta{},
	// or the ContentMeta from a previous call to Fetch.
	//
	// This method ensures that each key has a key ID.  For keys that do not have a key ID from their source,
	// a key ID is generated using a thumbprint hash.
	Fetch(ctx context.Context, location string, prev ContentMeta) (keys []Key, next ContentMeta, err error)
}

// NewFetcher produces a Fetcher from a set of configuration options.
func NewFetcher(options ...FetcherOption) (Fetcher, error) {
	var (
		err error

		f = &fetcher{
			keyIDHash: crypto.SHA256,
		}
	)

	for _, o := range options {
		err = multierr.Append(err, o.applyToFetcher(f))
	}

	if f.loader == nil {
		f.loader, _ = NewLoader()
	}

	if f.parser == nil {
		f.parser, _ = NewParser()
	}

	return f, err
}

// fetcher is the internal Fetcher implementation.
type fetcher struct {
	loader    Loader
	parser    Parser
	keyIDHash crypto.Hash
}

func (f *fetcher) Fetch(ctx context.Context, location string, prev ContentMeta) (keys []Key, next ContentMeta, err error) {
	var data []byte
	data, next, err = f.loader.LoadContent(ctx, location, prev)

	if err == nil {
		keys, err = f.parser.Parse(next.Format, data)
	}

	for i, k := range keys {
		updated, hashErr := EnsureKeyID(k, f.keyIDHash)
		keys[i] = updated
		err = multierr.Append(err, hashErr)
	}

	return
}
