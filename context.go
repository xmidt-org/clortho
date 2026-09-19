// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
)

var (
	ErrMissingConnectionDetails = errors.New("connection tls/trust details are missing")
	ErrMissingConnectionTrust   = errors.New("connection trust value is missing")
)

type contentMetaKey struct{}

// GetContentMeta returns the ContentMeta stored in the context by SetContentMeta.
// The returned bool is false when none was stored.  Loaders treat that case as the
// zero value, so callers are never required to seed one.
func GetContentMeta(ctx context.Context) (meta ContentMeta, ok bool) {
	meta, ok = ctx.Value(contentMetaKey{}).(ContentMeta)

	return
}

// SetContentMeta stores the ContentMeta from a previous load in the context, so that
// a subsequent load of the same location can be conditional (e.g. If-Modified-Since).
// The Refresher does this between refreshes.  It is optional for all other callers.
func SetContentMeta(ctx context.Context, meta ContentMeta) context.Context {
	return context.WithValue(
		ctx,
		contentMetaKey{},
		meta,
	)
}
