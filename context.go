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

func GetContentMeta(ctx context.Context) (meta ContentMeta, ok bool) {
	meta, ok = ctx.Value(contentMetaKey{}).(ContentMeta)

	return
}

func SetContentMeta(ctx context.Context, meta ContentMeta) context.Context {
	return context.WithValue(
		ctx,
		contentMetaKey{},
		meta,
	)
}
