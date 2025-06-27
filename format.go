// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

const (
	// MediaTypeJSON is the media type for JSON data.  By default, content with this media type
	// may contain either a single JWK or a JWK set.
	MediaTypeJSON = "application/json"

	// SuffixJSON is the file suffix for JSON data.  By default, files with this suffix may
	// contain either a single JWK or a JWK Set.
	SuffixJSON = ".json"

	// MediaTypeJWK is the media type for a single JWK.
	MediaTypeJWK = "application/jwk+json"

	// SuffixJWK is the file suffix for a single JWK.
	SuffixJWK = ".jwk"

	// MediaTypeJWKSet is the media type for a JWK set.
	MediaTypeJWKSet = "application/jwk-set+json"

	// SuffixJWKSet is the file suffix for a JWK set.
	SuffixJWKSet = ".jwk-set"

	// MediaTypePEM is the media type for a PEM-encoded key.
	MediaTypePEM = "application/x-pem-file"

	// SuffixPEM is the file suffix for a PEM-encoded key.
	SuffixPEM = ".pem"
)
