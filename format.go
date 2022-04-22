/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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
