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

import (
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"go.uber.org/multierr"
)

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

// UnsupportedFormatError indicates that a format (media type or file suffix) was passed
// to Parse which had no associated Parser.
type UnsupportedFormatError struct {
	Format string
}

// Error fulfills the error interface.
func (ufe *UnsupportedFormatError) Error() string {
	return fmt.Sprintf("Unsupported key format: %s", ufe.Format)
}

// ParserOption allows tailoring of the Parser returned by NewParser.
type ParserOption interface {
	applyToParsers(*parsers) error
}

type parserOptionFunc func(*parsers) error

func (pof parserOptionFunc) applyToParsers(ps *parsers) error { return pof(ps) }

// WithFormats associates a Parsers with one or more formats.  Each format must be either
// a media type ("application/json") or a file suffix with leading period (".json").
func WithFormats(p Parser, formats ...string) ParserOption {
	return parserOptionFunc(func(ps *parsers) error {
		for _, f := range formats {
			ps.p[f] = p
		}

		return nil
	})
}

// Parser turns raw data into one or more Key instances.
type Parser interface {
	// Parse parses data, expected to be in the given format, into zero or more Keys.
	// If only one key is present in the data, this method returns a 1-element slice.
	//
	// Custom parsers should usually avoid trying to validate format.  This is because
	// a Parser might be registered with a nonstandard format.  The format is available to
	// custom parser code primarily for debugging.
	Parse(format string, data []byte) ([]Key, error)
}

// parsers is the internal implementation of Parser.  It allows for a configurable set
// of parsers based on format.
type parsers struct {
	p map[string]Parser
}

func (ps *parsers) Parse(format string, content []byte) ([]Key, error) {
	if p, ok := ps.p[format]; ok {
		return p.Parse(format, content)
	}

	return nil, &UnsupportedFormatError{
		Format: format,
	}
}

// NewParser returns a Parser tailored with the given options.
//
// The returned Parser handles the following formats by default:
//
//   application/json
//   application/jwk+json
//   application/jwk-set+json
//   application/x-pem-file
//   .json
//   .jwk
//   .jwk-set
//   .pem
//
// A caller can use WithFormats to change the parser associated with a format or
// to register a Parser for a new, custom format.
func NewParser(options ...ParserOption) (Parser, error) {
	var (
		err error

		jsp = JWKSetParser{}

		jp = JWKKeyParser{}

		usePEM = JWKSetParser{
			Options: []jwk.ParseOption{
				jwk.WithPEM(true),
			},
		}

		ps = &parsers{
			p: map[string]Parser{
				MediaTypeJSON: jsp,
				SuffixJSON:    jsp,

				MediaTypeJWK: jp,
				SuffixJWK:    jp,

				MediaTypeJWKSet: jsp,
				SuffixJWKSet:    jsp,

				MediaTypePEM: usePEM,
				SuffixPEM:    usePEM,
			},
		}
	)

	for _, o := range options {
		multierr.Append(err, o.applyToParsers(ps))
	}

	return ps, err
}

// JWKKeyParser parses content as a single JWK.
type JWKKeyParser struct {
	Options []jwk.ParseOption
}

// Parse expects data to be a single JWK.  If data is a JWK set, this method returns
// an error.
func (jkp JWKKeyParser) Parse(_ string, data []byte) ([]Key, error) {
	jwkKey, err := jwk.ParseKey(data, jkp.Options...)
	if err != nil {
		return nil, err
	}

	keys := make([]Key, 0, 1)
	return appendJWKKey(jwkKey, keys)
}

// JWKSetParser parses content as a JWK set.
type JWKSetParser struct {
	Options []jwk.ParseOption
}

// Parse allows data to be either a single JWK or a JWK set.  For a single JWK, a
// 1-element slice is returned.
func (jsp JWKSetParser) Parse(_ string, data []byte) ([]Key, error) {
	jwkSet, err := jwk.Parse(data, jsp.Options...)
	if err != nil {
		return nil, err
	}

	keys := make([]Key, 0, jwkSet.Len())
	return appendJWKSet(jwkSet, keys)
}
