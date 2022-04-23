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

type NoParserConfiguredError struct {
	Format string
}

func (npce *NoParserConfiguredError) Error() string {
	return fmt.Sprintf("No parser configured for format %s", npce.Format)
}

// Parser turns raw data into one or more Key instances.
type Parser interface {
	// Parse parses data, expected to be in the given format, into zero or more Keys.
	// If only one key is present in the data, this method returns a 1-element slice.
	//
	// Format is an opaque string which used as a key to determine which parsing algorithm
	// to apply to the data.  Most commonly, format is either a file suffix (including the
	// leading '.') or a media type such as application/json.
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

func (ps *parsers) Parse(format string, content []byte) (keys []Key, err error) {
	if p, ok := ps.p[format]; ok {
		keys, err = p.Parse(format, content)
	} else {
		err = &NoParserConfiguredError{
			Format: format,
		}
	}

	return
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
//
// The Parser returned by this function guarantees that all keys have a key ID.  A thumbprint
// using the WithKeyIDHash option is used to generate key IDs as needed.  By default, SHA256
// is used if WithKeyIDHash option is supplied.
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
				SuffixPEM:    usePEM,
				MediaTypePEM: usePEM,

				SuffixJSON:    jsp,
				MediaTypeJSON: jsp,

				SuffixJWK:    jp,
				MediaTypeJWK: jp,

				SuffixJWKSet:    jsp,
				MediaTypeJWKSet: jsp,
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
