// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"fmt"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"go.uber.org/multierr"
)

// UnsupportedFormatError indicates that a Parser cannot parse a given format.
type UnsupportedFormatError struct {
	Format string
}

// Error implements the error interface.
func (ufe UnsupportedFormatError) Error() string {
	return fmt.Sprintf("No parser configured for format %s", ufe.Format)
}

// Parser turns raw data into one or more Key instances.
type Parser interface {
	// Parse parses data, expected to be in the given format, into zero or more Keys.
	// If only one key is present in the data, this method returns a 1-element slice.
	//
	// Format is an opaque string which used as a key to determine which parsing algorithm
	// to apply to the data.  Most commonly, format is either a file suffix (including the
	// leading '.') or a media type such as application/json.  If format contains any MIME
	// parameters, e.g. text/xml;charset=utf-8, they are ignored.
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
	formatKey := format
	if i := strings.IndexByte(formatKey, ';'); i >= 0 {
		// strip any MIME parameters, matching only on the media type
		formatKey = formatKey[:i]
	}

	if p, ok := ps.p[formatKey]; ok {
		keys, err = p.Parse(formatKey, content)
	} else {
		err = UnsupportedFormatError{
			Format: format, // include the original format string, for easier debugging
		}
	}

	return
}

// NewParser returns a Parser tailored with the given options.
//
// The returned Parser handles the following formats by default:
//
//	application/json
//	application/jwk+json
//	application/jwk-set+json
//	application/x-pem-file
//	.json
//	.jwk
//	.jwk-set
//	.pem
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
		err = multierr.Append(err, o.applyToParsers(ps))
	}

	if err != nil {
		ps = nil
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
