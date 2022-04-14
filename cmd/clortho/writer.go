package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/jwk"
)

const (
	// DefaultPath is the value indicating to take the default behavior, which
	// is different depending upon context.
	DefaultPath = ""

	// StreamPath is the value for a path that indicates either stdin or stdout,
	// depending upon the context.
	StreamPath = "-"

	// FormatPEM is the command line flag value to explicitly select PEM for key output.
	FormatPEM = "pem"

	// FormatJWK is the command line flag value to explicitly select JWK for key output.
	// Note that even if this is supplied, output may be a JWK set instead when the generated
	// key is being appended to an existing set.
	FormatJWK = "jwk"

	// FormatJWKSet is the command line flag value to explicitly select a JWK set for key output.
	// This is the default in most cases.  When used with a single key, the output will be a
	// JWK set with (1) element.
	FormatJWKSet = "jwk-set"

	// SuffixPEM is the system file suffix for the PEM format.
	SuffixPEM = ".pem"

	// SuffixJWK is the system file suffix for the JWK format.  Files of this type
	// are also allowed to contain JWK sets.
	SuffixJWK = ".jwk"

	// SuffixJWKSet is the system file suffix for the JWK set format.  Files of this type
	// must contain a set and cannot contain a single JWK key.
	SuffixJWKSet = ".jwk-set"
)

var suffixToFormat = map[string]string{
	SuffixPEM:    FormatPEM,
	SuffixJWK:    FormatJWK,
	SuffixJWKSet: FormatJWKSet,
}

var formats = map[string]bool{
	FormatPEM:    true,
	FormatJWK:    true,
	FormatJWKSet: true,
}

// IsJSON tests the given data to see if it's JSON.  If this function returns
// false, PEM is assumed.
func IsJSON(data []byte) bool {
	for _, c := range data {
		// fast whitespace detection
		if c == '\t' || c == '\n' || c == '\v' || c == '\f' || c == '\r' || c == ' ' {
			continue
		}

		return c == '{'
	}

	// nothing but whitespace ...
	return false
}

// unmarshalSet performs the common behavior for reading in a JWK set for appending.
// If the data is empty (or nil), then the detectedFormat is returned as FormatJWKSet
// and a non-nil, empty jwk.Set is returned.
func unmarshalSet(data []byte) (detectedFormat string, set jwk.Set, err error) {
	switch {
	case len(data) == 0:
		detectedFormat = FormatJWKSet
		set = jwk.NewSet()

	case IsJSON(data):
		// NOTE: there's a bug in github.com/lestrrat-go/jwx/jwk.  jwk.Parse
		// will result in a jwk.Set with the key material as JSON fields at the same
		// level as keys due to how the unmarshalling is implemented.
		//
		// To work around this, we first try and parse it as a key, then as a set.
		var key jwk.Key
		key, err = jwk.ParseKey(data)
		if err == nil {
			detectedFormat = FormatJWK // single key
			set = jwk.NewSet()
			set.Add(key)
		} else {
			detectedFormat = FormatJWKSet
			set, err = jwk.Parse(data)
		}

	default:
		detectedFormat = FormatPEM
		set, err = jwk.Parse(data, jwk.WithPEM(true))
	}

	return
}

// Reader is the strategy for reading a key set for appending.
type Reader interface {
	// Path returns the file system location this reader uses.  If StreamPath,
	// then data is read from stdin.  If DefaultPath, this reader doesn't read
	// any data, instead returning an empty set.
	Path() string

	// ReadSet reads the set to which the generated key should be appended.
	// The returned set will always be non-nil if the error is nil, though
	// the set can be empty if the source is empty or doesn't exist.
	ReadSet() (detectedFormat string, set jwk.Set, err error)
}

// NewReader constructs a Reader appropriate for the given path and configured stdin.
func NewReader(stdin io.Reader, path string) (r Reader, err error) {
	switch path {
	case DefaultPath:
		// by default, don't append to anything
		r = nilReader{}

	case StreamPath:
		r = stdinReader{stdin: stdin}

	default:
		path, err = filepath.Abs(path)
		if err == nil {
			r = pathReader{path: path}
		}
	}

	return
}

type nilReader struct{}

func (nr nilReader) Path() string { return DefaultPath }

func (nr nilReader) ReadSet() (string, jwk.Set, error) {
	return unmarshalSet(nil)
}

type stdinReader struct {
	stdin io.Reader
}

func (sr stdinReader) Path() string { return StreamPath }

func (sr stdinReader) ReadSet() (string, jwk.Set, error) {
	data, err := io.ReadAll(sr.stdin)
	if err == nil {
		return unmarshalSet(data)
	}

	return "", nil, err
}

type pathReader struct {
	path string
}

func (pr pathReader) Path() string { return pr.path }

func (pr pathReader) ReadSet() (detectedFormat string, set jwk.Set, err error) {
	var data []byte
	data, err = os.ReadFile(pr.path)
	if err == nil {
		detectedFormat, set, err = unmarshalSet(data)
	}

	return
}

// marshalSet marshals the set using the supplied format.
func marshalSet(format string, set jwk.Set) (data []byte, err error) {
	switch {
	case format == FormatPEM:
		data, err = jwk.Pem(set)

	case format == FormatJWK && set.Len() == 1:
		key, _ := set.Get(0)
		data, err = json.MarshalIndent(key, "", "\t")

	default:
		data, err = json.MarshalIndent(set, "", "\t")
	}

	return
}

// Writer provides the logic for writing keys.
type Writer interface {
	Path() string

	// WriteSet writes the given set to the output.  This method honors FormatJWK
	// if and only if set has exactly (1) key.
	WriteSet(format string, set jwk.Set) error
}

// NewWriter produces a Writer that outputs keys to either path or stdout,
// depending on whether path is a system file.
func NewWriter(stdout io.Writer, path string) (w Writer, err error) {
	switch path {
	case DefaultPath:
		fallthrough

	case StreamPath:
		w = stdoutWriter{stdout: stdout}

	default:
		path, err = filepath.Abs(path)
		if err == nil {
			w = pathWriter{path: path}
		}
	}

	return
}

type stdoutWriter struct {
	stdout io.Writer
}

func (sw stdoutWriter) Path() string { return StreamPath }

func (sw stdoutWriter) WriteSet(format string, set jwk.Set) (err error) {
	var data []byte
	data, err = marshalSet(format, set)
	if err == nil {
		_, err = sw.stdout.Write(data)
	}

	return
}

type pathWriter struct {
	path string
}

func (pw pathWriter) Path() string { return pw.path }

func (pw pathWriter) WriteSet(format string, set jwk.Set) (err error) {
	var (
		data []byte
		f    *os.File
	)

	data, err = marshalSet(format, set)
	if err == nil {
		f, err = os.OpenFile(pw.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	}

	if err == nil {
		defer f.Close()
		_, err = f.Write(data)
	}

	return
}
