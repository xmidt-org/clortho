package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
)

const (
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

// ReadSetBytes reads the JWK set from a byte slice.  The format is determined by
// looking at the content, e.g. PEM, jwk, or jwk-set.
func ReadSetBytes(data []byte) (format string, set jwk.Set, err error) {
	switch {
	case len(data) == 0:
		format = FormatJWKSet
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
			format = FormatJWK // single key
			set = jwk.NewSet()
			set.Add(key)
		} else {
			format = FormatJWKSet
			set, err = jwk.Parse(data)
		}

	default:
		format = FormatPEM
		set, err = jwk.Parse(data, jwk.WithPEM(true))
	}

	return
}

// Writer provides the logic for writing keys.
type Writer struct {
	// Stdout is the stream to use for non-file output.
	Stdout io.Writer

	// Stdin is the stream to use for non-file input.
	Stdin io.Reader

	// Path is the location where the key is written.  This is also the location
	// to which the key is appended, if Append is true.
	//
	// If a system file, this field should have filepath.Abs called on it prior
	// to invoking any methods of this type.  This enables simpler debugging.
	Path string

	// Append indicates whether a written key will be appended to the existing
	// contents of Path.  If this field is true, then Path will be read and parsed
	// as a JWK set, then the key will be appended to that set.
	Append bool

	// Format is the desired output format of the key or set.  If empty, the format
	// is determined dynamically:  If Append is true, then the parsed format of the contents
	// of Path is used.  Otherwise, output defaults to jwk-set format, even for a single key.
	Format string
}

func (w Writer) readAppendSet() (inFormat string, set jwk.Set, err error) {
	var data []byte
	switch {
	case w.Append && w.Path == StreamPath && w.Stdin != nil:
		data, err = io.ReadAll(w.Stdin)

	case w.Append && w.Path != StreamPath:
		var f *os.File
		f, err = os.Open(w.Path)
		if err == nil {
			defer f.Close()
			data, err = io.ReadAll(f)
		} else if errors.Is(err, fs.ErrNotExist) {
			err = nil // ignore when the file doesn't exist
		}
	}

	if err == nil && len(data) > 0 {
		inFormat, set, err = ReadSetBytes(data)
	} else {
		// for an empty or nonexistent file, assume an empty set
		set = jwk.NewSet()
	}

	return
}

func (w Writer) determineOutFormat(inFormat string) (format string, err error) {
	format = FormatJWKSet // the default

	switch {
	case len(w.Format) > 0:
		// if the user explicitly specified an output format, use that
		format = w.Format

	case len(inFormat) > 0:
		// ... then fallback to the detected format from the keys being appended to
		format = inFormat

	case w.Path == StreamPath:
		format = FormatJWKSet

	default:
		// if writing to a system file, try to use the file suffix to
		// determine the format.  failing that, fallback to jwk-set.
		format = suffixToFormat[filepath.Ext(w.Path)]
		if len(format) == 0 {
			format = FormatJWKSet
		}
	}

	if _, ok := formats[format]; !ok {
		err = fmt.Errorf("%s is not a valid format", format)
	}

	return
}

// WriteKey outputs the given key, appending it to any existing set as necessary.
// This method will read the Path file if appending is required.
func (w Writer) WriteKey(key jwk.Key) (err error) {
	var (
		inFormat  string
		outFormat string
		set       jwk.Set
		data      []byte
	)

	inFormat, set, err = w.readAppendSet()
	if err == nil {
		set.Add(key)
		outFormat, err = w.determineOutFormat(inFormat)
	}

	if err == nil {
		switch {
		case outFormat == FormatPEM:
			switch key.KeyType() {
			case jwa.RSA:
				fallthrough

			case jwa.EC:
				data, err = jwk.Pem(set)

			default:
				err = fmt.Errorf("Keys of type '%s' cannot be written as PEM blocks", key.KeyType())
			}

		case outFormat == FormatJWK && set.Len() == 1:
			// can only write a single key if there was nothing to append to
			data, err = json.MarshalIndent(key, "", "\t")

		default:
			// by default, write a jwk set
			data, err = json.MarshalIndent(set, "", "\t")
		}
	}

	if err == nil {
		if w.Path == StreamPath {
			_, err = w.Stdout.Write(data)
		} else {
			var f *os.File
			f, err = os.OpenFile(w.Path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
			if err == nil {
				defer f.Close()
				_, err = f.Write(data)
			}
		}
	}

	return
}
