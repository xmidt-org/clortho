package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/jwk"
)

const (
	StreamPath = "-"

	FormatPEM    = "pem"
	FormatJWK    = "jwk"
	FormatJWKSet = "jwk-set"

	SuffixPEM    = ".pem"
	SuffixJWK    = ".jwk"
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

func ReadSetFile(name string) (format string, set jwk.Set, err error) {
	var f *os.File
	f, err = os.Open(name)
	if err == nil {
		defer f.Close()
		format, set, err = ReadSet(f)
	}

	return
}

func ReadSet(r io.Reader) (format string, set jwk.Set, err error) {
	var data []byte
	data, err = io.ReadAll(r)
	if err == nil {
		format, set, err = ReadSetBytes(data)
	}

	return
}

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

// CheckFormat asserts that v is a valid format, returning an error if not.
func CheckFormat(v string) error {
	if _, ok := formats[v]; ok {
		return nil
	}

	return fmt.Errorf("%s is not a valid format", v)
}

type Writer struct {
	Stdout io.Writer
	Stdin  io.Reader
	Path   string
	Append bool
	Format string
}

func (w Writer) readAppendSet() (inFormat string, set jwk.Set, err error) {
	switch {
	case w.Append && w.Path == StreamPath && w.Stdin != nil:
		inFormat, set, err = ReadSet(w.Stdin)

	case w.Append && w.Path != StreamPath:
		inFormat, set, err = ReadSetFile(w.Path)

	default:
		// leave inFormat unset
		set = jwk.NewSet()
	}

	return
}

func (w Writer) determineOutFormat(inFormat string) (format string, err error) {
	format = FormatJWKSet // the default

	switch {
	// if the user explicitly specified an output format, use that
	case len(w.Format) > 0:
		format = w.Format

	// if writing to stdout and appending to an existing set,
	// use the format of the existing set
	case w.Path == StreamPath && len(inFormat) > 0:
		format = inFormat

	// if writing to a system file, try to use the file suffix to
	// determine the format.  failing that, use the format of the
	// existing set.  failing that, fallback to jwk-set
	case w.Path != StreamPath:
		format = suffixToFormat[filepath.Ext(w.Path)]
		switch {
		case len(format) == 0 && len(inFormat) > 0:
			format = inFormat

		case len(format) == 0:
			format = FormatJWKSet
		}
	}

	err = CheckFormat(format)
	return
}

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
			data, err = jwk.Pem(set)

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
