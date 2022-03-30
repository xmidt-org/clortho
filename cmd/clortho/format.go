package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"github.com/lestrrat-go/jwx/jwk"
)

const (
	FormatPEM    = "pem"
	FormatJWK    = "jwk"
	FormatJWKSet = "jwk-set"
)

func IsFile(path string) bool {
	return len(path) > 0 && path != "-"
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

func ReadSetFile(path string) (jwk.Set, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	switch {
	case IsJSON(data):
		// There's a bug in jwk.Parse:  when passed a single key, it does not
		// work as intended.  The JWK set contains all the fields of the original
		// key parsed, along with a keys array.
		//
		// Workaround:  try parsing this as a key first, then as a set.
		key, err := jwk.ParseKey(data)
		if err == nil {
			set := jwk.NewSet()
			set.Add(key)
			return set, nil
		}

		return jwk.Parse(data)

	case len(data) > 0:
		return jwk.Parse(data, jwk.WithPEM(true))

	default:
		return jwk.NewSet(), nil
	}
}

func WriteSetFile(set jwk.Set, format, path string) error {
	var err error
	path, err = filepath.Abs(path)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer f.Close()
	return WriteSet(set, format, f)
}

func WriteSet(set jwk.Set, format string, o io.Writer) (err error) {
	var data []byte
	switch {
	case format == FormatPEM:
		data, err = jwk.Pem(set)

	case format == FormatJWK && set.Len() == 1:
		key, _ := set.Get(0)
		data, err = json.MarshalIndent(key, "", "\t")

	default:
		data, err = json.MarshalIndent(set, "", "\t")
	}

	if err == nil {
		_, err = o.Write(data)
	}

	return
}
