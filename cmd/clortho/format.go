package main

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
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

func readSetFromPath(path string, ignoreMissing bool) (jwk.Set, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrExist) && ignoreMissing {
			return nil, nil
		}

		return nil, err
	}

	defer f.Close()
	return readSetFromReader(f)
}

func readSetFromReader(r io.Reader) (jwk.Set, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	if len(data) > 0 {
		return jwk.Parse(data, jwk.WithPEM(!IsJSON(data)))
	}

	// an empty file or nothing from stdin is ok
	return nil, nil
}

func ReadSets(stdin io.Reader, in []string, ignoreMissing bool) (merged jwk.Set, err error) {
	merged = jwk.NewSet()
	previous := make(map[string]bool, len(in))
	for _, source := range in {
		var keys jwk.Set
		if IsFile(source) {
			source, err = filepath.Abs(source)
			if err != nil {
				return
			}

			if previous[source] {
				continue
			}

			previous[source] = true
			keys, err = readSetFromPath(source, ignoreMissing)
		} else if !previous[""] {
			previous[""] = true
			keys, err = readSetFromReader(stdin)
		}

		if err != nil {
			return
		} else if keys == nil {
			continue // empty input
		}

		for i := 0; i < keys.Len(); i++ {
			k, _ := keys.Get(i)
			merged.Add(k)
		}
	}

	return
}

func WriteSet(set jwk.Set, stdout io.Writer, format, path string) error {
	if IsFile(path) {
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
		return WriteSetTo(set, format, f)
	} else {
		return WriteSetTo(set, format, stdout)
	}
}

func WriteSetTo(set jwk.Set, format string, o io.Writer) (err error) {
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
