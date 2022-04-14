package main

import (
	"io"

	"github.com/lestrrat-go/jwx/jwk"
)

// Pipe represents a source and a sink of key material.  A generated key
// will be inserted into this pipe by reading a set, adding the key, then
// writing the set.
type Pipe struct {
	// Reader represents the source of material to which the key will be
	// appended.
	Reader Reader

	// Writer represents the target where key material is to be output.
	Writer Writer
}

// WriteKey inserts a key into this pipe, using the supplied output format.
func (p Pipe) WriteKey(format string, key jwk.Key) error {
	_, set, err := p.Reader.ReadSet()
	if err != nil {
		return err
	}

	set.Add(key)
	return p.Writer.WriteSet(format, set)
}

// NewPipe constructs a Pipe from default streams, and append, and an output path.
func NewPipe(stdin io.Reader, stdout io.Writer, app, out string) (p Pipe, err error) {
	p.Reader, err = NewReader(stdin, app)
	if err == nil {
		path := out
		if len(path) == 0 {
			path = app
		}

		p.Writer, err = NewWriter(stdout, path)
	}

	return
}

// PublicPipe is similar to Pipe, but writes only the public portion of the key.
type PublicPipe Pipe

// WritePublicKey inserts the public portion of the key into this pipe.
func (pp PublicPipe) WritePublicKey(format string, key jwk.Key) error {
	pkey, err := key.PublicKey()
	if err != nil {
		return err
	}

	return Pipe(pp).WriteKey(format, pkey)
}

func NewPublicPipe(stdin io.Reader, stdout io.Writer, app, out string) (PublicPipe, error) {
	p, err := NewPipe(stdin, stdout, app, out)
	return PublicPipe(p), err
}
