package main

import (
	"fmt"
	"strconv"

	"github.com/lestrrat-go/jwx/jwk"
)

var reservedAttributes = map[string]bool{
	"kty":     true,
	"use":     true,
	"key_ops": true,
	"alg":     true,
	"kid":     true,
	"x58":     true, // have to set this due to a bug in lestrrat-go
	"x5u":     true,
	"x5c":     true,
	"x5t":     true,
	"x5t#256": true,

	// elliptic curve attributes
	"crv": true,
	"d":   true,
	"x":   true,
	"y":   true,

	// RSA attributes
	// "d": true, already included
	"dp": true,
	"dq": true,
	"e":  true,
	"n":  true,
	"p":  true,
	"qi": true,
	"q":  true,

	// symmetric attributes
	"k": true,
}

type Attributes map[string]string

func (a Attributes) SetTo(key jwk.Key) error {
	for n, v := range a {
		if reservedAttributes[n] {
			return fmt.Errorf("Cannot set %s as an extra attribute", n)
		}

		if i, err := strconv.Atoi(v); err == nil {
			key.Set(n, i)
		} else if f, err := strconv.ParseFloat(v, 64); err == nil {
			key.Set(n, f)
		} else if len(v) > 1 && v[0] == '\'' && v[len(v)-1] == '\'' {
			key.Set(n, v[1:len(v)-1])
		} else {
			key.Set(n, v)
		}
	}

	return nil
}
