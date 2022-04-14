package main

import "github.com/lestrrat-go/jwx/jwk"

type KeyGenerator func() (interface{}, error)

func NewKey(kg KeyGenerator) (key jwk.Key, err error) {
	rawKey, err := kg()
	if err == nil {
		key, err = jwk.New(rawKey)
	}

	return
}
