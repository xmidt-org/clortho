// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"sync"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

var (
	testKeysOnce sync.Once
	testRSA      *rsa.PrivateKey
	testEC       *ecdsa.PrivateKey
)

// testPrivateKeys generates the private keys the tests sign with, once per
// package, since key generation dominates test time otherwise.
func testPrivateKeys(t *testing.T) (*rsa.PrivateKey, *ecdsa.PrivateKey) {
	testKeysOnce.Do(func() {
		var err error
		testRSA, err = rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		testEC, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
	})

	return testRSA, testEC
}

// publicJWK builds a public JWK from raw key material with the given kid and
// any extra members, e.g. "use" or "alg".
func publicJWK(t *testing.T, raw any, kid string, members map[string]any) jwk.Key {
	k, err := jwk.Import[jwk.Key](raw)
	require.NoError(t, err)
	pub, err := k.PublicKey()
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, kid))
	for name, value := range members {
		require.NoError(t, pub.Set(name, value))
	}

	return pub
}

// jwkSetJSON renders keys as a JWK set document.
func jwkSetJSON(t *testing.T, keys ...jwk.Key) []byte {
	set := jwk.NewSet()
	for _, k := range keys {
		require.NoError(t, set.AddKey(k))
	}

	data, err := json.Marshal(set)
	require.NoError(t, err)
	return data
}
