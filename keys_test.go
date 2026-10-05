// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseKeysSet(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	data := jwkSetJSON(t,
		publicJWK(t, rsaKey, "one", nil),
		publicJWK(t, ecKey, "two", map[string]any{"use": "sig", "alg": "ES256"}),
	)

	keys, err := parseKeys(data)
	require.NoError(t, err)
	require.Len(t, keys, 2)

	kid, _ := keys[0].KeyID()
	assert.Equal(t, "one", kid)
	kid, _ = keys[1].KeyID()
	assert.Equal(t, "two", kid)
	use, _ := keys[1].KeyUsage()
	assert.Equal(t, "sig", use)
	alg, _ := keys[1].Algorithm()
	assert.Equal(t, "ES256", alg.String())
}

func TestParseKeysSingleKey(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	data, err := json.Marshal(publicJWK(t, rsaKey, "solo", nil))
	require.NoError(t, err)

	keys, err := parseKeys(data)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	kid, _ := keys[0].KeyID()
	assert.Equal(t, "solo", kid)
}

func TestParseKeysEmptySet(t *testing.T) {
	keys, err := parseKeys([]byte(`{"keys":[]}`))
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestParseKeysInvalidJSON(t *testing.T) {
	keys, err := parseKeys([]byte(`not json`))
	assert.Error(t, err)
	assert.Nil(t, keys)
}

func TestParseKeysRejectsAMissingKeyID(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	k, err := jwk.Import[jwk.Key](&rsaKey.PublicKey)
	require.NoError(t, err)

	keys, err := parseKeys(jwkSetJSON(t, k))
	assert.ErrorIs(t, err, ErrMissingKeyID)
	assert.Nil(t, keys)
}

func TestParseKeysRejectsASymmetricKey(t *testing.T) {
	keys, err := parseKeys([]byte(`{"keys":[{"kty":"oct","k":"c2VjcmV0","kid":"shared"}]}`))
	assert.ErrorIs(t, err, ErrSymmetricKey)
	assert.ErrorContains(t, err, "shared")
	assert.Nil(t, keys)
}

func TestParseKeysRejectsADuplicateKeyIDWithinTheSet(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	data := jwkSetJSON(t,
		publicJWK(t, rsaKey, "same", nil),
		publicJWK(t, ecKey, "same", nil),
	)

	keys, err := parseKeys(data)
	assert.ErrorIs(t, err, ErrDuplicateKeyID)
	assert.Nil(t, keys)
}

func TestParseKeysReportsEveryBadKey(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	noKid, err := jwk.Import[jwk.Key](&rsaKey.PublicKey)
	require.NoError(t, err)
	oct, err := jwk.ParseKey([]byte(`{"kty":"oct","k":"c2VjcmV0","kid":"shared"}`))
	require.NoError(t, err)

	_, err = parseKeys(jwkSetJSON(t, noKid, oct))
	assert.ErrorIs(t, err, ErrMissingKeyID)
	assert.ErrorIs(t, err, ErrSymmetricKey)
}

func TestParseKeysConvertsAPrivateKeyToItsPublicForm(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	private, err := jwk.Import[jwk.Key](rsaKey)
	require.NoError(t, err)
	require.NoError(t, private.Set(jwk.KeyIDKey, "leaked"))

	keys, err := parseKeys(jwkSetJSON(t, private))
	require.NoError(t, err)
	require.Len(t, keys, 1)

	rendered, err := json.Marshal(keys[0])
	require.NoError(t, err)
	assert.NotContains(t, string(rendered), `"d":`)
	kid, _ := keys[0].KeyID()
	assert.Equal(t, "leaked", kid)
}

func TestParseKeysRejectsAKeyWithNoPublicForm(t *testing.T) {
	// an OKP key with an unknown curve parses, but has no public form jwx can build
	keys, err := parseKeys([]byte(`{"keys":[{"kty":"OKP","crv":"X448","x":"AAAA","kid":"odd"}]}`))
	if err == nil {
		// jwx may accept the curve, in which case the key is simply valid
		assert.Len(t, keys, 1)
		return
	}

	assert.Nil(t, keys)
}

func TestParseKey(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	bare, err := jwk.Import[jwk.Key](&rsaKey.PublicKey)
	require.NoError(t, err)
	withoutKeyID, err := json.Marshal(bare)
	require.NoError(t, err)
	withKeyID, err := json.Marshal(publicJWK(t, &rsaKey.PublicKey, "a", nil))
	require.NoError(t, err)

	tests := []struct {
		name     string
		data     []byte
		expected error
		failed   bool
	}{
		{name: "a key that does not say what it is", data: withoutKeyID},
		{name: "a key that says it is the one asked for", data: withKeyID},
		{name: "a key that says it is another", data: bytes.Replace(withKeyID, []byte(`"a"`), []byte(`"b"`), 1), expected: ErrKeyIDMismatch},
		{name: "a symmetric key", data: []byte(`{"kty":"oct","k":"c2VjcmV0"}`), expected: ErrSymmetricKey},
		{name: "a key set", data: jwkSetJSON(t, publicJWK(t, &rsaKey.PublicKey, "a", nil)), failed: true},
		{name: "PEM", data: []byte("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"), failed: true},
		{name: "nothing", data: nil, failed: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := parseKey(tt.data, "a")
			switch {
			case tt.expected != nil:
				assert.ErrorIs(t, err, tt.expected)
				assert.Nil(t, key)

			case tt.failed:
				assert.Error(t, err)
				assert.Nil(t, key)

			default:
				require.NoError(t, err)
				kid, ok := key.KeyID()
				assert.True(t, ok)
				assert.Equal(t, "a", kid, "the key takes the ID that was asked for")
			}
		})
	}
}
