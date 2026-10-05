// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// publicPEM renders a public key the usual way: a PKIX "PUBLIC KEY" block.
func publicPEM(t *testing.T, pub any) string {
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// privatePEM renders a private key as a PKCS #8 "PRIVATE KEY" block.
func privatePEM(t *testing.T, private any) string {
	der, err := x509.MarshalPKCS8PrivateKey(private)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// jwkText renders raw key material as a JWK, with any extra members.
func jwkText(t *testing.T, raw any, members map[string]any) string {
	k, err := jwk.Import[jwk.Key](raw)
	require.NoError(t, err)
	for name, value := range members {
		require.NoError(t, k.Set(name, value))
	}

	text, err := json.Marshal(k)
	require.NoError(t, err)
	return string(text)
}

// askFixed does one lookup for a key ID, as jwx would for a token.
func askFixed(t *testing.T, p *FixedKeyProvider, header string) (recordingSink, error) {
	var sink recordingSink
	err := p.FetchKeys(context.Background(), &sink, unverifiedSignature(t, header), nil)
	return sink, err
}

func TestNewFixedKeyProviderRejectsABadConfig(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	good := publicPEM(t, &rsaKey.PublicKey)
	tests := []struct {
		name     string
		keys     []FixedKey
		expected error
	}{
		{"no keys", nil, ErrNoFixedKeys},
		{"a key with no key ID", []FixedKey{{Key: good}}, ErrMissingKeyID},
		{"two keys with one key ID", []FixedKey{{KeyID: "a", Key: good}, {KeyID: "a", Key: publicPEM(t, &ecKey.PublicKey)}}, ErrDuplicateKeyID},
		{"no key text", []FixedKey{{KeyID: "a"}}, ErrInvalidFixedKey},
		{"only white space", []FixedKey{{KeyID: "a", Key: " \n\t "}}, ErrInvalidFixedKey},
		{"neither PEM nor a JWK", []FixedKey{{KeyID: "a", Key: "ssh-rsa AAAAB3NzaC1yc2E user@host"}}, ErrInvalidFixedKey},
		{"PEM that holds no key", []FixedKey{{KeyID: "a", Key: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"}}, ErrInvalidFixedKey},
		{"PEM cut short", []FixedKey{{KeyID: "a", Key: good[:len(good)/2]}}, ErrInvalidFixedKey},
		{"two PEM blocks", []FixedKey{{KeyID: "a", Key: good + publicPEM(t, &ecKey.PublicKey)}}, ErrInvalidFixedKey},
		{"JSON that is not a key", []FixedKey{{KeyID: "a", Key: `{"hello":"world"}`}}, ErrInvalidFixedKey},
		{"JSON cut short", []FixedKey{{KeyID: "a", Key: `{"kty":"RSA",`}}, ErrInvalidFixedKey},
		{"a key set, where one key is wanted", []FixedKey{{KeyID: "a", Key: string(jwkSetJSON(t, publicJWK(t, &rsaKey.PublicKey, "a", nil)))}}, ErrInvalidFixedKey},
		{"a symmetric key", []FixedKey{{KeyID: "a", Key: `{"kty":"oct","k":"c2VjcmV0"}`}}, ErrSymmetricKey},
		{"a JWK that says it is another key", []FixedKey{{KeyID: "a", Key: jwkText(t, &rsaKey.PublicKey, map[string]any{jwk.KeyIDKey: "b"})}}, ErrKeyIDMismatch},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewFixedKeyProvider(FixedKeyConfig{Keys: tt.keys})
			assert.ErrorIs(t, err, tt.expected)
			assert.Nil(t, p)
		})
	}
}

func TestNewFixedKeyProviderReportsEveryProblemAtOnce(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	_, err := NewFixedKeyProvider(FixedKeyConfig{Keys: []FixedKey{
		{KeyID: "good", Key: publicPEM(t, &rsaKey.PublicKey)},
		{Key: publicPEM(t, &rsaKey.PublicKey)},
		{KeyID: "good", Key: publicPEM(t, &rsaKey.PublicKey)},
		{KeyID: "odd", Key: "not a key"},
		{KeyID: "shared", Key: `{"kty":"oct","k":"c2VjcmV0"}`},
	}})

	assert.ErrorIs(t, err, ErrMissingKeyID)
	assert.ErrorIs(t, err, ErrDuplicateKeyID)
	assert.ErrorIs(t, err, ErrInvalidFixedKey)
	assert.ErrorIs(t, err, ErrSymmetricKey)

	// each problem says which key it is about
	for _, where := range []string{"fixed key 1", "fixed key 2", `fixed key 3, "odd"`, `fixed key 4, "shared"`} {
		assert.ErrorContains(t, err, where)
	}
}

func TestNewFixedKeyProviderNeverQuotesAKey(t *testing.T) {
	// a key that cannot be used may be a secret put here by mistake, and the
	// error is likely to be logged
	const keyMaterial = "c2VjcmV0c2VjcmV0c2VjcmV0"
	for _, text := range []string{
		keyMaterial,
		`{"kty":"oct","k":"` + keyMaterial + `"}`,
		`{"kty":"RSA","n":"` + keyMaterial + `"`,
		`{"kty":"RSA","d":"` + keyMaterial + `","e":"AQAB"}`,
		"-----BEGIN PRIVATE KEY-----\n" + keyMaterial + "\n-----END PRIVATE KEY-----\n",
		"-----BEGIN PRIVATE KEY-----\n" + keyMaterial,
	} {
		_, err := NewFixedKeyProvider(FixedKeyConfig{Keys: []FixedKey{{KeyID: "a", Key: text}}})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), keyMaterial)
	}
}

func TestNewFixedKeyProviderAcceptsEitherForm(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	rsaPEM := publicPEM(t, &rsaKey.PublicKey)
	tests := []struct {
		name string
		text string
		kty  jwa.KeyType
	}{
		{"PEM, RSA", rsaPEM, jwa.RSA()},
		{"PEM, EC", publicPEM(t, &ecKey.PublicKey), jwa.EC()},
		{
			"PEM, RSA in the older PKCS #1 block",
			string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)})),
			jwa.RSA(),
		},
		{"PEM, indented as a configuration file would", "\n    " + strings.ReplaceAll(strings.TrimSpace(rsaPEM), "\n", "\n    ") + "\n  ", jwa.RSA()},
		{"PEM, with a blank line and spaces around it", "\n\n  " + rsaPEM + "  \n", jwa.RSA()},
		{"JWK that does not say what it is", jwkText(t, &ecKey.PublicKey, nil), jwa.EC()},
		{"JWK that says it is this key", jwkText(t, &ecKey.PublicKey, map[string]any{jwk.KeyIDKey: "a"}), jwa.EC()},
		{"JWK, with white space around it", "\n  " + jwkText(t, &rsaKey.PublicKey, nil) + "\n", jwa.RSA()},
		{"PEM, a private key", privatePEM(t, ecKey), jwa.EC()},
		{"JWK, a private key", jwkText(t, rsaKey, nil), jwa.RSA()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewFixedKeyProvider(FixedKeyConfig{Keys: []FixedKey{{KeyID: "a", Key: tt.text}}})
			require.NoError(t, err)

			held := p.keys["a"]
			assert.Equal(t, tt.kty, held.KeyType())

			// whatever the text said, the key answers to the configured ID
			kid, ok := held.KeyID()
			assert.True(t, ok)
			assert.Equal(t, "a", kid)

			// and only its public half is held
			rendered, err := json.Marshal(held)
			require.NoError(t, err)
			var members map[string]any
			require.NoError(t, json.Unmarshal(rendered, &members))
			assert.NotContains(t, members, "d")
		})
	}
}

func TestFixedKeyProviderVerifiesAToken(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	p, err := NewFixedKeyProvider(FixedKeyConfig{Keys: []FixedKey{
		{KeyID: "from-pem", Key: publicPEM(t, &rsaKey.PublicKey)},
		{KeyID: "from-jwk", Key: jwkText(t, &ecKey.PublicKey, nil)},
	}})
	require.NoError(t, err)

	payload, err := jws.Verify(sign(t, rsaKey, jwa.RS256(), "from-pem"), jws.WithKeyProvider(p))
	require.NoError(t, err)
	assert.Equal(t, "payload", string(payload))

	payload, err = jws.Verify(sign(t, ecKey, jwa.ES256(), "from-jwk"), jws.WithKeyProvider(p))
	require.NoError(t, err)
	assert.Equal(t, "payload", string(payload))

	// a token that names a real key ID, and was signed by something else
	_, err = jws.Verify(sign(t, ecKey, jwa.ES256(), "from-pem"), jws.WithKeyProvider(p))
	assert.Error(t, err)
}

func TestFixedKeyProviderFetchKeys(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	keys := []FixedKey{
		{KeyID: "plain", Key: publicPEM(t, &rsaKey.PublicKey)},
		{KeyID: "for-encryption", Key: jwkText(t, &rsaKey.PublicKey, map[string]any{jwk.KeyUsageKey: "enc"})},
		{KeyID: "rs512-only", Key: jwkText(t, &rsaKey.PublicKey, map[string]any{jwk.AlgorithmKey: jwa.RS512()})},
	}

	strict, err := NewFixedKeyProvider(FixedKeyConfig{Keys: keys})
	require.NoError(t, err)

	sink, err := askFixed(t, strict, `{"kid":"plain","alg":"RS384"}`)
	require.NoError(t, err)
	assert.Equal(t, jwa.RS384(), sink.alg, "the key is offered under the token's algorithm")
	assert.NotNil(t, sink.key)

	_, err = askFixed(t, strict, `{"kid":"unknown","alg":"RS256"}`)
	assert.ErrorIs(t, err, ErrKeyNotFound)

	_, err = askFixed(t, strict, `{"alg":"RS256"}`)
	assert.ErrorIs(t, err, ErrMissingKeyID)

	_, err = askFixed(t, strict, `{"kid":"plain"}`)
	assert.ErrorIs(t, err, ErrMissingAlgorithm)

	_, err = askFixed(t, strict, `{"kid":"for-encryption","alg":"RS256"}`)
	assert.ErrorIs(t, err, ErrKeyUsage)

	_, err = askFixed(t, strict, `{"kid":"rs512-only","alg":"RS256"}`)
	assert.ErrorIs(t, err, ErrKeyAlgorithm)

	lenient, err := NewFixedKeyProvider(FixedKeyConfig{
		Keys:   keys,
		Verify: VerifyConfig{IgnoreKeyUsage: true, IgnoreKeyAlgorithm: true},
	})
	require.NoError(t, err)

	_, err = askFixed(t, lenient, `{"kid":"for-encryption","alg":"RS256"}`)
	assert.NoError(t, err)

	_, err = askFixed(t, lenient, `{"kid":"rs512-only","alg":"RS256"}`)
	assert.NoError(t, err)
}

func TestFixedKeyProviderKeyIDs(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	text := publicPEM(t, &rsaKey.PublicKey)
	keys := []FixedKey{{KeyID: "c", Key: text}, {KeyID: "a", Key: text}, {KeyID: "b", Key: text}}
	p, err := NewFixedKeyProvider(FixedKeyConfig{Keys: keys})
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, p.KeyIDs())

	// what the provider holds does not follow the caller's slice afterward
	keys[0].KeyID = "changed"
	assert.Equal(t, []string{"a", "b", "c"}, p.KeyIDs())
}
