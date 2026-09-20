// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/suite"
)

type KeyProviderSuite struct {
	suite.Suite

	privateKey *rsa.PrivateKey

	// additional key types, used to check that the provider does not
	// discriminate on key type and that mismatches are rejected
	p256Key      *ecdsa.PrivateKey
	p384Key      *ecdsa.PrivateKey
	symmetricKey []byte
}

func (suite *KeyProviderSuite) SetupSuite() {
	var err error
	suite.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	suite.Require().NoError(err)

	suite.p256Key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	suite.Require().NoError(err)

	suite.p384Key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	suite.Require().NoError(err)

	suite.symmetricKey = make([]byte, 32)
	_, err = rand.Read(suite.symmetricKey)
	suite.Require().NoError(err)
}

// sign produces a compact JWS over a fixed payload, signed with the given
// algorithm and key, and carrying kid in its protected header.
func (suite *KeyProviderSuite) sign(alg jwa.SignatureAlgorithm, key any, kid string) []byte {
	headers := jws.NewHeaders()
	suite.Require().NoError(headers.Set(jws.KeyIDKey, kid))

	signed, err := jws.Sign(
		[]byte(`{"sub":"test"}`),
		jws.WithKey(alg, key, jws.WithProtectedHeaders(headers)),
	)

	suite.Require().NoError(err)
	return signed
}

// signature parses a compact JWS and returns its single signature, which is
// what jws.Verify hands to a KeyProvider.
func (suite *KeyProviderSuite) signature(compact []byte) *jws.Signature {
	msg, err := jws.Parse(compact)
	suite.Require().NoError(err)
	suite.Require().Len(msg.Signatures(), 1)
	return msg.Signatures()[0]
}

// newRing returns a ring holding the given raw key under kid.
func (suite *KeyProviderSuite) newRing(kid string, raw any) KeyRing {
	jk, err := jwk.Import[jwk.Key](raw)
	suite.Require().NoError(err)
	suite.Require().NoError(jk.Set(jwk.KeyIDKey, kid))

	k, err := convertJWKKey(jk)
	suite.Require().NoError(err)

	return NewKeyRing(k)
}

// newKeyProvider returns a provider over a ring holding raw under kid.
func (suite *KeyProviderSuite) newKeyProvider(kid string, raw any) jws.KeyProvider {
	kp, err := NewKeyProvider(WithKeyRing(suite.newRing(kid, raw)))
	suite.Require().NoError(err)
	suite.Require().NotNil(kp)
	return kp
}

// recordingSink captures the (alg, key) pairs a KeyProvider offers for verification.
type recordingSink struct {
	algs []jwa.SignatureAlgorithm
	keys []any
}

func (rs *recordingSink) Key(alg jwa.SignatureAlgorithm, key any) {
	rs.algs = append(rs.algs, alg)
	rs.keys = append(rs.keys, key)
}

// newSignedJWS signs a JWS carrying the given kid.
func (suite *KeyProviderSuite) newSignedJWS(kid string) []byte {
	headers := jws.NewHeaders()
	suite.Require().NoError(headers.Set(jws.KeyIDKey, kid))

	signed, err := jws.Sign(
		[]byte(`{"sub":"test"}`),
		jws.WithKey(jwa.RS256(), suite.privateKey, jws.WithProtectedHeaders(headers)),
	)

	suite.Require().NoError(err)
	return signed
}

// newRingWith returns a ring holding the suite's public key under kid.
func (suite *KeyProviderSuite) newRingWith(kid string) KeyRing {
	return suite.newRing(kid, &suite.privateKey.PublicKey)
}

// newRingWithUsage returns a ring holding the suite's public key under kid, with
// the JWK "use" member set to usage as it would be when parsed from a JWKS.
func (suite *KeyProviderSuite) newRingWithUsage(kid, usage string) KeyRing {
	jk, err := jwk.Import[jwk.Key](&suite.privateKey.PublicKey)
	suite.Require().NoError(err)
	suite.Require().NoError(jk.Set(jwk.KeyIDKey, kid))
	suite.Require().NoError(jk.Set(jwk.KeyUsageKey, usage))

	k, err := convertJWKKey(jk)
	suite.Require().NoError(err)
	suite.Require().Equal(usage, k.KeyUsage())

	return NewKeyRing(k)
}

// TestNoOptions is the regression guard for the nil key ring panic.
func (suite *KeyProviderSuite) TestNoOptions() {
	kp, err := NewKeyProvider()

	suite.Nil(kp)
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrKeyProviderNoKeyRing)
}

func (suite *KeyProviderSuite) TestNilKeyRing() {
	kp, err := NewKeyProvider(WithKeyRing(nil))

	suite.Nil(kp)
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrKeyProviderNoKeyRing)
}

func (suite *KeyProviderSuite) TestOptionError() {
	expectedErr := errors.New("expected option failure")
	failingOption := keyProviderOptionFunc(func(*keyProvider) error {
		return expectedErr
	})

	kp, err := NewKeyProvider(failingOption, WithKeyRing(NewKeyRing()))

	suite.Nil(kp)
	suite.Require().Error(err)
	suite.ErrorIs(err, expectedErr)
	// a ring was supplied, so only the option error should be reported
	suite.NotErrorIs(err, ErrKeyProviderNoKeyRing)
}

func (suite *KeyProviderSuite) TestOptionErrorAndNoKeyRing() {
	expectedErr := errors.New("expected option failure")
	failingOption := keyProviderOptionFunc(func(*keyProvider) error {
		return expectedErr
	})

	kp, err := NewKeyProvider(failingOption)

	suite.Nil(kp)
	suite.Require().Error(err)
	suite.ErrorIs(err, expectedErr)
	suite.ErrorIs(err, ErrKeyProviderNoKeyRing)
}

// TestEmptyKeyRing pins the empty-ring versus no-ring distinction.
func (suite *KeyProviderSuite) TestEmptyKeyRing() {
	kp, err := NewKeyProvider(WithKeyRing(NewKeyRing()))

	suite.Require().NoError(err)
	suite.Require().NotNil(kp)

	_, err = jws.Verify(suite.newSignedJWS("kid-1"), jws.WithKeyProvider(kp))
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrKeyProviderKeyNotFound)
	suite.NotErrorIs(err, ErrKeyProviderNoKeyRing)
}

// TestZeroValueProvider covers the zero value the constructor cannot guard.
func (suite *KeyProviderSuite) TestZeroValueProvider() {
	suite.Require().NotPanics(func() {
		_, err := jws.Verify(suite.newSignedJWS("kid-1"), jws.WithKeyProvider(keyProvider{}))
		suite.Require().Error(err)
		suite.ErrorIs(err, ErrKeyProviderNoKeyRing)
	})
}

func (suite *KeyProviderSuite) TestVerifySuccess() {
	kp, err := NewKeyProvider(WithKeyRing(suite.newRingWith("kid-1")))

	suite.Require().NoError(err)
	suite.Require().NotNil(kp)

	payload, err := jws.Verify(suite.newSignedJWS("kid-1"), jws.WithKeyProvider(kp))
	suite.Require().NoError(err)
	suite.JSONEq(`{"sub":"test"}`, string(payload))
}

func (suite *KeyProviderSuite) TestMissingKeyID() {
	kp, err := NewKeyProvider(WithKeyRing(suite.newRingWith("kid-1")))
	suite.Require().NoError(err)

	unsigned, err := jws.Sign(
		[]byte(`{"sub":"test"}`),
		jws.WithKey(jwa.RS256(), suite.privateKey),
	)
	suite.Require().NoError(err)

	_, err = jws.Verify(unsigned, jws.WithKeyProvider(kp))
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrKeyProviderMissingKeyID)

	// the message is unchanged from before the sentinel existed
	suite.Equal(`payload must contain a "kid" field in its protected header`, ErrKeyProviderMissingKeyID.Error())
}

// unsignedJWS builds a compact JWS by hand from the given protected header, so
// that headers jws.Sign always supplies (such as alg) can be left out.  The
// signature is garbage; these tokens only ever reach FetchKeys, never a verifier.
func (suite *KeyProviderSuite) unsignedJWS(protected string) *jws.Signature {
	enc := base64.RawURLEncoding.EncodeToString
	compact := enc([]byte(protected)) + "." + enc([]byte(`{"sub":"test"}`)) + "." + enc([]byte("sig"))
	return suite.signature([]byte(compact))
}

// TestMissingAlg checks the protected header without an alg, which jws.Sign
// cannot produce, so FetchKeys is called directly.
func (suite *KeyProviderSuite) TestMissingAlg() {
	var (
		kp   = suite.newKeyProvider("kid-1", &suite.privateKey.PublicKey)
		sig  = suite.unsignedJWS(`{"kid":"kid-1"}`)
		sink recordingSink
	)

	err := kp.FetchKeys(context.Background(), &sink, sig, nil)
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrKeyProviderMissingAlg)
	suite.Empty(sink.algs, "nothing should be offered to the sink")

	// the message is unchanged from before the sentinel existed
	suite.Equal(`protected header must contain an "alg" field`, ErrKeyProviderMissingAlg.Error())
}

// TestKeyImportError checks a ring key whose raw material jwx cannot import.
// The error must be classifiable and must carry jwx's reason.
func (suite *KeyProviderSuite) TestKeyImportError() {
	var (
		bad = &key{keyID: "kid-1", raw: "not a key"}
		kp  = suite.newKeyProvider("kid-1", &suite.privateKey.PublicKey)
	)

	// swap the good key for the bad one under the same kid
	kp.(*keyProvider).keyRing.Add(bad)

	_, importErr := jwk.Import[jwk.Key](bad.Raw())
	suite.Require().Error(importErr)

	var sink recordingSink
	err := kp.FetchKeys(context.Background(), &sink, suite.signature(suite.newSignedJWS("kid-1")), nil)
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrKeyProviderKeyImport)
	suite.ErrorContains(err, importErr.Error())
	suite.Empty(sink.algs)

	// and through jws.Verify, the sentinel is still reachable
	_, err = jws.Verify(suite.newSignedJWS("kid-1"), jws.WithKeyProvider(kp))
	suite.ErrorIs(err, ErrKeyProviderKeyImport)
}

// TestKeyNotFoundMessage pins the message of the one sentinel that predates this
// change, so that its text does not drift either.
func (suite *KeyProviderSuite) TestKeyNotFoundMessage() {
	suite.Equal("key provider failed to find the request kid in its keyring", ErrKeyProviderKeyNotFound.Error())
}

// TestFetchKeysOffersHeaderAlgorithm pins the contract that FetchKeys offers the
// ring key to the sink under the algorithm named in the protected header, and
// nothing else.  Whether that (alg, key) pair is usable is jws.Verify's decision:
// it owns the algorithm-versus-key check, and it re-checks the header alg against
// every pair a provider offers.  FetchKeys must not pre-empt that with its own
// compatibility gate.
func (suite *KeyProviderSuite) TestFetchKeysOffersHeaderAlgorithm() {
	testCases := []struct {
		name    string
		ringKey any
		alg     jwa.SignatureAlgorithm
		signKey any
	}{
		{
			name:    "MatchingRSA",
			ringKey: &suite.privateKey.PublicKey,
			alg:     jwa.RS256(),
			signKey: suite.privateKey,
		},
		{
			name:    "MatchingEC",
			ringKey: &suite.p256Key.PublicKey,
			alg:     jwa.ES256(),
			signKey: suite.p256Key,
		},
		{
			// an HMAC alg against an asymmetric ring key.  the provider offers the
			// pair; jws.Verify is what rejects it.
			name:    "MismatchedRSA",
			ringKey: &suite.privateKey.PublicKey,
			alg:     jwa.HS256(),
			signKey: suite.symmetricKey,
		},
		{
			// a P-256 ring key with an ES384 header.  RFC 7518 forbids this pair.
			name:    "MismatchedCurve",
			ringKey: &suite.p256Key.PublicKey,
			alg:     jwa.ES384(),
			signKey: suite.p384Key,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			var (
				kp   = suite.newKeyProvider("kid-1", tc.ringKey)
				sig  = suite.signature(suite.sign(tc.alg, tc.signKey, "kid-1"))
				sink recordingSink
			)

			err := kp.FetchKeys(context.Background(), &sink, sig, nil)
			suite.Require().NoError(err)

			suite.Require().Len(sink.algs, 1)
			suite.Equal(tc.alg, sink.algs[0])

			suite.Require().Len(sink.keys, 1)
			offered, ok := sink.keys[0].(jwk.Key)
			suite.Require().True(ok, "offered key should be a jwk.Key")

			expected, err := jwk.Import[jwk.Key](tc.ringKey)
			suite.Require().NoError(err)
			suite.True(jwk.Equal(expected, offered), "offered key should be the ring key")
		})
	}
}

// TestVerifyRejectsMismatchedKey is the guard behind removing the provider's own
// algorithm gate: for every mismatch the old gate claimed to catch, jws.Verify
// must reject the token on its own.
func (suite *KeyProviderSuite) TestVerifyRejectsMismatchedKey() {
	// the classic algorithm confusion attack: sign with HS256 using the public
	// key's encoding as the shared secret, hoping the verifier uses the public
	// key it already holds the same way.
	rsaPublicDER, err := x509.MarshalPKIXPublicKey(&suite.privateKey.PublicKey)
	suite.Require().NoError(err)

	testCases := []struct {
		name    string
		ringKey any
		alg     jwa.SignatureAlgorithm
		signKey any
	}{
		{
			name:    "AlgorithmConfusion",
			ringKey: &suite.privateKey.PublicKey,
			alg:     jwa.HS256(),
			signKey: rsaPublicDER,
		},
		{
			name:    "KeyTypeMismatch",
			ringKey: &suite.p256Key.PublicKey,
			alg:     jwa.RS256(),
			signKey: suite.privateKey,
		},
		{
			name:    "CurveMismatch",
			ringKey: &suite.p256Key.PublicKey,
			alg:     jwa.ES384(),
			signKey: suite.p384Key,
		},
		{
			name:    "WrongKeyOfSameType",
			ringKey: &suite.p384Key.PublicKey,
			alg:     jwa.ES256(),
			signKey: suite.p256Key,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			kp := suite.newKeyProvider("kid-1", tc.ringKey)

			payload, err := jws.Verify(
				suite.sign(tc.alg, tc.signKey, "kid-1"),
				jws.WithKeyProvider(kp),
			)

			suite.Error(err)
			suite.Nil(payload)
		})
	}
}

// TestVerifySuccessByKeyType checks that the provider works for each key type
// the ring can hold, not just RSA.
func (suite *KeyProviderSuite) TestVerifySuccessByKeyType() {
	testCases := []struct {
		name    string
		ringKey any
		alg     jwa.SignatureAlgorithm
		signKey any
		opts    []KeyProviderOption
	}{
		{
			name:    "RSA",
			ringKey: &suite.privateKey.PublicKey,
			alg:     jwa.PS256(),
			signKey: suite.privateKey,
		},
		{
			name:    "EC",
			ringKey: &suite.p256Key.PublicKey,
			alg:     jwa.ES256(),
			signKey: suite.p256Key,
		},
		{
			// symmetric keys are rejected by default; see TestSymmetricKeyRejectedByDefault
			name:    "Symmetric",
			ringKey: suite.symmetricKey,
			alg:     jwa.HS256(),
			signKey: suite.symmetricKey,
			opts:    []KeyProviderOption{WithAllowSymmetricKeys()},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			opts := append([]KeyProviderOption{WithKeyRing(suite.newRing("kid-1", tc.ringKey))}, tc.opts...)
			kp, err := NewKeyProvider(opts...)
			suite.Require().NoError(err)

			payload, err := jws.Verify(
				suite.sign(tc.alg, tc.signKey, "kid-1"),
				jws.WithKeyProvider(kp),
			)

			suite.Require().NoError(err)
			suite.JSONEq(`{"sub":"test"}`, string(payload))
		})
	}
}

// newSymmetricRingFromJWKS serves a JWKS containing the suite's symmetric key,
// fetches it through the default Fetcher exactly as a Refresher would, and
// returns the resulting ring.  This is the issue's reproduction: a JWKS is
// public, so a secret published in one is public too.
func (suite *KeyProviderSuite) newSymmetricRingFromJWKS() KeyRing {
	jk, err := jwk.Import[jwk.Key](suite.symmetricKey)
	suite.Require().NoError(err)
	suite.Require().NoError(jk.Set(jwk.KeyIDKey, "hmac-1"))

	set := jwk.NewSet()
	suite.Require().NoError(set.AddKey(jk))
	body, err := json.Marshal(set)
	suite.Require().NoError(err)

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", MediaTypeJWKSet)
		_, _ = rw.Write(body)
	}))
	suite.T().Cleanup(server.Close)

	keys, _, err := NewFetcher().Fetch(context.Background(), server.URL+"/keys")
	suite.Require().NoError(err)
	suite.Require().Len(keys, 1)
	suite.Require().Equal("oct", keys[0].KeyType())

	return NewKeyRing(keys...)
}

// TestSymmetricKeyRejectedByDefault checks that a symmetric key that arrived
// through a JWKS is never offered for verification.  Anyone who could read the
// JWKS has the secret and can mint tokens that verify with it.
func (suite *KeyProviderSuite) TestSymmetricKeyRejectedByDefault() {
	kp, err := NewKeyProvider(WithKeyRing(suite.newSymmetricRingFromJWKS()))
	suite.Require().NoError(err)

	forged := suite.sign(jwa.HS256(), suite.symmetricKey, "hmac-1")

	var sink recordingSink
	err = kp.FetchKeys(context.Background(), &sink, suite.signature(forged), nil)
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrKeyProviderSymmetricKey)
	suite.Empty(sink.algs, "the secret must not be offered to the verifier")

	payload, err := jws.Verify(forged, jws.WithKeyProvider(kp))
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrKeyProviderSymmetricKey)
	suite.Nil(payload)
}

// TestSymmetricKeyAllowed checks the opt-in for a deployment that genuinely
// shares a secret, e.g. through a local file source.
func (suite *KeyProviderSuite) TestSymmetricKeyAllowed() {
	kp, err := NewKeyProvider(
		WithKeyRing(suite.newSymmetricRingFromJWKS()),
		WithAllowSymmetricKeys(),
	)
	suite.Require().NoError(err)

	payload, err := jws.Verify(suite.sign(jwa.HS256(), suite.symmetricKey, "hmac-1"), jws.WithKeyProvider(kp))
	suite.Require().NoError(err)
	suite.JSONEq(`{"sub":"test"}`, string(payload))
}

// TestNoRefreshSources checks that a provider built with a Config that has no
// refresh sources is rejected.  Keys reach the verifier only through the
// refreshed ring, so such a deployment would answer every token with "key not
// found" while its configuration looked correct.
func (suite *KeyProviderSuite) TestNoRefreshSources() {
	kp, err := NewKeyProvider(
		WithKeyRing(NewKeyRing()),
		WithConfig(Config{
			Resolve: ResolveConfig{Template: "https://example.com/keys/{keyID}"},
		}),
	)

	suite.Nil(kp)
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrNoRefreshSources)
	suite.NotErrorIs(err, ErrKeyProviderNoKeyRing)
}

// TestWithRefreshSources checks that a Config with at least one refresh source
// is accepted, and that the provider still verifies from its ring.
func (suite *KeyProviderSuite) TestWithRefreshSources() {
	kp, err := NewKeyProvider(
		WithKeyRing(suite.newRingWith("kid-1")),
		WithConfig(Config{
			Refresh: RefreshConfig{
				Sources: []RefreshSource{{URI: "https://example.com/keys"}},
			},
		}),
	)

	suite.Require().NoError(err)
	suite.Require().NotNil(kp)

	payload, err := jws.Verify(suite.newSignedJWS("kid-1"), jws.WithKeyProvider(kp))
	suite.Require().NoError(err)
	suite.JSONEq(`{"sub":"test"}`, string(payload))
}

// TestKeyUsageEnforcedByDefault pins the default: a key marked for a use other
// than signing is rejected with no option given, matching RFC 7517 section 4.2
// and jwx's own key set provider.
func (suite *KeyProviderSuite) TestKeyUsageEnforcedByDefault() {
	kp, err := NewKeyProvider(WithKeyRing(suite.newRingWithUsage("kid-1", jwk.ForEncryption.String())))
	suite.Require().NoError(err)

	payload, err := jws.Verify(suite.newSignedJWS("kid-1"), jws.WithKeyProvider(kp))
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrKeyProviderKeyUsage)
	suite.Nil(payload)
}

// TestKeyUsageIgnored checks the opt-out: with WithIgnoreKeyUsage, a key marked
// for encryption still verifies, which is what every release before v0.4.0 did.
func (suite *KeyProviderSuite) TestKeyUsageIgnored() {
	kp, err := NewKeyProvider(
		WithKeyRing(suite.newRingWithUsage("kid-1", jwk.ForEncryption.String())),
		WithIgnoreKeyUsage(),
	)
	suite.Require().NoError(err)

	payload, err := jws.Verify(suite.newSignedJWS("kid-1"), jws.WithKeyProvider(kp))
	suite.Require().NoError(err)
	suite.JSONEq(`{"sub":"test"}`, string(payload))
}

// TestDeprecatedWithEnforceKeyUsage pins the deprecated option: it selects the
// default, so it must keep working until it is removed.
func (suite *KeyProviderSuite) TestDeprecatedWithEnforceKeyUsage() {
	kp, err := NewKeyProvider(
		WithKeyRing(suite.newRingWithUsage("kid-1", jwk.ForEncryption.String())),
		WithEnforceKeyUsage(), //nolint:staticcheck // deliberately exercising the deprecated option
	)
	suite.Require().NoError(err)

	_, err = jws.Verify(suite.newSignedJWS("kid-1"), jws.WithKeyProvider(kp))
	suite.ErrorIs(err, ErrKeyProviderKeyUsage)
}

// TestKeyUsageEnforced checks each use value under the default: anything other
// than sig is rejected with ErrKeyProviderKeyUsage, while sig and an absent use
// are accepted.  The use comes from the JWKS, via the clortho Key, since the
// jwx key rebuilt from raw material never carries one.
func (suite *KeyProviderSuite) TestKeyUsageEnforced() {
	testCases := []struct {
		name     string
		usage    string
		rejected bool
	}{
		{name: "Encryption", usage: jwk.ForEncryption.String(), rejected: true},
		{name: "Custom", usage: "something-else", rejected: true},
		{name: "Signature", usage: jwk.ForSignature.String(), rejected: false},
		{name: "Unset", usage: "", rejected: false},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			ring := suite.newRingWith("kid-1")
			if tc.usage != "" {
				ring = suite.newRingWithUsage("kid-1", tc.usage)
			}

			kp, err := NewKeyProvider(WithKeyRing(ring))
			suite.Require().NoError(err)

			payload, err := jws.Verify(suite.newSignedJWS("kid-1"), jws.WithKeyProvider(kp))
			if tc.rejected {
				suite.Require().Error(err)
				suite.ErrorIs(err, ErrKeyProviderKeyUsage)
				suite.Nil(payload)
				return
			}

			suite.Require().NoError(err)
			suite.JSONEq(`{"sub":"test"}`, string(payload))
		})
	}
}

func TestKeyProvider(t *testing.T) {
	suite.Run(t, new(KeyProviderSuite))
}
