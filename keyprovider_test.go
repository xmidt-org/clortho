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
	"errors"
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
	kp, err := NewKeyProvider(WithRingKey(suite.newRing(kid, raw)))
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

// TestNoOptions is the regression guard for the nil key ring panic.
func (suite *KeyProviderSuite) TestNoOptions() {
	kp, err := NewKeyProvider()

	suite.Nil(kp)
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrKeyProviderNoKeyRing)
}

func (suite *KeyProviderSuite) TestNilKeyRing() {
	kp, err := NewKeyProvider(WithRingKey(nil))

	suite.Nil(kp)
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrKeyProviderNoKeyRing)
}

func (suite *KeyProviderSuite) TestOptionError() {
	expectedErr := errors.New("expected option failure")
	failingOption := keyProviderOptionFunc(func(*keyProvider) error {
		return expectedErr
	})

	kp, err := NewKeyProvider(failingOption, WithRingKey(NewKeyRing()))

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
	kp, err := NewKeyProvider(WithRingKey(NewKeyRing()))

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
	kp, err := NewKeyProvider(WithRingKey(suite.newRingWith("kid-1")))

	suite.Require().NoError(err)
	suite.Require().NotNil(kp)

	payload, err := jws.Verify(suite.newSignedJWS("kid-1"), jws.WithKeyProvider(kp))
	suite.Require().NoError(err)
	suite.JSONEq(`{"sub":"test"}`, string(payload))
}

func (suite *KeyProviderSuite) TestMissingKeyID() {
	kp, err := NewKeyProvider(WithRingKey(suite.newRingWith("kid-1")))
	suite.Require().NoError(err)

	unsigned, err := jws.Sign(
		[]byte(`{"sub":"test"}`),
		jws.WithKey(jwa.RS256(), suite.privateKey),
	)
	suite.Require().NoError(err)

	_, err = jws.Verify(unsigned, jws.WithKeyProvider(kp))
	suite.Error(err)
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
			name:    "Symmetric",
			ringKey: suite.symmetricKey,
			alg:     jwa.HS256(),
			signKey: suite.symmetricKey,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			kp := suite.newKeyProvider("kid-1", tc.ringKey)

			payload, err := jws.Verify(
				suite.sign(tc.alg, tc.signKey, "kid-1"),
				jws.WithKeyProvider(kp),
			)

			suite.Require().NoError(err)
			suite.JSONEq(`{"sub":"test"}`, string(payload))
		})
	}
}

// TestNoRefreshSources checks that a provider built with a Config that has no
// refresh sources is rejected.  Keys reach the verifier only through the
// refreshed ring, so such a deployment would answer every token with "key not
// found" while its configuration looked correct.
func (suite *KeyProviderSuite) TestNoRefreshSources() {
	kp, err := NewKeyProvider(
		WithRingKey(NewKeyRing()),
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
		WithRingKey(suite.newRingWith("kid-1")),
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

func TestKeyProvider(t *testing.T) {
	suite.Run(t, new(KeyProviderSuite))
}
