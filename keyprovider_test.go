// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"crypto/rand"
	"crypto/rsa"
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
}

func (suite *KeyProviderSuite) SetupSuite() {
	var err error
	suite.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	suite.Require().NoError(err)
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
	jk, err := jwk.Import[jwk.Key](&suite.privateKey.PublicKey)
	suite.Require().NoError(err)
	suite.Require().NoError(jk.Set(jwk.KeyIDKey, kid))

	k, err := convertJWKKey(jk)
	suite.Require().NoError(err)

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

func TestKeyProvider(t *testing.T) {
	suite.Run(t, new(KeyProviderSuite))
}
