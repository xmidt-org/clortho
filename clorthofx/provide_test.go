// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthofx

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/clortho"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"gopkg.in/h2non/gock.v1"
)

type ProvideSuite struct {
	suite.Suite

	// publicKey is an RSA public key with kid "kid-1", for adding to a ring
	publicKey clortho.Key
}

func (suite *ProvideSuite) SetupSuite() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	suite.Require().NoError(err)

	jk, err := jwk.Import[jwk.Key](&privateKey.PublicKey)
	suite.Require().NoError(err)
	suite.Require().NoError(jk.Set(jwk.KeyIDKey, "kid-1"))

	publicJWK, err := json.Marshal(jk)
	suite.Require().NoError(err)

	p, err := clortho.NewParser()
	suite.Require().NoError(err)
	keys, err := p.Parse(clortho.MediaTypeJWK, publicJWK)
	suite.Require().NoError(err)
	suite.Require().Len(keys, 1)
	suite.publicKey = keys[0]
}

func (suite *ProvideSuite) TearDownTest() {
	gock.OffAll()
}

// newFxTest creates a test App using the supplied options
func (suite *ProvideSuite) newFxTest(o ...fx.Option) *fxtest.App {
	app := fxtest.New(
		suite.T(),
		o...,
	)

	suite.Require().NotNil(app)
	suite.Require().NoError(app.Err())
	return app
}

func (suite *ProvideSuite) TestDefaults() {
	var (
		kr        clortho.KeyRing
		resolver  clortho.Resolver
		refresher clortho.Refresher

		app = suite.newFxTest(
			Provide(),
			fx.Populate(
				&kr,
				&resolver,
				&refresher,
			),
		)
	)

	app.RequireStart()

	suite.Require().NotNil(kr)
	suite.Require().NotNil(resolver)
	suite.Require().NotNil(refresher)

	// TODO: how best to test the refresher here?

	key, err := resolver.Resolve(
		clortho.SetContentMeta(context.Background(), clortho.ContentMeta{}),
		"test",
	)

	suite.Nil(key)
	suite.Error(err)

	app.RequireStop()
}

// TestResolverNoTemplate checks the module's Resolver for an application with
// no resolve template configured, which is every refresh-only consumer.  The
// module still provides a Resolver; it serves the ring and reports ErrNoTemplate
// on a miss.
func (suite *ProvideSuite) TestResolverNoTemplate() {
	var (
		kr       clortho.KeyRing
		resolver clortho.Resolver

		app = suite.newFxTest(
			Provide(),
			fx.Populate(&kr, &resolver),
		)
	)

	app.RequireStart()
	defer app.RequireStop()

	key, err := resolver.Resolve(context.Background(), "kid-1")
	suite.Nil(key)
	suite.ErrorIs(err, clortho.ErrNoTemplate)

	kr.Add(suite.publicKey)

	key, err = resolver.Resolve(context.Background(), "kid-1")
	suite.Require().NoError(err)
	suite.Equal(suite.publicKey, key)
}

// TODO: flesh these tests out with gock, possibly using
// an internal package for the common testing code
func TestProvide(t *testing.T) {
	suite.Run(t, new(ProvideSuite))
}
