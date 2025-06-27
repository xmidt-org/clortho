// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthofx

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/clortho"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"gopkg.in/h2non/gock.v1"
)

type ProvideSuite struct {
	suite.Suite
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
		context.Background(),
		"test",
	)

	suite.Nil(key)
	suite.Error(err)

	app.RequireStop()
}

// TODO: flesh these tests out with gock, possibly using
// an internal package for the common testing code
func TestProvide(t *testing.T) {
	suite.Run(t, new(ProvideSuite))
}
