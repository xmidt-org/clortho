/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

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
