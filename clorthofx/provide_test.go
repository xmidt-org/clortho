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
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/fx/fxtest"
)

type ProvideSuite struct {
	suite.Suite
}

func (suite *ProvideSuite) TestDefaults() {
	app := fxtest.New(
		suite.T(),
		Provide(),
	)

	app.RequireStart()
	app.RequireStop()
}

func TestProvide(t *testing.T) {
	suite.Run(t, new(ProvideSuite))
}
