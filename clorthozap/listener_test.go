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

package clorthozap

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type ListenerSuite struct {
	suite.Suite
}

// newTestLogger creates a logger with the given level enabled and standard log message keys.
// The returned *bytes.Buffer can be used to examine log output.
func (suite *ListenerSuite) newTestLogger(level zapcore.Level) (*zap.Logger, *bytes.Buffer) {
	b := new(bytes.Buffer)
	return zap.New(
		zapcore.NewCore(
			zapcore.NewJSONEncoder(zapcore.EncoderConfig{
				MessageKey: "msg",
				LevelKey:   "level",
			}),
			zapcore.AddSync(b),
			level,
		),
	), b
}

func (suite *ListenerSuite) TestOnRefreshEvent() {
}

func TestListener(t *testing.T) {
	suite.Run(t, new(ListenerSuite))
}
