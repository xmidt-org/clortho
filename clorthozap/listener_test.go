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
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/clortho"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

const (
	// keys is a jwk set used to stand-in for an event's Keys field
	keys = `{
    "keys": [
        {
		    "kid": "A",
            "p": "yD2VKf9BGOHp1dbWKg7m4dccMnYvxCrzpq6S3-cO9egK6IJYFeA5AidCsAZiQaVuFCigoFgelEQIatjjcNdhZE_ideul7xjIkaoj6AJ48nZheYmvunKDUIus_3UqV18tJ7Lofiz0u5dVZe_R9NbYH4n53lX7fcOLMcIuHkIP2f8",
            "kty": "RSA",
            "q": "wK5h6m64OBedeRA1Kq-Uqjg5rzeBuXhfOHiOSB6yCdMTbgtRmouUYdm-eQ61f1B2YtZY2sl35AibzD8FALR9FxHb9fe1EkJ9GJBZVmJA9Aazd4f71SOJ7vcWlgo5awDH3dv4Mn_NgiRkLLedADvB9HxWcTxjYeXkEEqPHUmlb_U",
            "d": "hpz_FlBnWDop_JzW6EGwQV3sM2nvU-8HfjquekXe5xju0rISoYzX7qxvI3uXkzJeWsOnYpI5RdWXGgfzCDlhPP5SLml9kYbqTjzbOVSmXBrgTPF1MNdeYH-DiGu2rfh8WO7ziGMybTmEZ7DWm6Y3jYI-Bm3dWhW_8FX2FQbOIUJlX82Z25lKepaNPAUOywM7mf4BVLwroYIyc1iB8tTFtdNnRMou1IsAn-FEkySp9I2AnmPlVEuoRHo4TBonb-b4clMrsWoB3NLfNDbgrTrFTd3z6SRSKVTJbxqR-EODumhUK0KRiKX36N6-pvPvDsAEoaCUTH63HLAUaSqWN_yvwQ",
            "e": "AQAB",
            "qi": "dcm8P4aN5RRYR-4M-9Z4VWUlF7dXLR3TN-BNOvhQHB22vGwbtLQhpL0NY1ppl-FtCr4ExXXahYIAp-Lmsw4fnqbiCsXTXn93Boa1pJopB2R-JCf2_fyoJg0Slsjb2yqjqwW8M9h1uiojHeyxuDOay8z3yzbgXt8w4NeUEC4spUs",
            "dp": "iSvepjFtB72i8VFFzvP8aBNzBoJ-AFUoKjQG-4kOb5hw-IxqCTpb80Sv42PMJYpNGVQnjRAwioL8fS1syR1SY2RyDzPJrTv-EgNKq6Id9oLwDVEr536QxDma3jkGM2pIxZxCtkTXtjZaUwVxf9c5oIlleVDPgnzVOtX5v9Kjh0M",
            "dq": "E2L4UyAkxPALVhz9XHgiGyZhF3IcSU8FNadbmYINI9PrBo14_nXAzj-cXI3QUSkFYFh0xD61I2qCUoCcvj9qvqF7Yjo0K8wozgnoEzr7khICiKpT-lQDEtolmZ8Zu9xuP7JcPKiDQu7qbV1kHJvmnfTMtcP_s9_vnHwD_kxkquk",
            "n": "lraWUZZmIT6IDyTtO_ho-XMPyPUPoT97P00P3uvaRU792L-cuQJQzOcvRGBnEQMe4Yj7yzYtPQwgiUjvYcXkmRnr-R-lSreGDsu8XLcM-8WgPV_6jVUet9AD9Af5HWuhVNKtJdmzlxdX7XrU_E_-i_2r2_IFkA4bzmoJ6hWiwok-VssktCvvIgxLB7tu2D3tzS6bDTtgTwfOjun4UJXltkKbX6lI_nDfYXjV5w4nlS-axQ5Hj6lHJKmE5a1mo7AyFvUY9DWMbMBY2Dy_wigV5heSz17rNPVLSJAoYrB34N31g8gCoOVe3GWaGKCzPSRcmE1l2H9taL11c33eUQwyCw"
        },
        {
		    "kid": "B",
            "kty": "EC",
            "d": "pEKRYzqBzvAfIlPxppQG8hSxtJxRm-DLqpCPjx26bEDwCIz2JdISM-lGV1euPIhl",
            "crv": "P-384",
            "x": "jhH5USR4IO3uaURYSn4z8IDn7MnWGGa76eNZTvI8Zc08XSQ0YzikcZtLAVUw1zoc",
            "y": "uILRhb6eP2PnfSk1xBdttboPXJO_o21Ho0Tb5de6kb46BGaVLPD-RC6zJ2KmYWIm"
        }
    ]
}`

	// newKeys is a jwk set intended to stand in for an event's New field
	newKeys = `{
    "keys": [
        {
            "kid": "C",
            "kty": "EC",
            "d": "AK88liJbuM-sg_6EqvzKLFaMt0oIvDXucmnwK8Vza7JAR0Sal4W0kdiPVpbxcrHsx1M8bx8qP-dQFkBc3dpO7fxY",
            "crv": "P-521",
            "x": "AScg7sADU-hQFjnmhekzqLpRKj4XXUd2jJQNGfGkQT4bC4FArVvP0vamuLsABiqZr4QqXPj_ilWvNDh8umRVxU5c",
            "y": "AF_9M9_DK0sfAdIzVUvGsOSZPfNavvYZiJAwqGnRNdzjH2r1VantDqoYftFqsd6c50NKYraRXmdverwBci5_VuA3"
        },
        {
            "kid": "D",
            "kty": "OKP",
            "d": "283roMFHvoICtcZJC5DsdkHLJMNYWD4z-u-LmyHakmg",
            "crv": "Ed25519",
            "x": "mNGL9p0Ll7e6HXXVYUJ2Vb1zKT5Uw6vIihG7urY2bpY"
        }
    ]
}`

	// deletedKeys is a jwk set that stands in for an event's Deleted field
	deletedKeys = `{
    "keys": [
        {
            "kid": "E",
            "kty": "oct",
            "k": "yRE408XjhgbOtiyMRoNm7xEKqibpDYPY0m1pNRYy_VoTGw3l6Fnhhvi6lUwOLjix4pxH9jQpsg531oxonQ_Guq3bm3zyUI_cBXVwtmg1lDTMjo06YRdrOjtj4f-61pCZfz7xc-GYf9uoyxgtb2yIxQq1cve37qtoUhkoGtkO13TmtFTpxtc8ueWSt7Arp2zCrrIu9jrF2xKQNL4P6P0TNfUWjE4E42AqI8Ux4TEBAyh_lVkicVDeQJrvNJ3j6toNDBfuScdJGxrklhprapWrhBYTMRMtBYvkcZwxx8YTfsBBvLUTyl4U1-xjJMekJe3bF1mwDz9gOaREjEkzJjxaJw"
        },
        {
            "p": "3zv6eF8jeXk9WVk8edMgXVw2rwQlddo4fuy6ZXUwRLJLjJhQsBfcL2KcWR2_HGL9TltjTPfAWubYhCTBJTZf9Q",
            "kty": "RSA",
            "q": "0_IHxLuP1Wb8Uhta0REciA2Sn71RCRITVX-p-IzvB2ALTkohynMrtW28hWVGrWbSqaCrn4Ng519APkOHAgWK8Q",
            "d": "rhRbhTOHMt_YFOM_lBJyJcd0ggC4poLShxVrNS3aSUGb_8oQpPHVV9E0X4dA-awKDiL6Pt54R1bmmpIGk6K9mhcD82wZlXTWqk1E-vSvU9PgB8SvPQBDVecBSCb1uciPKh4QDBHNydaZZ1ANAFW9wDrMuw-xJpCEY-zrEPEW1ME",
            "e": "AQAB",
            "kid": "F",
            "qi": "1Lgvy6YUKvoGOEXlDIARvlCckDZuo6HzsP8ozdmMnyRLiAjTwkv67r8_aqd-XJnbZxPTWtIxukraqdtvlKy8Aw",
            "dp": "ENSHzL13gjgGzQ6yRYkKXp-OK-HHJTx_l-onH3EXY4aBtabiJnSWECiCGyHn_67i5B51vR7MrM3MsyHGQhT4ZQ",
            "dq": "mU9jyy0Zd_ZM4l-jK8PC7a9TtnTNH1CR57C3FHFtndodk34QP09b-JruWVfO7jOIgucT_gicmgDOibty90VnIQ",
            "n": "uNF86i2Hd_gdtpnNsS_--PGsOaJPYbnCfStZ-aBF5pxUBvnNQnGRJz0RVYI8PteLF6FyRBuM2WQETXR4LMt2_OmaYlY9gXT0ok-DmsmGt6g0aCN1mxrXTdFThJ7k7Nkf5i6Jn7YM0q_2pVLuonvCh6PvF_yvT3-SomaX5iGzZ6U"
        }
    ]
}`
)

// errorListenerOption is a ListenerOption that returns an error.
// This type is necessary because we currently don't have an option
// that we can test NewListener when it returns an error.
type errorListenerOption struct {
	expectedError error
}

func (elo errorListenerOption) applyToListener(l *Listener) error {
	return elo.expectedError
}

type ListenerSuite struct {
	suite.Suite

	keys        clortho.Keys
	newKeys     clortho.Keys
	deletedKeys clortho.Keys
}

func (suite *ListenerSuite) SetupSuite() {
	p, err := clortho.NewParser()
	suite.Require().NoError(err)
	suite.Require().NotNil(p)

	suite.keys, err = p.Parse(clortho.MediaTypeJWKSet, []byte(keys))
	suite.Require().NoError(err)
	suite.Require().Len(suite.keys, 2)

	suite.newKeys, err = p.Parse(clortho.MediaTypeJWKSet, []byte(newKeys))
	suite.Require().NoError(err)
	suite.Require().Len(suite.newKeys, 2)

	suite.deletedKeys, err = p.Parse(clortho.MediaTypeJWKSet, []byte(deletedKeys))
	suite.Require().NoError(err)
	suite.Require().Len(suite.deletedKeys, 2)
}

func (suite *ListenerSuite) unmarshalEntry(b *bytes.Buffer) (m map[string]interface{}) {
	suite.Require().NotEmpty(b.Bytes())
	suite.Require().NoError(json.Unmarshal(b.Bytes(), &m))
	return
}

func (suite *ListenerSuite) assertRefreshEntry(b *bytes.Buffer, expectedEvent clortho.RefreshEvent, expectedLevel zapcore.Level) {
	m := suite.unmarshalEntry(b)

	suite.Equal(expectedEvent.URI, m["uri"])
	suite.ElementsMatch(expectedEvent.Keys.AppendKeyIDs(nil), m["keys"])
	suite.ElementsMatch(expectedEvent.New.AppendKeyIDs(nil), m["new"])
	suite.ElementsMatch(expectedEvent.Deleted.AppendKeyIDs(nil), m["deleted"])
	suite.Equal(expectedLevel.String(), m["level"])

	if expectedEvent.Err != nil {
		suite.Equal(expectedEvent.Err.Error(), m["error"])
	} else {
		suite.Nil(m["error"])
	}
}

func (suite *ListenerSuite) assertResolveEntry(b *bytes.Buffer, expectedEvent clortho.ResolveEvent, expectedLevel zapcore.Level) {
	m := suite.unmarshalEntry(b)

	suite.Equal(expectedEvent.URI, m["uri"])
	suite.Equal(expectedEvent.KeyID, m["keyID"])
	suite.Equal(expectedLevel.String(), m["level"])

	if expectedEvent.Err != nil {
		suite.Equal(expectedEvent.Err.Error(), m["error"])
	} else {
		suite.Nil(m["error"])
	}
}

// newTestLogger creates a logger with the given level enabled and standard log message keys.
// The returned *bytes.Buffer can be used to examine log output.
func (suite *ListenerSuite) newTestLogger(level zapcore.Level) (*zap.Logger, *bytes.Buffer) {
	b := new(bytes.Buffer)
	return zap.New(
		zapcore.NewCore(
			zapcore.NewJSONEncoder(zapcore.EncoderConfig{
				MessageKey:  "msg",
				LevelKey:    "level",
				EncodeLevel: zapcore.LowercaseLevelEncoder, // this matches Level.String()
			}),
			zapcore.AddSync(b),
			level,
		),
	), b
}

func (suite *ListenerSuite) newListener(options ...ListenerOption) *Listener {
	listener, err := NewListener(options...)
	suite.Require().NoError(err)
	suite.Require().NotNil(listener)
	return listener
}

func (suite *ListenerSuite) testOnRefreshEventNoError() {
	testCases := []struct {
		description string
		event       clortho.RefreshEvent
	}{
		{
			description: "keys only",
			event: clortho.RefreshEvent{
				URI:  "http://getkeys.com",
				Keys: suite.keys,
			},
		},
		{
			description: "keys and new",
			event: clortho.RefreshEvent{
				URI:  "http://getkeys.com",
				Keys: suite.keys,
				New:  suite.newKeys,
			},
		},
		{
			description: "keys and deleted",
			event: clortho.RefreshEvent{
				URI:     "http://getkeys.com",
				Keys:    suite.keys,
				Deleted: suite.deletedKeys,
			},
		},
		{
			description: "all",
			event: clortho.RefreshEvent{
				URI:     "http://getkeys.com",
				Keys:    suite.keys,
				New:     suite.newKeys,
				Deleted: suite.deletedKeys,
			},
		},
	}

	for _, testCase := range testCases {
		suite.Run(testCase.description, func() {
			suite.Run("DefaultLevel", func() {
				suite.Run(testCase.description, func() {
					var (
						logger, output = suite.newTestLogger(zapcore.InfoLevel)
						listener       = suite.newListener(WithLogger(logger))
					)

					suite.Empty(output.Bytes())
					listener.OnRefreshEvent(testCase.event)
					suite.assertRefreshEntry(output, testCase.event, zapcore.InfoLevel)
				})
			})

			suite.Run("CustomLevel", func() {
				suite.Run(testCase.description, func() {
					var (
						logger, output = suite.newTestLogger(zapcore.DebugLevel)
						listener       = suite.newListener(WithLogger(logger), WithLevel(zap.DebugLevel))
					)

					suite.Empty(output.Bytes())
					listener.OnRefreshEvent(testCase.event)
					suite.assertRefreshEntry(output, testCase.event, zapcore.DebugLevel)
				})
			})
		})
	}
}

func (suite *ListenerSuite) testOnRefreshEventError() {
	var (
		expectedError  = errors.New("expected")
		logger, output = suite.newTestLogger(zapcore.ErrorLevel)
		listener       = suite.newListener(WithLogger(logger))

		event = clortho.RefreshEvent{
			URI:  "http://badkeys.com",
			Keys: suite.keys,
			Err:  expectedError,
		}
	)

	suite.Empty(output.Bytes())
	listener.OnRefreshEvent(event)
	suite.assertRefreshEntry(output, event, zapcore.ErrorLevel)
}

func (suite *ListenerSuite) testOnRefreshEventDisabled() {
	var (
		logger, output = suite.newTestLogger(zapcore.PanicLevel)
		listener       = suite.newListener(WithLogger(logger))
	)

	suite.Empty(output.Bytes())
	listener.OnRefreshEvent(clortho.RefreshEvent{
		URI: "http://does.not.matter",
	})

	suite.Empty(output.Bytes())
}

func (suite *ListenerSuite) TestDefault() {
	listener, err := NewListener()
	suite.Require().NoError(err)
	suite.NotNil(listener.logger)
}

func (suite *ListenerSuite) TestError() {
	var (
		expectedError = errors.New("expected")
		listener, err = NewListener(errorListenerOption{expectedError: expectedError})
	)

	suite.Nil(listener)
	suite.ErrorIs(err, expectedError)
}

func (suite *ListenerSuite) TestOnRefreshEvent() {
	suite.Run("NoError", suite.testOnRefreshEventNoError)
	suite.Run("Error", suite.testOnRefreshEventError)
	suite.Run("Disabled", suite.testOnRefreshEventDisabled)
}

func (suite *ListenerSuite) testOnResolveEventNoError() {
	var (
		logger, output = suite.newTestLogger(zapcore.InfoLevel)
		listener       = suite.newListener(WithLogger(logger))

		event = clortho.ResolveEvent{
			URI:   "https://getkeys.com/foo",
			KeyID: "foo",
			// NOTE: we don't use the Key field for logging
		}
	)

	suite.Empty(output.Bytes())
	listener.OnResolveEvent(event)
	suite.assertResolveEntry(output, event, zapcore.InfoLevel)
}

func (suite *ListenerSuite) testOnResolveEventError() {
	var (
		expectedError = errors.New("expected")

		logger, output = suite.newTestLogger(zapcore.ErrorLevel)
		listener       = suite.newListener(WithLogger(logger))

		event = clortho.ResolveEvent{
			URI:   "https://getkeys.com/foo",
			KeyID: "foo",
			// NOTE: we don't use the Key field for logging
			Err: expectedError,
		}
	)

	suite.Empty(output.Bytes())
	listener.OnResolveEvent(event)
	suite.assertResolveEntry(output, event, zapcore.ErrorLevel)
}

func (suite *ListenerSuite) testOnResolveEventDisabled() {
	var (
		logger, output = suite.newTestLogger(zapcore.PanicLevel)
		listener       = suite.newListener(WithLogger(logger))
	)

	suite.Empty(output.Bytes())
	listener.OnResolveEvent(clortho.ResolveEvent{
		URI: "http://does.not.matter",
	})

	suite.Empty(output.Bytes())
}

func (suite *ListenerSuite) TestOnResolveEvent() {
	suite.Run("NoError", suite.testOnResolveEventNoError)
	suite.Run("Error", suite.testOnResolveEventError)
	suite.Run("Disabled", suite.testOnResolveEventDisabled)
}

func TestListener(t *testing.T) {
	suite.Run(t, new(ListenerSuite))
}
