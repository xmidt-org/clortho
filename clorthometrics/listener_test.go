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

package clorthometrics

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/clortho"
	"github.com/xmidt-org/touchstone"
	"github.com/xmidt-org/touchstone/touchtest"
	"go.uber.org/zap"
)

const (
	RefreshesMetric     = "refreshes"
	RefreshKeysMetric   = "refresh_keys"
	RefreshErrorsMetric = "refresh_errors"

	ResolvesMetric      = "resolves"
	ResolveErrorsMetric = "resolve_errors"

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

	keys []clortho.Key
}

func (suite *ListenerSuite) SetupSuite() {
	p, err := clortho.NewParser()
	suite.Require().NoError(err)
	suite.Require().NotNil(p)

	suite.keys, err = p.Parse(clortho.MediaTypeJWKSet, []byte(keys))
	suite.Require().NoError(err)
}

func (suite *ListenerSuite) newListener(options ...ListenerOption) *Listener {
	l, err := NewListener(options...)
	suite.Require().NoError(err)
	suite.Require().NotNil(l)
	return l
}

func (suite *ListenerSuite) newFactory() (*prometheus.Registry, *touchstone.Factory) {
	r := prometheus.NewPedanticRegistry()
	f := touchstone.NewFactory(touchstone.Config{}, zap.L(), r)
	return r, f
}

func (suite *ListenerSuite) newRefreshes(f *touchstone.Factory) *prometheus.CounterVec {
	cv, err := f.NewCounterVec(
		prometheus.CounterOpts{
			Name: RefreshesMetric,
			Help: RefreshesMetric, // necessary so that help text is consistent for assertions
		},
		SourceLabel,
	)

	suite.Require().NoError(err)
	return cv
}

func (suite *ListenerSuite) newRefreshKeys(f *touchstone.Factory) *prometheus.GaugeVec {
	gv, err := f.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: RefreshKeysMetric,
			Help: RefreshKeysMetric, // necessary so that help text is consistent for assertions
		},
		SourceLabel,
	)

	suite.Require().NoError(err)
	return gv
}

func (suite *ListenerSuite) newRefreshErrors(f *touchstone.Factory) *prometheus.CounterVec {
	cv, err := f.NewCounterVec(
		prometheus.CounterOpts{
			Name: RefreshErrorsMetric,
			Help: RefreshErrorsMetric, // necessary so that help text is consistent for assertions
		},
		SourceLabel,
	)

	suite.Require().NoError(err)
	return cv
}

func (suite *ListenerSuite) newResolves(f *touchstone.Factory) *prometheus.CounterVec {
	cv, err := f.NewCounterVec(
		prometheus.CounterOpts{
			Name: ResolvesMetric,
			Help: ResolvesMetric, // necessary so that help text is consistent for assertions
		},
		SourceLabel, KeyIDLabel,
	)

	suite.Require().NoError(err)
	return cv
}

func (suite *ListenerSuite) newResolveErrors(f *touchstone.Factory) *prometheus.CounterVec {
	cv, err := f.NewCounterVec(
		prometheus.CounterOpts{
			Name: ResolveErrorsMetric,
			Help: ResolveErrorsMetric, // necessary so that help text is consistent for assertions
		},
		SourceLabel, KeyIDLabel,
	)

	suite.Require().NoError(err)
	return cv
}

func (suite *ListenerSuite) testOnRefreshEventNoMetrics() {
	l := suite.newListener()
	l.OnRefreshEvent(clortho.RefreshEvent{
		URI: "http://does.not.matter",
	})
}

func (suite *ListenerSuite) testOnRefreshEventNoError() {
	var (
		expectedRegistry, expectedFactory = suite.newFactory()
		actualRegistry, actualFactory     = suite.newFactory()

		expectedRefreshes   = suite.newRefreshes(expectedFactory)
		expectedRefreshKeys = suite.newRefreshKeys(expectedFactory)

		l = suite.newListener(
			WithRefreshes(suite.newRefreshes(actualFactory)),
			WithRefreshKeys(suite.newRefreshKeys(actualFactory)),
			WithRefreshErrors(suite.newRefreshErrors(actualFactory)),
		)

		metricAssert = touchtest.New(suite.T())
	)

	// refresh_errors should be unused for this test
	suite.newRefreshErrors(expectedFactory)

	expectedRefreshes.With(prometheus.Labels{
		SourceLabel: "http://getkeys.com/keys",
	}).Add(1.0)

	expectedRefreshKeys.With(prometheus.Labels{
		SourceLabel: "http://getkeys.com/keys",
	}).Set(2.0)

	metricAssert.Expect(expectedRegistry)

	l.OnRefreshEvent(clortho.RefreshEvent{
		URI:  "http://getkeys.com/keys",
		Keys: suite.keys,
	})

	metricAssert.GatherAndCompare(
		actualRegistry,
		RefreshesMetric, RefreshKeysMetric, RefreshErrorsMetric,
	)
}

func (suite *ListenerSuite) testOnRefreshEventError() {
	var (
		expectedRegistry, expectedFactory = suite.newFactory()
		actualRegistry, actualFactory     = suite.newFactory()

		expectedRefreshes     = suite.newRefreshes(expectedFactory)
		expectedRefreshKeys   = suite.newRefreshKeys(expectedFactory)
		expectedRefreshErrors = suite.newRefreshErrors(expectedFactory)

		l = suite.newListener(
			WithRefreshes(suite.newRefreshes(actualFactory)),
			WithRefreshKeys(suite.newRefreshKeys(actualFactory)),
			WithRefreshErrors(suite.newRefreshErrors(actualFactory)),
		)

		metricAssert = touchtest.New(suite.T())
	)

	expectedRefreshes.With(prometheus.Labels{
		SourceLabel: "http://getkeys.com/keys",
	}).Add(1.0)

	expectedRefreshKeys.With(prometheus.Labels{
		SourceLabel: "http://getkeys.com/keys",
	}).Set(2.0)

	expectedRefreshErrors.With(prometheus.Labels{
		SourceLabel: "http://getkeys.com/keys",
	}).Add(1.0)

	metricAssert.Expect(expectedRegistry)

	l.OnRefreshEvent(clortho.RefreshEvent{
		URI:  "http://getkeys.com/keys",
		Keys: suite.keys,
		Err:  errors.New("expected"),
	})

	metricAssert.GatherAndCompare(
		actualRegistry,
		RefreshesMetric, RefreshKeysMetric, RefreshErrorsMetric,
	)
}

func (suite *ListenerSuite) TestOnRefreshEvent() {
	suite.Run("NoMetrics", suite.testOnRefreshEventNoMetrics)
	suite.Run("NoError", suite.testOnRefreshEventNoError)
	suite.Run("Error", suite.testOnRefreshEventError)
}

func (suite *ListenerSuite) testOnResolveEventNoMetrics() {
	l := suite.newListener()
	l.OnResolveEvent(clortho.ResolveEvent{
		URI: "http://does.not.matter",
	})
}

func (suite *ListenerSuite) testOnResolveEventNoError() {
	var (
		expectedRegistry, expectedFactory = suite.newFactory()
		actualRegistry, actualFactory     = suite.newFactory()

		expectedResolves = suite.newResolves(expectedFactory)

		l = suite.newListener(
			WithResolves(suite.newResolves(actualFactory)),
			WithResolveErrors(suite.newResolveErrors(actualFactory)),
		)

		metricAssert = touchtest.New(suite.T())
	)

	// resolve_errors should be unused for this test
	suite.newResolveErrors(expectedFactory)

	expectedResolves.With(prometheus.Labels{
		SourceLabel: "http://getkeys.com/A",
		KeyIDLabel:  "A",
	}).Add(1.0)

	metricAssert.Expect(expectedRegistry)

	l.OnResolveEvent(clortho.ResolveEvent{
		URI:   "http://getkeys.com/A",
		KeyID: "A",
		// Keys is unused by the metrics
	})

	metricAssert.GatherAndCompare(
		actualRegistry,
		ResolvesMetric, ResolveErrorsMetric,
	)
}

func (suite *ListenerSuite) testOnResolveEventError() {
	var (
		expectedRegistry, expectedFactory = suite.newFactory()
		actualRegistry, actualFactory     = suite.newFactory()

		expectedResolves      = suite.newResolves(expectedFactory)
		expectedResolveErrors = suite.newResolveErrors(expectedFactory)

		l = suite.newListener(
			WithResolves(suite.newResolves(actualFactory)),
			WithResolveErrors(suite.newResolveErrors(actualFactory)),
		)

		metricAssert = touchtest.New(suite.T())
	)

	expectedResolves.With(prometheus.Labels{
		SourceLabel: "http://getkeys.com/A",
		KeyIDLabel:  "A",
	}).Add(1.0)

	expectedResolveErrors.With(prometheus.Labels{
		SourceLabel: "http://getkeys.com/A",
		KeyIDLabel:  "A",
	}).Add(1.0)

	metricAssert.Expect(expectedRegistry)

	l.OnResolveEvent(clortho.ResolveEvent{
		URI:   "http://getkeys.com/A",
		KeyID: "A",
		Err:   errors.New("expected"),
		// Keys is unused by the metrics
	})

	metricAssert.GatherAndCompare(
		actualRegistry,
		ResolvesMetric, ResolveErrorsMetric,
	)
}

func (suite *ListenerSuite) TestOnResolveEvent() {
	suite.Run("NoMetrics", suite.testOnResolveEventNoMetrics)
	suite.Run("NoError", suite.testOnResolveEventNoError)
	suite.Run("Error", suite.testOnResolveEventError)
}

func (suite *ListenerSuite) TestError() {
	var (
		expectedError = errors.New("expected")
		listener, err = NewListener(errorListenerOption{expectedError: expectedError})
	)

	suite.Nil(listener)
	suite.ErrorIs(err, expectedError)
}

func TestListener(t *testing.T) {
	suite.Run(t, new(ListenerSuite))
}
