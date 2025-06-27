// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/chronon"
)

const (
	// refresherSet1 contains (3) keys with ids A, B, and C.
	refresherSet1 = `
{
	"keys": [
        {
		    "kid": "A",
            "p": "2LUcSydys1EKBIapx7zSx65JZwQmHWgiVCSTBCwXLKoAb-5yY1AjkrFL4E3TJMvETPMltGuxJR1jzhLtGDatYudgRlxDE8pwaumDo7b1ztAJuFpQ9t71H-E2FtBs03lYEB8CvH0BOO9ksGF03XPy1ygApZmT7M1WVatgi1siQ_s",
            "kty": "RSA",
            "q": "1QAUnp6Ysjsh6zBLl_OeLH52xt1Fdso3SK4opjabgs_6yIK8lYiEuDxF4T1iPpJh1gZVUEhqxTk-GHdPFc0sC2LGNfDp9g2L2ZeRBxU8Xf7LwMCWY4peGnUDm3peAGXsSD85vf-NryBa-CeYpEZCJga9sHVffPbi-Mh07w24MAs",
            "d": "pNLeCfcIKhUB854LxXSQvJZZ61XaonccA9mg04VNhkjrfiuLz9JdWhmkvb-qryBFy4HJEwbSCFOe9k5l4D3K3PmrBZX_vLwHsqT0d4O88Ecp_RV7hzsW9LE4eMNy1h_jSVLBoBVX6mIkmsjuhBsGe4vC9qR-Mc34c7eYeSIchcQ9Xve7tlCfKDCNd4pKsXbk7nfsNJhDZV6Ny1fvk2fskdSMh0HSXyrgUi3KAnIiKtaQ-BCJpbx57jF1i1ezmKbQsnR4l7MZj_Ad2ry-OuKqouz6CVLFkfr5CE0QzHZeJU80vumho-WC-Gqb48BOYaiCXUmRzf_lBBKfGVDbcB_O1Q",
            "e": "AQAB",
            "qi": "N2jrLIDuuZjh7T0GTJFXupl04OAly8-LM97XZgWnZaitGUoUgdlEr6frNevZK6_D3YRQyJEU08vZtwsuywLK-6pEP_1wq-REXTAXa0Hr-XQ0A7zGRud12kP1J7fomsN9MzFvcokLGMxviY5R8WNo7J9wCfEFJuCDEycKm271UTc",
            "dp": "wbdkS2pABjtzEQivzHTmlskdpJD44WCtDzqCkUA4lxyAt44Xgt-obQFAKopnLIVaPM897UI3YE4dYaFZgEOgSsE6NqtS6uYUB_4mRrrOkMk3ZyyVI5m61XyktVArd_8I0aBm-cdkyFh3UZRMu4likyKXMXFP4mbLvlksPGaDAvE",
            "dq": "XHOif47bPFFKUakuxo-pkip6J6sXYY44HMXrQunk6gyYD7wfWtBcuxL-Sdu47uvep2UsVqJ4JY7JExmGLDJX8cE3w2YERxZuI04UVvyyrSHREqMFI8OFQPqVTED62DVlL56x03Q-7Uqf8aJOMM-GGrdGUnc_sSAAOHfZuYE89y0",
            "n": "tE7B_vQQzojnOzImvPxUhxzvhpLBwSHiQ1OBJMm_kVX_A2bOvaA-aDNgGKHVoX_Iq5uZwW6fnZIiY9XINmeAF0PpwmTlCQlmBAcxMuGZNroFEarN-jDv16DIOyg4r41zlLxSWN5XJTlAZ5IQ5oRrNzkR76YLlw1c_JPRSgAnATpH_8vgpGC4euCARGGtfmARacmn2ej4WEluTiUKgdarZhuAWY3yCO2Mt7YJLgmWNI2SVMhkGk1JMTxJyqHpChXrMM2AcWBw9qTVdipXJ0lHJECgWMCgC6soD83oH42THHfvZPwzKmuhjv0GvQpsDt7SMaCp8D4iK3YoJLh88p_7yQ"
        },
        {
		    "kid": "B",
            "kty": "EC",
            "d": "ACQIK3SUBxteXSOwVtCitAeHhLYiEwK4xtVyVkF_xyrVrEEaIND3QtVW9YOhR6x1yAjUbSQgk53CQ0pcQgDfWQMI",
            "crv": "P-521",
            "x": "AaWvCYZyNVxBi8dSESLB8c6eWKIpkd43hanGSvgpXDY5TylUmU_WteOMNnniO5q1rQ8C6pH30Doz9yJfwEFPI0Wc",
            "y": "ASI0jYOMOjC_8SUcMOpZampPMkBxGpIBOO5OZ3Sf9eB8FWoFDRz5tgF2vDPgdDsV8O29xfI3MS0B0_gQT4gzu0Me"
        },
        {
		    "kid": "C",
            "kty": "oct",
            "k": "V9ikjQsxcZ9dhEo0GERTXYOTyIkwVXsU3o4_LFGwBJletL1d8vNgtKtUCij9UcZRTHS5MRg6HqGBxYPcLGo35zcFUjM7QxFZSoIjcgq5z-1U9viyh7opIhYEzUwVZFyzMK6JbfHCyXdVwoSGSyyuSCyCa_vBCIxVutTbh4TLsto"
        }
    ]
}`

	// refresherSet2 contains keys A and C from refresherSet1 and a new key with kid D.
	refresherSet2 = `
{
	"keys": [
        {
		    "kid": "A",
            "p": "2LUcSydys1EKBIapx7zSx65JZwQmHWgiVCSTBCwXLKoAb-5yY1AjkrFL4E3TJMvETPMltGuxJR1jzhLtGDatYudgRlxDE8pwaumDo7b1ztAJuFpQ9t71H-E2FtBs03lYEB8CvH0BOO9ksGF03XPy1ygApZmT7M1WVatgi1siQ_s",
            "kty": "RSA",
            "q": "1QAUnp6Ysjsh6zBLl_OeLH52xt1Fdso3SK4opjabgs_6yIK8lYiEuDxF4T1iPpJh1gZVUEhqxTk-GHdPFc0sC2LGNfDp9g2L2ZeRBxU8Xf7LwMCWY4peGnUDm3peAGXsSD85vf-NryBa-CeYpEZCJga9sHVffPbi-Mh07w24MAs",
            "d": "pNLeCfcIKhUB854LxXSQvJZZ61XaonccA9mg04VNhkjrfiuLz9JdWhmkvb-qryBFy4HJEwbSCFOe9k5l4D3K3PmrBZX_vLwHsqT0d4O88Ecp_RV7hzsW9LE4eMNy1h_jSVLBoBVX6mIkmsjuhBsGe4vC9qR-Mc34c7eYeSIchcQ9Xve7tlCfKDCNd4pKsXbk7nfsNJhDZV6Ny1fvk2fskdSMh0HSXyrgUi3KAnIiKtaQ-BCJpbx57jF1i1ezmKbQsnR4l7MZj_Ad2ry-OuKqouz6CVLFkfr5CE0QzHZeJU80vumho-WC-Gqb48BOYaiCXUmRzf_lBBKfGVDbcB_O1Q",
            "e": "AQAB",
            "qi": "N2jrLIDuuZjh7T0GTJFXupl04OAly8-LM97XZgWnZaitGUoUgdlEr6frNevZK6_D3YRQyJEU08vZtwsuywLK-6pEP_1wq-REXTAXa0Hr-XQ0A7zGRud12kP1J7fomsN9MzFvcokLGMxviY5R8WNo7J9wCfEFJuCDEycKm271UTc",
            "dp": "wbdkS2pABjtzEQivzHTmlskdpJD44WCtDzqCkUA4lxyAt44Xgt-obQFAKopnLIVaPM897UI3YE4dYaFZgEOgSsE6NqtS6uYUB_4mRrrOkMk3ZyyVI5m61XyktVArd_8I0aBm-cdkyFh3UZRMu4likyKXMXFP4mbLvlksPGaDAvE",
            "dq": "XHOif47bPFFKUakuxo-pkip6J6sXYY44HMXrQunk6gyYD7wfWtBcuxL-Sdu47uvep2UsVqJ4JY7JExmGLDJX8cE3w2YERxZuI04UVvyyrSHREqMFI8OFQPqVTED62DVlL56x03Q-7Uqf8aJOMM-GGrdGUnc_sSAAOHfZuYE89y0",
            "n": "tE7B_vQQzojnOzImvPxUhxzvhpLBwSHiQ1OBJMm_kVX_A2bOvaA-aDNgGKHVoX_Iq5uZwW6fnZIiY9XINmeAF0PpwmTlCQlmBAcxMuGZNroFEarN-jDv16DIOyg4r41zlLxSWN5XJTlAZ5IQ5oRrNzkR76YLlw1c_JPRSgAnATpH_8vgpGC4euCARGGtfmARacmn2ej4WEluTiUKgdarZhuAWY3yCO2Mt7YJLgmWNI2SVMhkGk1JMTxJyqHpChXrMM2AcWBw9qTVdipXJ0lHJECgWMCgC6soD83oH42THHfvZPwzKmuhjv0GvQpsDt7SMaCp8D4iK3YoJLh88p_7yQ"
        },
        {
		    "kid": "C",
            "kty": "oct",
            "k": "V9ikjQsxcZ9dhEo0GERTXYOTyIkwVXsU3o4_LFGwBJletL1d8vNgtKtUCij9UcZRTHS5MRg6HqGBxYPcLGo35zcFUjM7QxFZSoIjcgq5z-1U9viyh7opIhYEzUwVZFyzMK6JbfHCyXdVwoSGSyyuSCyCa_vBCIxVutTbh4TLsto"
        },
        {
		    "kid": "D",
            "kty": "OKP",
            "d": "X84lrN4j7cdeI2qRuNMePBd8jZc2k2kPBPBpJtOGo8Y",
            "crv": "Ed25519",
            "x": "dAQ68LJi1emSeLjSwegvjJd-rdorG1jw0zpHwP2g67A"
        }
    ]
}`
)

type RefresherSuite struct {
	suite.Suite

	set1 []Key
	set2 []Key
}

func (suite *RefresherSuite) SetupTest() {
	p, err := NewParser()
	suite.Require().NoError(err)
	suite.Require().NotNil(p)

	suite.set1, err = p.Parse(MediaTypeJWKSet, []byte(refresherSet1))
	suite.Require().NoError(err)
	suite.Require().Len(suite.set1, 3)

	suite.set2, err = p.Parse(MediaTypeJWKSet, []byte(refresherSet2))
	suite.Require().NoError(err)
	suite.Require().Len(suite.set2, 3)
}

func (suite *RefresherSuite) newRefresher(options ...RefresherOption) Refresher {
	r, err := NewRefresher(options...)
	suite.Require().NoError(err)
	suite.Require().NotNil(r)
	return r
}

// newClockFor creates a fake clock for the given Refresher and returns that clock
// to control tasks.  This method should always be called before Start.
func (suite *RefresherSuite) newClockFor(r Refresher) *chronon.FakeClock {
	suite.Require().IsType((*refresher)(nil), r)
	fc := chronon.NewFakeClock(time.Now())
	r.(*refresher).clock = fc
	return fc
}

func (suite *RefresherSuite) TestDefault() {
	r := suite.newRefresher()
	suite.Require().IsType((*refresher)(nil), r)

	suite.NotNil(r.(*refresher).fetcher)
	suite.Empty(r.(*refresher).sources)
	suite.NotNil(r.(*refresher).clock)
}

func (suite *RefresherSuite) getTimer(ch <-chan chronon.FakeTimer) (timer chronon.FakeTimer) {
	select {
	case <-time.After(2 * time.Second):
		suite.Fail("Refresh tasks did not start")
	case timer = <-ch:
		// passing
	}

	return
}

func (suite *RefresherSuite) testRefresh(source RefreshSource) {
	var (
		f = new(mockFetcher)
		r = suite.newRefresher(
			WithFetcher(f),
			WithSources(source),
		)

		expectedError = errors.New("expected")
		listener      = new(mockRefreshListener)
		fc            = suite.newClockFor(r)
		timerCh       = make(chan chronon.FakeTimer, 1)

		matchContext = func(ctx context.Context) bool {
			return suite.NotEqual(context.Background(), ctx)
		}
	)

	r.AddListener(listener)
	fc.NotifyOnTimer(timerCh)

	f.ExpectFetchCtx(matchContext, source.URI, ContentMeta{}).
		Return(suite.set1, ContentMeta{Format: MediaTypeJWKSet}, error(nil)).
		Once()
	listener.ExpectOnRefreshEvent(RefreshEvent{
		URI:  source.URI,
		Keys: suite.set1,
		New:  suite.set1, // this is the first event, so everything's new
	}).Once()

	f.ExpectFetchCtx(matchContext, source.URI, ContentMeta{Format: MediaTypeJWKSet}).
		Return([]Key(nil), ContentMeta{}, expectedError).
		Once()
	listener.ExpectOnRefreshEvent(RefreshEvent{
		URI:  source.URI,
		Keys: suite.set1, // the previous keys should be sent on error
		Err:  expectedError,
	}).Once()

	f.ExpectFetchCtx(matchContext, source.URI, ContentMeta{}).
		Return(suite.set2, ContentMeta{}, error(nil)).
		Once()
	listener.ExpectOnRefreshEvent(RefreshEvent{
		URI:     source.URI,
		Keys:    suite.set2,
		New:     []Key{suite.set2[2]}, // added kid "D"
		Deleted: []Key{suite.set1[1]}, // deleted kid "B"
	}).Once()

	suite.Require().NoError(
		r.Start(context.Background()),
	)

	suite.ErrorIs(
		r.Start(context.Background()),
		ErrRefresherStarted,
	)

	// fetch the timer after the first request
	timer := suite.getTimer(timerCh)

	// we're expecting (2) more events
	for i := 0; i < 2; i++ {
		fc.Set(timer.When())
		timer = suite.getTimer(timerCh)
	}

	suite.NoError(
		r.Stop(context.Background()),
	)

	suite.ErrorIs(
		r.Stop(context.Background()),
		ErrRefresherStopped,
	)

	f.AssertExpectations(suite.T())
	listener.AssertExpectations(suite.T())
}

func (suite *RefresherSuite) TestRefresh() {
	suite.Run("Default", func() {
		suite.testRefresh(RefreshSource{
			URI: "http://getkeys.com/keys",
			// take the defaults for interval, jitter, etc
		})
	})

	suite.Run("CustomInterval", func() {
		suite.testRefresh(RefreshSource{
			URI:      "http://getkeys.com/keys",
			Interval: 45 * time.Minute,
			Jitter:   0.15,
		})
	})
}

func (suite *RefresherSuite) TestStopDuringFetch() {
	var (
		f = new(mockFetcher)
		r = suite.newRefresher(
			WithFetcher(f),
			WithSources(RefreshSource{URI: "http://getkeys.com/keys"}),
		)

		listener     = new(mockRefreshListener)
		fetchReady   = make(chan struct{})
		fetchBarrier = make(chan struct{})
		matchContext = func(ctx context.Context) bool {
			return suite.NotEqual(context.Background(), ctx)
		}
	)

	f.ExpectFetchCtx(matchContext, "http://getkeys.com/keys", ContentMeta{}).
		Return(suite.set1, ContentMeta{Format: MediaTypeJWKSet}, error(nil)).
		Run(func(mock.Arguments) {
			close(fetchReady)
			<-fetchBarrier
		}).
		Once()

	suite.Require().NoError(
		r.Start(context.Background()),
	)

	select {
	case <-time.After(2 * time.Second):
		suite.Fail("Fetch was not called")
	case <-fetchReady:
		// passing
	}

	suite.Require().NoError(
		r.Stop(context.Background()),
	)

	close(fetchBarrier)
	runtime.Gosched()
	f.AssertExpectations(suite.T())
	listener.AssertExpectations(suite.T())
}

func (suite *RefresherSuite) TestMissingURI() {
	r, err := NewRefresher(
		WithSources(RefreshSource{}),
	)

	suite.Nil(r)
	suite.Require().Error(err)
}

func (suite *RefresherSuite) TestDuplicateURI() {
	r, err := NewRefresher(
		WithSources(
			RefreshSource{
				URI: "http://duplicate.net",
			},
			RefreshSource{
				URI: "http://duplicate.net",
			},
		),
	)

	suite.Nil(r)
	suite.Require().Error(err)
}

func TestRefresher(t *testing.T) {
	suite.Run(t, new(RefresherSuite))
}
