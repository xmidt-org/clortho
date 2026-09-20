// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
)

type JittererSuite struct {
	suite.Suite
}

func (suite *JittererSuite) TestNextInterval() {
	testCases := []struct {
		source                 RefreshSource
		meta                   ContentMeta
		fetchErr               error
		expectedLo, expectedHi time.Duration
	}{
		{
			expectedLo: time.Duration(float64(DefaultRefreshInterval) * (1.0 - DefaultRefreshJitter)),
			expectedHi: time.Duration(float64(DefaultRefreshInterval) * (1.0 + DefaultRefreshJitter)),
		},
		{
			source: RefreshSource{
				Interval: 16 * time.Minute,
				Jitter:   0.15,
			},
			expectedLo: time.Duration(float64(16*time.Minute) * (1.0 - 0.15)),
			expectedHi: time.Duration(float64(16*time.Minute) * (1.0 + 0.15)),
		},
		{
			meta: ContentMeta{
				TTL: 15 * time.Hour,
			},
			expectedLo: time.Duration(float64(15*time.Hour) * (1.0 - (2.0 * 0.1))),
			expectedHi: 15 * time.Hour,
		},
		{
			source: RefreshSource{
				Interval:    5 * time.Minute,
				MinInterval: 10 * time.Minute,
			},
			expectedLo: 10 * time.Minute,
			expectedHi: 10 * time.Minute,
		},
		{
			meta: ContentMeta{
				TTL: 5 * time.Minute,
			},
			expectedLo: 10 * time.Minute,
			expectedHi: 10 * time.Minute,
		},
	}

	for i, testCase := range testCases {
		suite.Run(strconv.Itoa(i), func() {
			var (
				j    = newJitterer(testCase.source)
				next = j.nextInterval(testCase.meta, testCase.fetchErr)
			)

			suite.GreaterOrEqual(next, testCase.expectedLo, "next to too low")
			suite.GreaterOrEqual(testCase.expectedHi, next, "next is too high")
		})
	}
}

// TestNextIntervalTTLCappedByDefaultMax checks that a source cannot push the
// refresh interval past DefaultRefreshMaxInterval by serving a huge max-age.
// The source is trusted to serve keys, not to decide that they are never
// checked again.
func (suite *JittererSuite) TestNextIntervalTTLCappedByDefaultMax() {
	j := newJitterer(RefreshSource{})
	next := j.nextInterval(ContentMeta{TTL: 100 * 365 * 24 * time.Hour}, nil)

	suite.LessOrEqual(next, DefaultRefreshMaxInterval)
	suite.GreaterOrEqual(next, DefaultRefreshMinInterval)
}

// TestNextIntervalNeverPanics checks that no combination of a valid Jitter and
// a hostile TTL can crash the refresh goroutine.  With Jitter above 0.5 the TTL
// base multiplier is negative, and an unbounded TTL overflowed the argument to
// rand.Int63n, which panics on a non-positive value.
func (suite *JittererSuite) TestNextIntervalNeverPanics() {
	for _, jitter := range []float64{0.1, 0.5, 0.9, 0.99} {
		for _, ttl := range []time.Duration{math.MaxInt64, math.MaxInt64 / 2, 200 * 365 * 24 * time.Hour} {
			j := newJitterer(RefreshSource{Jitter: jitter})
			suite.Require().NotPanics(func() {
				next := j.nextInterval(ContentMeta{TTL: ttl}, nil)
				suite.Greater(next, time.Duration(0), "jitter %v ttl %v", jitter, ttl)
				suite.LessOrEqual(next, DefaultRefreshMaxInterval, "jitter %v ttl %v", jitter, ttl)
			}, "jitter %v ttl %v", jitter, ttl)
		}
	}
}

// TestNextIntervalCustomMaxInterval checks that MaxInterval caps a TTL that
// would otherwise be honored.
func (suite *JittererSuite) TestNextIntervalCustomMaxInterval() {
	j := newJitterer(RefreshSource{MaxInterval: time.Hour})
	for range 50 {
		next := j.nextInterval(ContentMeta{TTL: 15 * time.Hour}, nil)
		suite.LessOrEqual(next, time.Hour)
		suite.GreaterOrEqual(next, DefaultRefreshMinInterval)
	}
}

// TestNextIntervalMaxCapsConfiguredInterval checks that MaxInterval also caps
// the configured Interval, the same way MinInterval floors it.
func (suite *JittererSuite) TestNextIntervalMaxCapsConfiguredInterval() {
	j := newJitterer(RefreshSource{Interval: 48 * time.Hour, MaxInterval: 24 * time.Hour})
	for range 50 {
		next := j.nextInterval(ContentMeta{}, nil)
		suite.LessOrEqual(next, 24*time.Hour)
	}
}

// TestNextIntervalMinWinsOverMax checks that a MaxInterval below MinInterval
// does not invert the range: the minimum is the hard floor.
func (suite *JittererSuite) TestNextIntervalMinWinsOverMax() {
	j := newJitterer(RefreshSource{MinInterval: 2 * time.Hour, MaxInterval: time.Hour})
	suite.Equal(2*time.Hour, j.nextInterval(ContentMeta{TTL: 10 * time.Minute}, nil))
	suite.Equal(2*time.Hour, j.nextInterval(ContentMeta{TTL: 10 * time.Hour}, nil))
}

// TestNextIntervalHugeConfiguredInterval checks that an absurd configured
// Interval cannot overflow the jitter range and panic either.
func (suite *JittererSuite) TestNextIntervalHugeConfiguredInterval() {
	j := newJitterer(RefreshSource{Interval: math.MaxInt64, Jitter: 0.9})
	suite.Require().NotPanics(func() {
		next := j.nextInterval(ContentMeta{}, nil)
		suite.Greater(next, time.Duration(0))
	})
}

// TestNextIntervalLongConfiguredIntervalKept checks that the default maximum
// never shortens an operator's own Interval, jitter window included: a 30 day
// interval still spreads across 27 to 33 days, and the top of that window is
// also the ceiling for what a source's max-age can request.
func (suite *JittererSuite) TestNextIntervalLongConfiguredIntervalKept() {
	const month = 30 * 24 * time.Hour
	var (
		j     = newJitterer(RefreshSource{Interval: month})
		lo    = time.Duration(float64(month) * (1.0 - DefaultRefreshJitter))
		hi    = time.Duration(float64(month) * (1.0 + DefaultRefreshJitter))
		above int
	)

	for range 200 {
		next := j.nextInterval(ContentMeta{}, nil)
		suite.GreaterOrEqual(next, lo)
		suite.LessOrEqual(next, hi)
		if next > month {
			above++
		}

		next = j.nextInterval(ContentMeta{TTL: 100 * 365 * 24 * time.Hour}, nil)
		suite.LessOrEqual(next, hi)
		suite.Greater(next, DefaultRefreshMaxInterval)
	}

	suite.Greater(above, 0, "the upper half of the jitter window is never reached")
}

// TestNextIntervalCeilingDoesNotClipJitter checks that the default ceiling sits
// above the jitter window rather than on the interval: with an Interval equal
// to DefaultRefreshMaxInterval, about half of all draws should land above it,
// not be pinned to it.  Otherwise jitter is defeated for any interval of a
// week or longer.
func (suite *JittererSuite) TestNextIntervalCeilingDoesNotClipJitter() {
	var (
		j          = newJitterer(RefreshSource{Interval: DefaultRefreshMaxInterval})
		above, atC int
	)

	for range 400 {
		next := j.nextInterval(ContentMeta{}, nil)
		switch {
		case next > DefaultRefreshMaxInterval:
			above++
		case next == DefaultRefreshMaxInterval:
			atC++
		}
	}

	// with 400 draws over a symmetric window the chance of fewer than 100
	// landing above the midpoint is negligible
	suite.Greater(above, 100, "draws above the interval: %d, pinned to it: %d", above, atC)
	suite.Less(atC, 10, "draws pinned exactly to the ceiling: %d", atC)
}

func TestJitterer(t *testing.T) {
	suite.Run(t, new(JittererSuite))
}
