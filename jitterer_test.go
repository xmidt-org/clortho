// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
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

func TestJitterer(t *testing.T) {
	suite.Run(t, new(JittererSuite))
}
