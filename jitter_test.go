// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// jitterSource returns a source with the defaults already filled in, as New
// would produce.
func jitterSource(interval, minInterval, maxInterval time.Duration, percentage float64) RefreshSource {
	return RefreshSource{
		URI:                "https://keys.example.com/jwks",
		RefreshInterval:    interval,
		MinRefreshInterval: minInterval,
		MaxRefreshInterval: maxInterval,
		JitterPercentage:   percentage,
	}
}

func TestJitterWithoutATTLStaysInsideTheWindow(t *testing.T) {
	j := newJitterer(jitterSource(time.Hour, time.Minute, 24*time.Hour, 10))
	for range 1000 {
		next := j.nextInterval(0, nil)
		assert.GreaterOrEqual(t, next, 54*time.Minute)
		assert.LessOrEqual(t, next, 66*time.Minute)
	}
}

func TestJitterWithATTLIsTheSameFractionEarlyAndNeverLate(t *testing.T) {
	j := newJitterer(jitterSource(time.Hour, time.Minute, 24*time.Hour, 10))
	for range 1000 {
		next := j.nextInterval(30*time.Minute, nil)
		assert.GreaterOrEqual(t, next, 27*time.Minute)
		assert.LessOrEqual(t, next, 30*time.Minute)
	}
}

func TestJitterIgnoresTheTTLAfterAnError(t *testing.T) {
	j := newJitterer(jitterSource(time.Hour, time.Minute, 24*time.Hour, 10))
	for range 1000 {
		next := j.nextInterval(time.Second, errors.New("fetch failed"))
		assert.GreaterOrEqual(t, next, 54*time.Minute)
		assert.LessOrEqual(t, next, 66*time.Minute)
	}
}

func TestJitterClipsToTheMinimum(t *testing.T) {
	j := newJitterer(jitterSource(time.Hour, 10*time.Minute, 24*time.Hour, 10))
	for range 100 {
		assert.Equal(t, 10*time.Minute, j.nextInterval(time.Second, nil))
	}
}

func TestJitterClipsATTLToTheMaximum(t *testing.T) {
	j := newJitterer(jitterSource(time.Hour, time.Minute, 2*time.Hour, 10))
	for range 1000 {
		next := j.nextInterval(365*24*time.Hour, nil)
		assert.LessOrEqual(t, next, 2*time.Hour)
		assert.GreaterOrEqual(t, next, time.Minute)
	}
}

func TestJitterClipsTheIntervalToTheMaximum(t *testing.T) {
	j := newJitterer(jitterSource(24*time.Hour, time.Minute, time.Hour, 10))
	for range 1000 {
		next := j.nextInterval(0, nil)
		assert.LessOrEqual(t, next, time.Hour)
		assert.GreaterOrEqual(t, next, 54*time.Minute)
	}
}

func TestJitterSurvivesAHugeTTL(t *testing.T) {
	j := newJitterer(jitterSource(time.Hour, time.Minute, 24*time.Hour, 10))
	next := j.nextInterval(math.MaxInt64, nil)
	assert.LessOrEqual(t, next, 24*time.Hour)
	assert.GreaterOrEqual(t, next, time.Minute)
}

func TestJitterSurvivesAHugeInterval(t *testing.T) {
	j := newJitterer(jitterSource(math.MaxInt64, time.Minute, math.MaxInt64, 10))
	next := j.nextInterval(0, nil)
	assert.GreaterOrEqual(t, next, time.Minute)
}

func TestPositive(t *testing.T) {
	assert.Equal(t, int64(1), positive(0))
	assert.Equal(t, int64(1), positive(-5))
	assert.Equal(t, int64(7), positive(7))
}
