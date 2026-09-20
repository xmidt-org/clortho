// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"math"
	"math/rand"
	"time"
)

// jitterer computes time intervals using jitter, bounded below by a minimum
// and above by a maximum.  Every interval it returns lies within those bounds,
// whatever the configuration or the metadata a source serves.
type jitterer struct {
	intervalBase  int64
	intervalRange int64

	minInterval time.Duration
	maxInterval time.Duration
	jitter      float64

	// ttlBaseMultiplier is the value we multiply TTLs or expirations by
	// to obtain the base for the jittered range.  We don't use standard
	// jitter for TTLs since we don't want to refresh after the TTL has elapsed.
	ttlBaseMultiplier float64
}

// newJitterer constructs a jitterer for a RefreshSource.
func newJitterer(source RefreshSource) jitterer {
	j := jitterer{
		minInterval: source.MinInterval,
		maxInterval: source.MaxInterval,
		jitter:      source.Jitter,
	}

	if j.minInterval <= 0 {
		j.minInterval = DefaultRefreshMinInterval
	}

	if j.jitter <= 0.0 || j.jitter >= 1.0 {
		j.jitter = DefaultRefreshJitter
	}

	interval := source.Interval
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}

	// with no explicit maximum, never cut an operator's own interval short, jitter
	// window included: the default ceiling is a week or the top of the jitter
	// window around the configured interval, whichever is longer.  the ceiling
	// exists to bound what a source can dictate via max-age, not to second-guess
	// the configuration.
	if j.maxInterval <= 0 {
		j.maxInterval = max(DefaultRefreshMaxInterval, jitterUpper(interval, j.jitter))
	}

	// the minimum is the hard floor, so it wins over a smaller maximum
	if j.maxInterval < j.minInterval {
		j.maxInterval = j.minInterval
	}

	// precompute certain values to make computations faster.  an explicit maximum
	// below the interval bounds it here; for an interval large enough that the
	// float arithmetic below overflows int64, positive() in nextInterval is what
	// keeps the result safe.
	interval = min(interval, j.maxInterval)

	j.intervalBase = int64(((1.0 - j.jitter) * float64(interval)))
	j.intervalRange = int64((1.0+j.jitter)*float64(interval)) - j.intervalBase + 1
	j.ttlBaseMultiplier = 1.0 - (2.0 * j.jitter)

	return j
}

// nextInterval calculates the next refresh interval given metadata and
// any error that occurred during fetching.
func (j jitterer) nextInterval(meta ContentMeta, fetchErr error) (next time.Duration) {
	if fetchErr != nil || meta.TTL <= 0 {
		next = time.Duration(j.intervalBase + rand.Int63n(positive(j.intervalRange)))
	} else {
		// a source's TTL is advisory.  cap it before the jitter arithmetic, both so
		// that a source cannot make us wait longer than the configured maximum and
		// so that the arithmetic below cannot overflow.
		ttl := min(meta.TTL, j.maxInterval)

		// adjust the jitter window down, so that we always pick a random interval
		// that is less than or equal to the TTL.
		base := int64(j.ttlBaseMultiplier * float64(ttl))
		next = time.Duration(base) + time.Duration(rand.Int63n(positive(int64(ttl)-base+1)))
	}

	// enforce the bounds regardless of how the next interval was calculated
	return max(j.minInterval, min(next, j.maxInterval))
}

// jitterUpper returns the top of the jitter window around interval, saturating
// at the largest Duration rather than overflowing.
func jitterUpper(interval time.Duration, jitter float64) time.Duration {
	upper := (1.0 + jitter) * float64(interval)
	if upper >= float64(math.MaxInt64) {
		return math.MaxInt64
	}

	return time.Duration(upper)
}

// positive returns n if it is a valid argument to rand.Int63n, and 1 otherwise.
// It makes nextInterval total: no configuration or metadata can reach Int63n
// with a value it panics on.
func positive(n int64) int64 {
	if n < 1 {
		return 1
	}

	return n
}
