// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"math/rand"
	"time"
)

// jitterer computes the time until a source's next refresh: a random point
// within JitterFraction either side of the base interval, clipped to the
// source's minimum and maximum.  When the base is a TTL the server sent, the
// window is also clipped at the TTL, so a refresh never waits past the time
// the server said the content was good for.  Every interval it returns lies
// within those bounds, whatever the configuration or the metadata a source
// serves.
type jitterer struct {
	intervalBase  int64
	intervalRange int64

	fraction    float64
	minInterval time.Duration
	maxInterval time.Duration
}

// newJitterer constructs a jitterer for a RefreshSource whose defaults have
// already been filled in by New.
func newJitterer(source RefreshSource) jitterer {
	j := jitterer{
		minInterval: source.MinRefreshInterval,
		maxInterval: source.MaxRefreshInterval,
	}

	// an explicit maximum below the interval bounds it here; for an interval
	// large enough that the float arithmetic below overflows int64, positive()
	// in nextInterval is what keeps the result safe.
	interval := min(source.RefreshInterval, j.maxInterval)

	j.fraction = source.JitterFraction
	j.intervalBase = int64((1.0 - j.fraction) * float64(interval))
	j.intervalRange = int64((1.0+j.fraction)*float64(interval)) - j.intervalBase + 1

	return j
}

// nextInterval computes the time until the next refresh, given the TTL the
// server advertised, if any, and whether the refresh succeeded.  A TTL is
// honored only after a success; after a failure the configured interval is
// used, so that a failing server cannot dictate the retry rate.
func (j jitterer) nextInterval(ttl time.Duration, refreshErr error) (next time.Duration) {
	if refreshErr != nil || ttl <= 0 {
		next = time.Duration(j.intervalBase + rand.Int63n(positive(j.intervalRange)))
	} else {
		// a TTL is advisory.  cap it before the jitter arithmetic, both so that a
		// source cannot make us wait longer than the configured maximum and so
		// that the arithmetic below cannot overflow.  the window is the same
		// fraction below the TTL as for a configured interval, and nothing
		// above it.
		ttl = min(ttl, j.maxInterval)

		base := int64((1.0 - j.fraction) * float64(ttl))
		next = time.Duration(base) + time.Duration(rand.Int63n(positive(int64(ttl)-base+1)))
	}

	// enforce the bounds regardless of how the next interval was calculated
	return max(j.minInterval, min(next, j.maxInterval))
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
