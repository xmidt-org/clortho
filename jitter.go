// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"math/rand"
	"time"
)

// jitterer computes the time until a source's next refresh.
//
// nextInterval is the normal schedule: a random point within JitterPercentage
// either side of the base interval, clipped to the source's minimum and
// maximum.  When the base is a TTL the server sent, the window is also clipped
// at the TTL, so a refresh never waits past the time the server said the
// content was good for.  Every interval it returns lies within those bounds,
// whatever the configuration or the metadata a source serves.
//
// delayed is the schedule for a retry after a failure, where the jitter only
// ever makes the retry later.
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

	j.fraction = source.JitterPercentage / 100.0
	j.intervalBase = int64((1.0 - j.fraction) * float64(interval))
	j.intervalRange = int64((1.0+j.fraction)*float64(interval)) - j.intervalBase + 1

	return j
}

// nextInterval computes the time until the next refresh on the normal
// schedule, given the TTL the server advertised, if any, and whether the
// refresh succeeded.  A TTL is honored only after a success; after a failure
// that waits for the normal schedule the configured interval is used, since
// the content the TTL described was not accepted.
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

// delayed returns base with jitter that can only make it later: a random
// point between base and JitterPercentage beyond it, and never past the
// source's maximum.  It schedules the retry after a failed refresh.
//
// Unlike nextInterval it applies no minimum.  base is either the minimum
// itself or a wait the server asked for, and a server's wait is honored even
// when it is shorter than the minimum.
func (j jitterer) delayed(base time.Duration) time.Duration {
	// the wait itself is never longer than the maximum
	base = min(base, j.maxInterval)

	// the most the jitter may add is the configured fraction of the wait
	window := time.Duration(j.fraction * float64(base))

	// but never more than the room left below the maximum.  this is also what
	// keeps the addition at the end from overflowing.
	room := j.maxInterval - base
	window = min(window, room)

	// pick a random point in the window.  the +1 makes the far end of the
	// window reachable, since Int63n excludes its argument.
	extra := time.Duration(rand.Int63n(positive(int64(window) + 1)))

	return base + extra
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
