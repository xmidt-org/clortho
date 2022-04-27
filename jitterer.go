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

package clortho

import (
	"math/rand"
	"time"
)

// jitterer computes time intervals using jitter and a minimum value.
type jitterer struct {
	intervalBase  int64
	intervalRange int64

	minInterval time.Duration
	jitter      float64

	// ttlBaseMultiplier is the value we multiply TTLs or expirations by
	// to obtain the base for the jittered range.  We don't use standard
	// jitter for TTLs since we don't want to refresh after the TTL has elapsed.
	ttlBaseMultiplier float64
}

// newJitterer constructs a jitterer for a RefreshSource.
func newJitterer(source RefreshSource) (j jitterer) {
	j = jitterer{
		minInterval: source.MinInterval,
		jitter:      source.Jitter,
	}

	if j.minInterval <= 0 {
		j.minInterval = DefaultRefreshMinInterval
	}

	if j.jitter <= 0.0 || j.jitter >= 1.0 {
		j.jitter = DefaultRefreshJitter
	}

	// precompute certain values to make computations faster

	interval := source.Interval
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}

	j.intervalBase = int64(((1.0 - j.jitter) * float64(interval)))
	j.intervalRange = int64((1.0+j.jitter)*float64(interval)) - j.intervalBase + 1
	j.ttlBaseMultiplier = 1.0 - (2.0 * j.jitter)

	return
}

// nextInterval calculates the next refresh interval given metadata and
// any error that occurred during fetching.
func (j jitterer) nextInterval(meta ContentMeta, fetchErr error) (next time.Duration) {
	if fetchErr != nil || meta.TTL <= 0 {
		next = time.Duration(j.intervalBase + rand.Int63n(j.intervalRange))
	} else {
		// adjust the jitter window down, so that we always pick a random interval
		// that is less than or equal to the TTL.
		base := int64(j.ttlBaseMultiplier * float64(meta.TTL))
		next = time.Duration(base) + time.Duration(rand.Int63n(int64(meta.TTL)-base+1))
	}

	// enforce our minimum interval regardless of how the next interval was calculated
	if next < j.minInterval {
		next = j.minInterval
	}

	return
}
