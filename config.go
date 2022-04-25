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
	"errors"
	"fmt"
	"time"

	"go.uber.org/multierr"
)

const (
	// DefaultRefreshInterval is used as the base interval between key refreshes when an
	// interval couldn't be determined any other way.
	DefaultRefreshInterval time.Duration = time.Hour * 24

	// DefaultRefreshMinInterval is the hard minimum for the base interval between key refreshes
	// regardless of how the base interval was determined.
	DefaultRefreshMinInterval time.Duration = time.Minute * 10

	// DefaultRefreshJitter is the default randomization factor for key refreshes.
	DefaultRefreshJitter float64 = 0.1
)

// RefreshSource describes a single location where keys are retrieved on a schedule.
type RefreshSource struct {
	// URI is the location where keys are served.  By default, clortho supports
	// file://, http://, and https:// URIs.
	//
	// This field is required and has no default.
	URI string `json:"uri" yaml:"uri"`

	// Interval is the base time between refreshing keys from this source.  This value
	// is used when the source URI doesn't specify any sort of time-to-live or expiry.
	// For example, if an http source doesn't specify a Cache-Control header, this value is used.
	//
	// If this field is unset, DefaultRefreshInterval is used.  If this field is negative,
	// an error is raised.
	Interval time.Duration `json:"interval" yaml:"interval"`

	// MinInterval specifies the absolute minimum time between key refreshes from this source.
	// Regardless of HTTP headers, the Interval field, etc, key refreshes will not occur more
	// faster than this field indicates.
	//
	// If this value is unset, DefaultRefreshMinInterval is used.  If this field is negative or larger
	// than Interval, an error is raised.
	MinInterval time.Duration `json:"minInterval" yaml:"minInterval"`

	// Jitter is the randomization factor applied to the interval between refreshes.  No matter how
	// the interval is determined (e.g. Cache-Control, Interval field, etc), a random value between
	// [1-Jitter,1+Jitter]*interval is used as the actual time before the next attempted refresh.
	//
	// If this field is unset, DefaultRefreshJitter is used.  If this field is greater than or equal
	// to 1.0 or is negative, an error is raised.
	Jitter float64 `json:"jitter" yaml:"jitter"`
}

// validateAndSetDefaults both (1) validates this source, and (2) returns a copy of this
// source with certain fields set to the appropriate defaults.
func (rs RefreshSource) validateAndSetDefaults() (defaulted RefreshSource, err error) {
	defaulted = rs

	// use the URI to match up errors to the source
	uri := defaulted.URI
	if len(uri) == 0 {
		uri = "missing URI"
		err = multierr.Append(err, errors.New("A URI is required for each refresh source"))
	}

	switch {
	case defaulted.Jitter == 0.0:
		defaulted.Jitter = DefaultRefreshJitter

	case rs.Jitter < 0.0 || rs.Jitter >= 1.0:
		err = multierr.Append(
			err,
			fmt.Errorf("Invalid refresh jitter for '%s': %f", uri, defaulted.Jitter),
		)
	}

	switch {
	case defaulted.Interval == 0:
		defaulted.Interval = DefaultRefreshInterval

	case defaulted.Interval < 0:
		err = multierr.Append(
			err,
			fmt.Errorf("Invalid refresh interval for '%s': %s", uri, defaulted.Interval),
		)
	}

	switch {
	case defaulted.MinInterval == 0:
		defaulted.MinInterval = DefaultRefreshMinInterval

	case defaulted.MinInterval < 0:
		err = multierr.Append(
			err,
			fmt.Errorf("Invalid minimum refresh interval for '%s': %s", uri, defaulted.MinInterval),
		)
	}

	if defaulted.MinInterval > defaulted.Interval {
		err = multierr.Append(
			err,
			fmt.Errorf(
				"Invalid MinInterval for '%s': MinInterval [%s] cannot be larger than Interval [%s]",
				uri, defaulted.MinInterval, defaulted.Interval,
			),
		)
	}

	return
}

// validateAndSetDefaults returns a slice containing a copy of each source which has been validated
// and had any necessary defaults applied.  A composite error containing all validation errors
// is returned, or nil to indicate everything was valid.
func validateAndSetDefaults(in ...RefreshSource) (out []RefreshSource, err error) {
	out = make([]RefreshSource, 0, len(out))
	duplicates := make(map[string]RefreshSource, len(out))
	for _, s := range in {
		defaulted, validationErr := s.validateAndSetDefaults()
		err = multierr.Append(err, validationErr)

		if _, ok := duplicates[defaulted.URI]; ok {
			err = multierr.Append(err, fmt.Errorf("Duplicate refresh source URI: '%s'", defaulted.URI))
			continue
		}

		duplicates[defaulted.URI] = defaulted
		out = append(out, defaulted)
	}

	return
}

// FetchConfig configures how to fetch individual keys on demand.
type FetchConfig struct {
	// Template is a URI template used to fetch keys.  This template may
	// use a single parameter named keyID, e.g. http://keys.com/{keyID}.
	Template string `json:"template" yaml:"template"`

	// Timeout refers to the maximum time to wait for a refresh operation.
	// There is no default for this field.  If unset, no timeout is applied.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
}

// RefreshConfig configures all aspects of key refresh.
type RefreshConfig struct {
	// Sources are the set of refresh sources to be polled for key material.
	//
	// If this slice is empty, a Refresher is still created, but it will
	// do nothing.
	//
	// If there are multiple sources with the same URI, an error is raised.
	Sources []RefreshSource `json:"sources" yaml:"sources"`
}

// Config configures clortho from (possibly) externally unmarshaled locations.
type Config struct {
	// Fetch is the subset of configuration that establishes how individual
	// keys will be fetched on demand.
	Fetch FetchConfig `json:"fetch" yaml:"fetch"`

	// Refresh is the subset of configuration that configures how keys are refreshed
	// in the background.
	Refresh RefreshConfig `json:"refresh" yaml:"refresh"`
}
