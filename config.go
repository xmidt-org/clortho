// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

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
	DefaultRefreshInterval = time.Hour * 24

	// DefaultRefreshMinInterval is the hard minimum for the base interval between key refreshes
	// regardless of how the base interval was determined.
	DefaultRefreshMinInterval = time.Minute * 10

	// DefaultRefreshJitter is the default randomization factor for key refreshes.
	DefaultRefreshJitter = 0.1
)

// RefreshSource describes a single location where keys are retrieved on a schedule.
type RefreshSource struct {
	// URI is the location where keys are served.  By default, clortho supports
	// file://, http://, and https:// URIs, as well as standard file system paths
	// such as /etc/foo/bar.jwk.
	//
	// This field is required and has no default.
	URI string `json:"uri" yaml:"uri"`

	// Interval is the base time between refreshing keys from this source.  This value
	// is used when the source URI doesn't specify any sort of time-to-live or expiry.
	// For example, if an http source doesn't specify a Cache-Control header, this value is used.
	//
	// If this field is not positive, DefaultRefreshInterval is used.
	Interval time.Duration `json:"interval" yaml:"interval"`

	// MinInterval specifies the absolute minimum time between key refreshes from this source.
	// Regardless of HTTP headers, the Interval field, etc, key refreshes will not occur more
	// often than this field indicates.
	//
	// If this value is not positive, DefaultRefreshMinInterval is used.
	MinInterval time.Duration `json:"minInterval" yaml:"minInterval"`

	// Jitter is the randomization factor applied to the interval between refreshes.  No matter how
	// the interval is determined (e.g. Cache-Control, Interval field, etc), a random value between
	// [1-Jitter,1+Jitter]*interval is used as the actual time before the next attempted refresh.
	//
	// Valid values are between 0.0 and 1.0, exclusive.  If this value is outside that range,
	// including being unset, DefaultRefreshJitter is used instead.
	Jitter float64 `json:"jitter" yaml:"jitter"`
}

// validate checks that this RefreshSource is valid.
func (rs RefreshSource) validate() (err error) {
	if len(rs.URI) == 0 {
		err = errors.New("A URI is required for each refresh source")
	}

	return
}

// validateRefreshSources validates a sequence of sources.
func validateRefreshSources(in ...RefreshSource) (err error) {
	duplicates := make(map[string]RefreshSource, len(in))
	for _, s := range in {
		err = multierr.Append(err, s.validate())

		if _, ok := duplicates[s.URI]; ok {
			err = multierr.Append(err, fmt.Errorf("Duplicate refresh source URI: '%s'", s.URI))
			continue
		}

		duplicates[s.URI] = s
	}

	return
}

// ResolveConfig configures how to fetch individual keys on demand.
type ResolveConfig struct {
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
	// Resolve is the subset of configuration that establishes how individual
	// keys will be resolved (or, fetched) on demand.
	Resolve ResolveConfig `json:"resolve" yaml:"resolve"`

	// Refresh is the subset of configuration that configures how keys are
	// refreshed asynchronously.
	Refresh RefreshConfig `json:"refresh" yaml:"refresh"`
}
