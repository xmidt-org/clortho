// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"errors"
	"fmt"
	"time"
)

const (
	// DefaultRefreshInterval is used as the base interval between key refreshes when an
	// interval couldn't be determined any other way.
	DefaultRefreshInterval = time.Hour * 24

	// DefaultRefreshMinInterval is the hard minimum for the base interval between key refreshes
	// regardless of how the base interval was determined.
	DefaultRefreshMinInterval = time.Minute * 10

	// DefaultRefreshMaxInterval is the hard maximum for the interval between key refreshes
	// regardless of how the interval was determined.  In particular, a source cannot push
	// the interval past this by serving a large Cache-Control max-age.
	DefaultRefreshMaxInterval = time.Hour * 24 * 7

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

	// MaxInterval specifies the absolute maximum time between key refreshes from this source.
	// Regardless of HTTP headers, the Interval field, etc, key refreshes will occur at least
	// this often.  This bounds how long a source can make the refresher wait by serving a
	// large max-age, so that rotated or revoked keys are not trusted indefinitely.
	//
	// If this value is not positive, the larger of DefaultRefreshMaxInterval and the
	// effective Interval is used, so a deliberately long Interval is never cut short by
	// the default.  If it is less than the effective MinInterval, MinInterval is used,
	// since that is the hard floor.
	MaxInterval time.Duration `json:"maxInterval" yaml:"maxInterval"`

	// Jitter is the randomization factor applied to the interval between refreshes.  No matter how
	// the interval is determined (e.g. Cache-Control, Interval field, etc), a random value between
	// [1-Jitter,1+Jitter]*interval is used as the actual time before the next attempted refresh.
	// That window is then clipped to [MinInterval, MaxInterval]; an explicit MaxInterval below
	// the top of the window therefore narrows it.
	//
	// Valid values are between 0.0 and 1.0, exclusive.  If this value is outside that range,
	// including being unset, DefaultRefreshJitter is used instead.
	Jitter float64 `json:"jitter" yaml:"jitter"`
}

// validate checks that this RefreshSource is valid.
func (rs RefreshSource) validate() (err error) {
	if len(rs.URI) == 0 {
		err = errors.New("a URI is required for each refresh source")
	}

	return
}

// validateRefreshSources validates a sequence of sources.
func validateRefreshSources(in ...RefreshSource) error {
	var errs []error
	duplicates := make(map[string]RefreshSource, len(in))
	for _, s := range in {
		errs = append(errs, s.validate())

		if _, ok := duplicates[s.URI]; ok {
			errs = append(errs, fmt.Errorf("duplicate refresh source URI: '%s'", s.URI))
			continue
		}

		duplicates[s.URI] = s
	}

	return errors.Join(errs...)
}

// ResolveConfig configures how to fetch individual keys on demand.  It is used by
// NewResolver, via WithConfig, and by nothing else.  A Resolver serves callers that
// ask for a specific key by ID, such as clients that need a key to verify a
// particular message.
//
// ResolveConfig plays no part in JWT verification through NewKeyProvider: the
// provider reads only the key ring, which is filled from RefreshConfig.Sources.  A
// deployment that sets only a resolve template will never have a key to verify with.
type ResolveConfig struct {
	// Template is a URI template used to fetch keys.  This template may
	// use a single parameter named keyID, e.g. http://keys.com/{keyID}.
	//
	// If empty, a Resolver built from this configuration serves only keys
	// already on its ring, and reports ErrNoTemplate for any other key ID.
	Template string `json:"template" yaml:"template"`

	// Timeout refers to the maximum time to wait for a refresh operation.
	// There is no default for this field.  If unset, no timeout is applied.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
}

// RefreshConfig configures all aspects of key refresh.  This is the only path by
// which keys reach a jws.KeyProvider: a Refresher polls these sources and fills the
// key ring the provider reads from.
type RefreshConfig struct {
	// Sources are the set of refresh sources to be polled for key material.
	//
	// If this slice is empty, a Refresher is still created, but it will
	// do nothing.  NewKeyProvider rejects a Config with no sources; see
	// ErrNoRefreshSources.
	//
	// If there are multiple sources with the same URI, an error is raised.
	Sources []RefreshSource `json:"sources" yaml:"sources"`
}

// Config configures clortho from (possibly) externally unmarshaled locations.
type Config struct {
	// Resolve is the subset of configuration that establishes how individual
	// keys will be resolved (or, fetched) on demand by a Resolver.  It is not
	// used for JWT verification; see ResolveConfig.
	Resolve ResolveConfig `json:"resolve" yaml:"resolve"`

	// Refresh is the subset of configuration that configures how keys are
	// refreshed asynchronously.  This is what feeds the key ring that a
	// jws.KeyProvider verifies against; see RefreshConfig.
	Refresh RefreshConfig `json:"refresh" yaml:"refresh"`
}
