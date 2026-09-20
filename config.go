// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"time"
)

const (
	// DefaultRefreshInterval is the time between refreshes when a source gives
	// no hint and RefreshSource.RefreshInterval is zero.
	DefaultRefreshInterval = 24 * time.Hour

	// DefaultMinRefreshInterval is the shortest time between refreshes when
	// RefreshSource.MinRefreshInterval is zero.
	DefaultMinRefreshInterval = 10 * time.Minute

	// DefaultMaxRefreshInterval is the longest time between refreshes when
	// RefreshSource.MaxRefreshInterval is zero.
	DefaultMaxRefreshInterval = 7 * 24 * time.Hour

	// DefaultJitterFraction is the jitter applied when
	// RefreshSource.JitterFraction is zero or out of range.
	DefaultJitterFraction = 0.1

	// DefaultHTTPTimeout is the timeout of the client used for an http or https
	// source when RefreshSource.Client is nil.
	DefaultHTTPTimeout = 30 * time.Second

	// DefaultMaxResponseBytes is the largest response body read from an http
	// or https source when RefreshSource.MaxResponseBytes is zero.
	DefaultMaxResponseBytes int64 = 25 * 1024
)

// Config is the only way to configure a Provider.  It is a plain struct with
// no struct tags: serialization is the caller's concern.  A service unmarshals
// its own settings and fills this in, which is also how it supplies things no
// configuration file can hold, such as an *http.Client.
type Config struct {
	// Sources are polled on a schedule.  At least one is required.
	//
	// All sources feed one map keyed by key ID.  A key ID served by more than
	// one source is reported as ErrDuplicateKeyID by the refresh that would
	// introduce it, not merged.  Use separate Providers for separate key spaces.
	Sources []RefreshSource

	// Verify is the policy applied to every key before it is offered to jwx.
	Verify VerifyConfig
}

// RefreshSource is one location that serves a JWK set or a single JWK.
type RefreshSource struct {
	// URI is a file path, or a file, http, or https URI.  Required.
	//
	// Every key the source serves must carry a kid, and none may be symmetric;
	// a refresh that finds otherwise fails and leaves the ring untouched.
	URI string

	// RefreshInterval is the time between refreshes when the server gives no
	// hint.  An http source's Cache-Control max-age, when present, is used
	// instead.  Zero: DefaultRefreshInterval.
	RefreshInterval time.Duration

	// MinRefreshInterval is the shortest time between refreshes, whatever the
	// server says and whatever an unknown key ID asks for.  Zero:
	// DefaultMinRefreshInterval.
	MinRefreshInterval time.Duration

	// MaxRefreshInterval is the longest time between refreshes, whatever the
	// server says.  A refresh happens at least this often even when the content
	// never changes, so it bounds how long a key the issuer has removed can
	// still verify.  Zero: DefaultMaxRefreshInterval.  A value below the
	// effective MinRefreshInterval is raised to it.
	MaxRefreshInterval time.Duration

	// JitterFraction is a percentage, plus or minus, applied to every refresh
	// interval: 0.1 means each refresh fires at a random point between ten
	// percent early and ten percent late.  When the interval comes from a
	// server TTL the late half is dropped, since the server said the content
	// is stale after that, so 0.1 then means up to ten percent early.  The
	// result is clipped to the min and max above.
	//
	// Valid values are at least zero and less than one; anything else,
	// including zero, gets DefaultJitterFraction.  Jitter cannot be turned
	// off, since its purpose is to keep a fleet that started together from
	// polling the key server in lockstep.
	JitterFraction float64

	// Client makes the requests for an http or https URI.  It owns timeout,
	// redirects, TLS, proxies, and any authorization its transport adds.  Nil: a
	// client with DefaultHTTPTimeout that does not follow redirects.  Ignored
	// for a file source.
	Client *http.Client

	// MaxResponseBytes caps the body read from an http or https URI.  A larger
	// body fails the refresh with ErrResponseTooLarge.  Zero:
	// DefaultMaxResponseBytes.
	MaxResponseBytes int64
}

// VerifyConfig is the policy FetchKeys applies to every key it takes from the
// ring.  The zero value is the strict default.
type VerifyConfig struct {
	// RefreshOnUnknownKeyID makes a lookup for a key ID that is not on the ring
	// trigger an early refresh of every source, and wait for it, so a token
	// signed with a newly rotated key verifies without waiting for the next
	// scheduled refresh.  The early refresh is rate-limited by each source's
	// MinRefreshInterval; a lookup that arrives inside that window fails
	// immediately with ErrKeyNotFound, so a flood of unknown key IDs costs at
	// most one request per source per MinRefreshInterval.
	//
	// Off, which is the default, an unknown key ID fails with ErrKeyNotFound
	// and no request is made: a token can never cause the Provider to contact
	// anything.
	RefreshOnUnknownKeyID bool

	// IgnoreKeyUsage turns off the check that a key's "use", when present, is
	// "sig".  Off by default: a key marked for anything else is rejected with
	// ErrKeyUsage.
	IgnoreKeyUsage bool

	// IgnoreKeyAlgorithm turns off the check that a key's "alg", when present,
	// matches the token header's alg.  Off by default: a mismatch is rejected
	// with ErrKeyAlgorithm.
	IgnoreKeyAlgorithm bool
}

// userinfoPassword matches the password of a URI's userinfo in text, for
// strings that url.Parse rejects.
var userinfoPassword = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9+.-]*://[^/?#@]*:)[^/?#@]*@`)

// redactURI returns uri with any userinfo password replaced, as
// url.URL.Redacted does.  Errors, events, and status carry redacted URIs so
// that a source configured with credentials in its URI does not put them in
// logs.
func redactURI(uri string) string {
	if u, err := url.Parse(uri); err == nil {
		if _, hasPassword := u.User.Password(); !hasPassword {
			return uri
		}

		return u.Redacted()
	}

	return userinfoPassword.ReplaceAllString(uri, "${1}xxxxx@")
}

// isHTTP reports whether a source URI is loaded over HTTP rather than from
// the file system.  New has already validated the scheme.
func isHTTP(uri string) bool {
	u, err := url.Parse(uri)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https")
}

// newDefaultHTTPClient returns the client used for an http or https source
// whose Client is nil.  It has DefaultHTTPTimeout and does not follow
// redirects: a redirect lets the server, rather than the configured location,
// decide where key material comes from, so a 3xx surfaces as an HTTPError.
// It shares the process's default transport, so connection pooling is
// unaffected.
func newDefaultHTTPClient() *http.Client {
	return &http.Client{
		Timeout: DefaultHTTPTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// validate checks the source's URI.
func (rs RefreshSource) validate() error {
	if rs.URI == "" {
		return errors.New("a URI is required for each source")
	}

	u, err := url.Parse(rs.URI)
	if err != nil {
		return fmt.Errorf("%w: %q", ErrUnsupportedScheme, redactURI(rs.URI))
	}

	switch u.Scheme {
	case "", "file", "http", "https":
		return nil

	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedScheme, redactURI(rs.URI))
	}
}

// withDefaults returns a copy of the source with every zero or invalid field
// replaced by its default.
func (rs RefreshSource) withDefaults() RefreshSource {
	if rs.RefreshInterval <= 0 {
		rs.RefreshInterval = DefaultRefreshInterval
	}

	if rs.MinRefreshInterval <= 0 {
		rs.MinRefreshInterval = DefaultMinRefreshInterval
	}

	if rs.MaxRefreshInterval <= 0 {
		rs.MaxRefreshInterval = DefaultMaxRefreshInterval
	}

	if rs.MaxRefreshInterval < rs.MinRefreshInterval {
		rs.MaxRefreshInterval = rs.MinRefreshInterval
	}

	if rs.JitterFraction <= 0.0 || rs.JitterFraction >= 1.0 {
		rs.JitterFraction = DefaultJitterFraction
	}

	if rs.Client == nil {
		rs.Client = newDefaultHTTPClient()
	}

	if rs.MaxResponseBytes <= 0 {
		rs.MaxResponseBytes = DefaultMaxResponseBytes
	}

	return rs
}

// normalizeSources validates every source and returns copies with defaults
// applied.  Every problem is reported, joined, rather than just the first.
func normalizeSources(in []RefreshSource) ([]RefreshSource, error) {
	if len(in) == 0 {
		return nil, ErrNoKeySources
	}

	var (
		errs = make([]error, 0, len(in))
		seen = make(map[string]bool, len(in))
		out  = make([]RefreshSource, 0, len(in))
	)

	for _, rs := range in {
		errs = append(errs, rs.validate())

		if seen[rs.URI] {
			errs = append(errs, fmt.Errorf("duplicate source URI: %q", redactURI(rs.URI)))
		}

		seen[rs.URI] = true
		out = append(out, rs.withDefaults())
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return out, nil
}
