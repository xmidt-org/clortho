// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/xmidt-org/chronon"
	"github.com/xmidt-org/eventor"
)

const (
	// DefaultFetchRateLimit is the shortest time between fetches for key IDs
	// that are not allowed key IDs, when PerKeyConfig.FetchRateLimit is zero.
	DefaultFetchRateLimit = 10 * time.Second

	// DefaultCacheTime is how long a fetched key is held when the server does
	// not say and PerKeyConfig.CacheTime is zero.
	DefaultCacheTime = 24 * time.Hour

	// DefaultMinCacheTime is the shortest time a fetched key is held when
	// PerKeyConfig.MinCacheTime is zero.
	DefaultMinCacheTime = 10 * time.Minute

	// DefaultMaxCacheTime is the longest time a fetched key is held when
	// PerKeyConfig.MaxCacheTime is zero.
	DefaultMaxCacheTime = 7 * 24 * time.Hour

	// DefaultNotFoundCoolDown is the wait before a key ID is asked for again
	// after the server said there is no such key, when
	// PerKeyConfig.NotFoundCoolDown is zero.
	DefaultNotFoundCoolDown = 10 * time.Minute

	// DefaultFailureCoolDown is the wait before a key ID is asked for again
	// after the server could not answer, when PerKeyConfig.FailureCoolDown is
	// zero.
	DefaultFailureCoolDown = 10 * time.Second

	// keyIDPlaceholder is where the key ID goes in a PerKeyConfig.Template.
	keyIDPlaceholder = "{keyID}"

	// maxKeyIDLength is the longest key ID that may be put into a URL.
	maxKeyIDLength = 128

	// perKeyAccept is the Accept header of a fetch.  It is exactly what themis
	// matches to answer with a JWK; anything else, a list of types included,
	// gets PEM.
	perKeyAccept = "application/json"
)

// PerKeyConfig is the only way to configure a PerKeyProvider.  Like
// KeySetConfig it is a plain struct with no struct tags.
//
// A PerKeyProvider fetches a key because a token named it, before that token
// has been verified.  Most of this config is about what such a token may cost:
//
//   - A key ID in AllowedKeyIDs may always be fetched.
//   - Any other key ID is fetched no more often than FetchRateLimit, across
//     all such IDs, or never when AllowedKeyIDsOnly is set.
//   - Every key ID, allowed or not, is fetched by one request at a time, and
//     after a fetch fails is left alone for a cool-down: NotFoundCoolDown
//     when the server said there is no such key, FailureCoolDown when the
//     server could not answer.
//   - A fetched key is held, and not fetched again, for the time the server
//     gave or else CacheTime.
//
// A lookup that would need a fetch which is not allowed right now fails at
// once.  It never waits for the limit to pass.
type PerKeyConfig struct {
	// Template is the URL a key is fetched from, with {keyID} where the key ID
	// goes: "https://keys.example.com/keys/{keyID}".  Required.  The scheme is
	// http or https.  Every {keyID} is replaced by the key ID.  The placeholder
	// may only be in the path or the query, so that no key ID can change which
	// server is asked.
	Template string

	// Client makes the requests, and is required.  It is used exactly as
	// given; see RefreshSource.Client, which follows the same rules.  A client
	// with no timeout lets a server that stops answering hold every lookup
	// waiting on that fetch.
	Client *http.Client

	// AllowedKeyIDs are the key IDs the operator knows the server to hold.
	// They are exempt from FetchRateLimit, so a flood of invented key IDs
	// cannot crowd out a real one.  Each must be a valid key ID.
	AllowedKeyIDs []string

	// AllowedKeyIDsOnly makes AllowedKeyIDs the complete list: a key ID that
	// is not on it is never fetched, and a token naming one costs no request
	// at all.  It requires AllowedKeyIDs to hold at least one key ID.
	AllowedKeyIDsOnly bool

	// FetchRateLimit is the shortest time between fetches for key IDs that are
	// not in AllowedKeyIDs, counted across all of them.  It is what a flood of
	// invented key IDs can cost the server: one request per FetchRateLimit.
	// If zero, DefaultFetchRateLimit is used.  Ignored when AllowedKeyIDsOnly
	// is set.
	//
	// The limit cannot tell an invented key ID from a real one it has not seen
	// before, so during a flood a real new key may not be fetched until the
	// flood eases.  AllowedKeyIDs is the way to protect a key from that.
	FetchRateLimit time.Duration

	// CacheTime is how long a fetched key is held when the server does not
	// say.  A response's Cache-Control max-age, when present, is used instead.
	// Either way the time is kept between MinCacheTime and MaxCacheTime.  If
	// zero, DefaultCacheTime is used.
	//
	// When the time is up, the next token that names the key causes it to be
	// fetched again.  If the server then says there is no such key, the key
	// is dropped at once.  If the server cannot answer, the key keeps
	// serving, so that an outage of the key server is not an outage of every
	// service that verifies with it.
	CacheTime time.Duration

	// MinCacheTime is the shortest time a fetched key is held, whatever the
	// server says.  Without it, a server that gave a tiny max-age would be
	// asked on nearly every token.  If zero, DefaultMinCacheTime is used.
	MinCacheTime time.Duration

	// MaxCacheTime is the longest time a fetched key is held, whatever the
	// server says, and so bounds how long a key the server has removed can
	// still verify.  If zero, DefaultMaxCacheTime is used.  A value below the
	// effective MinCacheTime is raised to it.
	MaxCacheTime time.Duration

	// NotFoundCoolDown is the wait before a key ID is asked for again after
	// the server said there is no such key, or served a key that was
	// rejected.  The server answered, so asking again soon would get the same
	// answer.  If zero, DefaultNotFoundCoolDown is used.
	NotFoundCoolDown time.Duration

	// FailureCoolDown is the wait before a key ID is asked for again after the
	// server could not answer: a timeout, a refused connection, a 500.  The
	// outage may be brief, so this is short.  A Retry-After on a 429 or 503
	// is used instead, up to MaxCacheTime.  If zero, DefaultFailureCoolDown
	// is used.
	FailureCoolDown time.Duration

	// MaxResponseBytes caps the body read from the server.  A larger body
	// fails the fetch with ErrResponseTooLarge.  If less than 1,
	// DefaultMaxResponseBytes is used.
	MaxResponseBytes int64

	// Verify is the set of checks applied to a key before it is offered to
	// jwx.
	Verify VerifyConfig
}

// FetchEvent describes one fetch of one key by a PerKeyProvider.  It is
// dispatched to every FetchListener after every fetch, successful or not.  A
// lookup that needed no request, or was refused one, produces no event.
type FetchEvent struct {
	// KeyID is the key ID that was asked for.  It comes from a token that had
	// not been verified, though it has passed the check on what a key ID may
	// hold.
	KeyID string

	// URI is the provider's URL template, with any password redacted.  It
	// names the provider and is the same for every key, so it is safe to use
	// as a metric label where KeyID is not.
	URI string

	// Err is why the fetch failed, or nil.
	Err error
}

// FetchListener is a sink for FetchEvents.  OnFetchEvent is called from the
// goroutine that made the fetch and must not panic.
type FetchListener interface {
	OnFetchEvent(FetchEvent)
}

// perKeyEntry is what a PerKeyProvider remembers about one key ID, guarded by
// PerKeyProvider.lock.  An entry exists only for a key ID that has actually
// been fetched for, so what a provider remembers is bounded by how often it is
// allowed to fetch.
type perKeyEntry struct {
	// key is the key held for this key ID, or nil if none is.
	key jwk.Key

	// expires is when key must be fetched again.  A key past this time keeps
	// serving for as long as it cannot be replaced.
	expires time.Time

	// coolDown is the end of the wait after a failed fetch.  No fetch for this
	// key ID starts before it.
	coolDown time.Time

	// inFlight is non-nil while a fetch for this key ID is running, and is
	// closed when that fetch ends.  Every lookup for the key ID waits on it,
	// so they share the one request.
	inFlight chan struct{}
}

// PerKeyProvider supplies verification keys by fetching each one from a
// server that serves single keys, named by the key ID in a token.  It is what
// a service uses against a server, such as themis, that offers no key set.
//
// Unlike a KeySetProvider, a PerKeyProvider can be made to send a request by
// a token, since the key ID it asks for comes from one.  PerKeyConfig bounds
// what that can cost.  A service that can list its key IDs should, with
// AllowedKeyIDs.
//
// A PerKeyProvider has no background work: it fetches only when a token asks.
// There is nothing to start or stop.
type PerKeyProvider struct {
	cfg PerKeyConfig

	// template is PerKeyConfig.Template, in which every {keyID} is replaced
	// by a key ID to make the URL for that key.
	template string

	// redacted is the template with any password hidden, for events.
	redacted string

	allowed   map[string]bool
	listeners eventor.Eventor[FetchListener]
	clock     chronon.Clock

	lock    sync.Mutex
	entries map[string]*perKeyEntry

	// lastUnlisted is when a fetch for a key ID outside the allowed list last
	// started.  It is the zero time until the first one.
	lastUnlisted time.Time
}

var _ jws.KeyProvider = (*PerKeyProvider)(nil)

// NewPerKeyProvider builds a PerKeyProvider from a PerKeyConfig.  It rejects a
// template that is missing or unusable (ErrInvalidTemplate), a template whose
// scheme is not http or https (ErrUnsupportedScheme), a missing Client
// (ErrMissingClient), an allowed key ID that is not a valid key ID
// (ErrInvalidKeyID), and AllowedKeyIDsOnly with no allowed key IDs
// (ErrNoAllowedKeyIDs).  Every problem is reported, joined, rather than just
// the first.
func NewPerKeyProvider(cfg PerKeyConfig) (*PerKeyProvider, error) {
	errs := []error{checkTemplate(cfg.Template)}

	if cfg.Client == nil {
		errs = append(errs, fmt.Errorf("%w: a PerKeyProvider always fetches over http or https", ErrMissingClient))
	}

	allowed := make(map[string]bool, len(cfg.AllowedKeyIDs))
	for _, keyID := range cfg.AllowedKeyIDs {
		if err := validateKeyID(keyID); err != nil {
			errs = append(errs, fmt.Errorf("allowed key ID: %w", err))
			continue
		}

		allowed[keyID] = true
	}

	if cfg.AllowedKeyIDsOnly && len(cfg.AllowedKeyIDs) == 0 {
		errs = append(errs, ErrNoAllowedKeyIDs)
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	cfg = cfg.withDefaults()
	return &PerKeyProvider{
		cfg:      cfg,
		template: cfg.Template,
		redacted: redactTemplate(cfg.Template),
		allowed:  allowed,
		clock:    chronon.SystemClock(),
		entries:  make(map[string]*perKeyEntry),
	}, nil
}

// withDefaults returns a copy of the config with every zero or invalid field
// replaced by its default.  The caller's AllowedKeyIDs slice is not kept.
func (cfg PerKeyConfig) withDefaults() PerKeyConfig {
	cfg.AllowedKeyIDs = slices.Clone(cfg.AllowedKeyIDs)

	if cfg.FetchRateLimit <= 0 {
		cfg.FetchRateLimit = DefaultFetchRateLimit
	}

	if cfg.CacheTime <= 0 {
		cfg.CacheTime = DefaultCacheTime
	}

	if cfg.MinCacheTime <= 0 {
		cfg.MinCacheTime = DefaultMinCacheTime
	}

	if cfg.MaxCacheTime <= 0 {
		cfg.MaxCacheTime = DefaultMaxCacheTime
	}

	if cfg.MaxCacheTime < cfg.MinCacheTime {
		cfg.MaxCacheTime = cfg.MinCacheTime
	}

	if cfg.NotFoundCoolDown <= 0 {
		cfg.NotFoundCoolDown = DefaultNotFoundCoolDown
	}

	if cfg.FailureCoolDown <= 0 {
		cfg.FailureCoolDown = DefaultFailureCoolDown
	}

	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = DefaultMaxResponseBytes
	}

	return cfg
}

// checkTemplate checks a URL template.  A template is never quoted in an
// error, since it may hold a password that cannot be redacted without parsing
// it.
func checkTemplate(template string) error {
	if template == "" {
		return fmt.Errorf("%w: a template is required", ErrInvalidTemplate)
	}

	return checkKeyIDPlacement(template, keyIDPlaceholder)
}

// redactTemplate returns a template with any password hidden.  Redacting
// re-encodes the path, which turns the braces of the placeholder into percent
// escapes, so they are put back.
func redactTemplate(template string) string {
	return strings.ReplaceAll(redactURI(template), url.PathEscape(keyIDPlaceholder), keyIDPlaceholder)
}

// checkKeyIDPlacement parses a URL in which keyID stands where a key ID will
// go, and reports whether that is somewhere a key ID may be.  A key ID may
// only fill in a path or a query, so that it can never change which server is
// asked, or with what credentials.
//
// The URL must parse, and the parts a key ID may not be in must not hold
// keyID.  For the {keyID} placeholder itself the parser does most of the work:
// braces are not legal in a server name, a port, or credentials, so a template
// with the placeholder there does not parse at all.  The parts are examined
// all the same, so that the rule does not rest on what the parser happens to
// refuse.
func checkKeyIDPlacement(uri, keyID string) error {
	u, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("%w: it could not be parsed as a URL; %s may only be in the path or the query", ErrInvalidTemplate, keyIDPlaceholder)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: a template's scheme must be http or https", ErrUnsupportedScheme)
	}

	switch {
	case u.Host == "":
		return fmt.Errorf("%w: it names no server", ErrInvalidTemplate)

	case strings.Contains(u.Host, keyID):
		// Host holds the port too
		return fmt.Errorf("%w: %s must not be in the server name or port", ErrInvalidTemplate, keyIDPlaceholder)

	case u.User != nil && strings.Contains(u.User.String(), keyID):
		return fmt.Errorf("%w: %s must not be in the credentials", ErrInvalidTemplate, keyIDPlaceholder)

	case strings.Contains(u.Fragment, keyID):
		// a fragment is never sent, so every key would be asked for at one URL
		return fmt.Errorf("%w: %s must not be in a fragment", ErrInvalidTemplate, keyIDPlaceholder)

	case !strings.Contains(u.Path, keyID) && !strings.Contains(u.RawQuery, keyID):
		return fmt.Errorf("%w: %s must be in the path or the query", ErrInvalidTemplate, keyIDPlaceholder)
	}

	return nil
}

// validateKeyID reports whether a key ID may be put into a URL.  The rule is
// an allow list: anything not named here is refused, which is safer than
// trying to name everything that could change what a URL means.
func validateKeyID(keyID string) error {
	switch {
	case keyID == "":
		return fmt.Errorf("%w: it is empty", ErrInvalidKeyID)

	case len(keyID) > maxKeyIDLength:
		return fmt.Errorf("%w: it is longer than %d characters", ErrInvalidKeyID, maxKeyIDLength)

	case strings.Contains(keyID, ".."):
		return fmt.Errorf(`%w: %q holds ".."`, ErrInvalidKeyID, keyID)
	}

	for _, c := range keyID {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return fmt.Errorf("%w: %q holds %q", ErrInvalidKeyID, keyID, c)
		}
	}

	return nil
}

// AddListener registers a sink for FetchEvents.  Only events after this call
// are delivered.  The returned closure removes the listener; calling it more
// than once has no further effect.
func (p *PerKeyProvider) AddListener(l FetchListener) (cancel func()) {
	return p.listeners.Add(l)
}

// KeyIDs lists the key IDs of the keys currently held, sorted, for health
// endpoints.  A PerKeyProvider holds nothing until a token asks, so an empty
// list is its normal state after start-up and says nothing about readiness.
func (p *PerKeyProvider) KeyIDs() []string {
	p.lock.Lock()
	defer p.lock.Unlock()

	keyIDs := make([]string, 0, len(p.entries))
	for keyID, e := range p.entries {
		if e.key != nil {
			keyIDs = append(keyIDs, keyID)
		}
	}

	slices.Sort(keyIDs)
	return keyIDs
}

// FetchKeys satisfies jws.KeyProvider, and is the only way a key leaves the
// PerKeyProvider.  It finds the key for the protected header's kid, fetching
// it if it is not held and a fetch is allowed, applies the VerifyConfig
// checks, and offers the key to jwx under the header's alg.
//
// When the key is not held and has to be fetched, FetchKeys waits for that
// fetch, for as long as the Client allows or until ctx ends.
//
// Errors carry sentinels for errors.Is: ErrMissingKeyID, ErrKeyNotFound,
// ErrInvalidKeyID, ErrMissingAlgorithm, ErrKeyUsage, and ErrKeyAlgorithm.
func (p *PerKeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	headers := sig.ProtectedHeaders()
	keyID, ok := headers.KeyID()
	if !ok || keyID == "" {
		return fmt.Errorf(`%w: protected header has no "kid"`, ErrMissingKeyID)
	}

	// the key ID comes from a token nobody has verified, and is about to go
	// into a URL.  one that fails this check is refused before anything else.
	if err := validateKeyID(keyID); err != nil {
		return fmt.Errorf("%w: %w", ErrKeyNotFound, err)
	}

	key := p.lookup(ctx, keyID)
	if key == nil {
		return fmt.Errorf("%w: %q", ErrKeyNotFound, keyID)
	}

	return p.cfg.Verify.offer(sink, headers, keyID, key)
}

// lookup returns the key for a key ID, or nil.  keyID has been validated.
//
// A key that is held and in date is returned at once.  Otherwise a fetch is
// needed: lookup joins one that is already running, or starts one if that is
// allowed, and waits for it.  A key whose time is up keeps serving whenever it
// could not be replaced, whether because a fetch was not allowed, because the
// server could not answer, or because the caller stopped waiting.
func (p *PerKeyProvider) lookup(ctx context.Context, keyID string) jwk.Key {
	p.lock.Lock()
	now := p.clock.Now()
	e := p.entries[keyID]
	if e != nil && e.key != nil && now.Before(e.expires) {
		defer p.lock.Unlock()
		return e.key
	}

	var done chan struct{}
	switch {
	case e != nil && e.inFlight != nil:
		done = e.inFlight

	case p.mayFetch(keyID, e, now):
		done = p.startFetch(ctx, keyID, now)
	}

	// held is what serves if no fetch replaces it
	var held jwk.Key
	if e != nil {
		held = e.key
	}

	p.lock.Unlock()
	if done == nil {
		return held
	}

	select {
	case <-done:
		// the fetch decided what is held now: a new key, the old one because
		// the server could not answer, or nothing because the key is gone
		p.lock.Lock()
		defer p.lock.Unlock()
		if e := p.entries[keyID]; e != nil {
			return e.key
		}

		return nil

	case <-ctx.Done():
		return held
	}
}

// mayFetch reports whether a fetch for a key ID may start now.  e is the
// entry for the key ID, which may be nil.  The caller holds p.lock.
func (p *PerKeyProvider) mayFetch(keyID string, e *perKeyEntry, now time.Time) bool {
	if e != nil && now.Before(e.coolDown) {
		return false
	}

	if p.allowed[keyID] {
		return true
	}

	if p.cfg.AllowedKeyIDsOnly {
		return false
	}

	return p.lastUnlisted.IsZero() || now.Sub(p.lastUnlisted) >= p.cfg.FetchRateLimit
}

// startFetch starts a fetch for a key ID and returns the channel that is
// closed when it ends.  The caller holds p.lock, and has checked mayFetch.
//
// The fetch runs on its own goroutine and is not canceled when ctx is: other
// lookups share it, and one caller giving up must not fail the rest.  It does
// keep ctx's values, for a Client that reads them.
func (p *PerKeyProvider) startFetch(ctx context.Context, keyID string, now time.Time) chan struct{} {
	if !p.allowed[keyID] {
		p.lastUnlisted = now
	}

	e := p.entries[keyID]
	if e == nil {
		e = new(perKeyEntry)
		p.entries[keyID] = e
	}

	e.inFlight = make(chan struct{})
	go p.fetch(context.WithoutCancel(ctx), keyID, e)
	return e.inFlight
}

// fetch asks the server for one key, records the outcome, releases every
// lookup waiting on it, and dispatches an event.
func (p *PerKeyProvider) fetch(ctx context.Context, keyID string, e *perKeyEntry) {
	c, err := loadHTTP(ctx, httpGet{
		client:   p.cfg.Client,
		uri:      strings.ReplaceAll(p.template, keyIDPlaceholder, keyID),
		accept:   perKeyAccept,
		maxBytes: p.cfg.MaxResponseBytes,
	})

	var key jwk.Key
	if err == nil {
		key, err = parseKey(c.data, keyID)
	}

	p.lock.Lock()
	now := p.clock.Now()
	switch {
	case err == nil:
		e.key = key
		e.expires = now.Add(p.cacheTime(c.ttl))
		e.coolDown = time.Time{}

	case isNoSuchKey(err):
		// the server answered, and the key is not there.  this is how a key the
		// server removed stops verifying.
		e.key = nil
		e.coolDown = now.Add(p.cfg.NotFoundCoolDown)

	case isRejectedKey(err):
		// the server answered with a key that cannot be used.  asking again
		// soon would get the same key, and whatever was held before is still
		// the last good one.
		e.coolDown = now.Add(p.cfg.NotFoundCoolDown)

	default:
		// the server could not answer.  what was held keeps serving.
		wait := p.cfg.FailureCoolDown
		if asked := c.retryWait(now); asked > 0 {
			wait = min(asked, p.cfg.MaxCacheTime)
		}

		e.coolDown = now.Add(wait)
	}

	close(e.inFlight)
	e.inFlight = nil
	p.forget(now)
	p.lock.Unlock()

	p.listeners.Visit(func(l FetchListener) {
		l.OnFetchEvent(FetchEvent{KeyID: keyID, URI: p.redacted, Err: err})
	})
}

// cacheTime returns how long a key just fetched is held: the time the server
// gave, or the configured one, kept between the minimum and the maximum.
func (p *PerKeyProvider) cacheTime(ttl time.Duration) time.Duration {
	held := p.cfg.CacheTime
	if ttl > 0 {
		held = ttl
	}

	return max(p.cfg.MinCacheTime, min(held, p.cfg.MaxCacheTime))
}

// forget drops what no longer needs remembering: a key ID with no key, no
// fetch running, and no cool-down left.  Such an entry records only that a
// fetch once failed.  The caller holds p.lock.
func (p *PerKeyProvider) forget(now time.Time) {
	for keyID, e := range p.entries {
		if e.key == nil && e.inFlight == nil && !now.Before(e.coolDown) {
			delete(p.entries, keyID)
		}
	}
}

// isNoSuchKey reports whether a fetch failed because the server said the key
// does not exist.
func isNoSuchKey(err error) bool {
	var httpErr *HTTPError
	return errors.As(err, &httpErr) &&
		(httpErr.StatusCode == http.StatusNotFound || httpErr.StatusCode == http.StatusGone)
}

// isRejectedKey reports whether a fetch failed because of the key the server
// returned, rather than because the server could not be read.
func isRejectedKey(err error) bool {
	return errors.Is(err, ErrSymmetricKey) ||
		errors.Is(err, ErrKeyIDMismatch) ||
		errors.Is(err, ErrResponseTooLarge)
}
