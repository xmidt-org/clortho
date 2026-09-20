// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"unicode"

	"github.com/jtacoma/uritemplates"
)

const (
	// KeyIDParameter is the name of the URI template parameter for expanding key URIs.
	KeyIDParameterName = "keyID"
)

var (
	// ErrNoTemplate indicates that no URI template is available for that Resolver's method.
	ErrNoTemplate = errors.New("no URI template expander has been configured for that method")

	// ErrKeyNotFound indicates that a key could not be resolved, e.g. a key ID did not exist.
	ErrKeyNotFound = errors.New("no such key exists")

	// ErrInvalidKeyID indicates that a key ID was rejected before being expanded
	// into a URI.  See ValidateKeyID for the default rule and WithKeyIDValidator to
	// change it.  A custom validator's error is wrapped so that this sentinel still
	// classifies it.
	ErrInvalidKeyID = errors.New("invalid key ID")

	// ErrUnsafeTemplate indicates that a URI template lets the key ID decide where
	// keys are fetched from, or has no literal origin at all, so no expansion of it
	// could be checked.  A template must begin with a literal scheme and, for http
	// and https, a literal host, and its variable must come after the path begins.
	ErrUnsafeTemplate = errors.New("URI template must have a literal scheme, host, and path before its variable")

	// ErrLocationOutsideTemplate indicates that an expanded location did not stay
	// within the origin and path prefix of the template it came from, and was not
	// fetched.  This is defense in depth behind ValidateKeyID: it holds even when a
	// custom validator allows path characters.
	ErrLocationOutsideTemplate = errors.New("resolved location is outside the configured template")

	// ErrFetchPanicked is returned to goroutines that were waiting on a fetch which
	// panicked in another goroutine.  The panic itself propagates in the goroutine
	// that performed the fetch.
	ErrFetchPanicked = errors.New("the fetch for that key panicked")
)

// ResolveEvent holds information about a key ID that has been resolved.
type ResolveEvent struct {
	// URI is the actual, expanded URI used to obtain the key material, with any
	// password in its userinfo redacted.  It is empty when the key ID was rejected
	// before expansion.
	URI string

	// KeyID is the key ID that was resolved.
	KeyID string

	// Key is the key material that was returned from the URI.
	Key Key

	// Err holds any error that occurred while trying to fetch key material.
	// If this field is set, Key will be nil.
	Err error
}

// ResolveListener is a sink for ResolveEvents.
type ResolveListener interface {
	// OnResolveEvent receives notifications for attempts to resolve keys.  This
	// method must not panic.
	OnResolveEvent(ResolveEvent)
}

// ValidateKeyID is the default rule a Resolver applies to a key ID before
// expanding it into a URI.  The key ID is the one input to this package that
// arrives from an unauthenticated party, and a URI template gives it a path
// into a file system or an HTTP request.  This rule rejects, with
// ErrInvalidKeyID: an empty key ID; a path separator, '/' or '\\'; the sequence
// ".."; the URI delimiters '?', '#' and '%', the last because a reserved
// expansion such as {+keyID} passes percent sequences through unencoded; and
// any whitespace or control character.
//
// A deployment whose key IDs legitimately contain something on that list, such
// as a URL, supplies its own rule with WithKeyIDValidator.
func ValidateKeyID(keyID string) error {
	if len(keyID) == 0 {
		return fmt.Errorf("%w: empty", ErrInvalidKeyID)
	}

	if strings.Contains(keyID, "..") {
		return fmt.Errorf("%w: %q contains \"..\"", ErrInvalidKeyID, keyID)
	}

	for _, c := range keyID {
		switch {
		case c == '/', c == '\\', c == '?', c == '#', c == '%':
			return fmt.Errorf("%w: %q contains %q", ErrInvalidKeyID, keyID, c)

		case unicode.IsSpace(c), unicode.IsControl(c):
			return fmt.Errorf("%w: %q contains whitespace or a control character", ErrInvalidKeyID, keyID)
		}
	}

	return nil
}

// templateOrigin is the literal part of a URI template that every expansion
// must stay within: the scheme, the host including any port, and the path up to
// the first variable.  For an opaque scheme such as urn:, which a custom Loader
// may be registered for, the prefix is the opaque part up to the variable.
type templateOrigin struct {
	scheme     string
	host       string
	pathPrefix string
	opaque     bool
}

// parseTemplateOrigin derives the origin from a URI template, or reports why
// the template cannot be pinned to one.
func parseTemplateOrigin(rawTemplate string) (*templateOrigin, error) {
	prefix := rawTemplate
	if i := strings.IndexByte(rawTemplate, '{'); i >= 0 {
		prefix = rawTemplate[:i]
	}

	// messages quote the template redacted: a credentialed template that is
	// rejected must not put its password in the startup log
	u, err := url.Parse(prefix)
	if err != nil {
		return nil, fmt.Errorf("%w: %q could not be parsed before its variable", ErrUnsafeTemplate, redactURI(rawTemplate))
	}

	switch {
	case u.Scheme == "":
		return nil, fmt.Errorf("%w: %q has no scheme before its variable", ErrUnsafeTemplate, redactURI(rawTemplate))

	case (u.Scheme == "http" || u.Scheme == "https") && u.Host == "":
		return nil, fmt.Errorf("%w: %q has no host before its variable", ErrUnsafeTemplate, redactURI(rawTemplate))

	case u.Host == "" && u.Path == "" && u.Opaque != "":
		// an opaque form, e.g. urn:keys:{keyID}; the literal opaque part is the prefix
		return &templateOrigin{
			scheme:     u.Scheme,
			pathPrefix: u.Opaque,
			opaque:     true,
		}, nil

	case u.Path == "":
		return nil, fmt.Errorf("%w: %q places its variable before the path begins", ErrUnsafeTemplate, redactURI(rawTemplate))
	}

	return &templateOrigin{
		scheme:     u.Scheme,
		host:       u.Host,
		pathPrefix: u.Path,
	}, nil
}

// canonicalPath reports whether p has no ".", ".." or empty segment.  A
// legitimate key ID never needs those to reach its key, and refusing them means
// the prefix comparison below cannot be defeated by a path that climbs out of
// one prefix and into a sibling that happens to share its leading characters.
// A trailing slash is allowed.
func canonicalPath(p string) bool {
	segments := strings.Split(p, "/")
	for i, segment := range segments[1:] {
		switch {
		case segment == "." || segment == "..":
			return false

		case segment == "" && i != len(segments)-2:
			return false
		}
	}

	return true
}

// check reports whether an expanded location stays within the origin.
func (to *templateOrigin) check(location string) error {
	// the standard library's parse error quotes its input, so it is not wrapped;
	// the location is quoted redacted instead
	u, err := url.Parse(location)
	if err != nil {
		return fmt.Errorf("%w: %q could not be parsed", ErrLocationOutsideTemplate, redactURI(location))
	}

	inside := u.Scheme == to.scheme
	if to.opaque {
		inside = inside && strings.HasPrefix(u.Opaque, to.pathPrefix)
	} else {
		inside = inside && u.Host == to.host && canonicalPath(u.Path) && strings.HasPrefix(u.Path, to.pathPrefix)
	}

	if !inside {
		return fmt.Errorf("%w: %q is not under %s", ErrLocationOutsideTemplate, u.Redacted(), to.String())
	}

	return nil
}

// String renders the origin the way a template author wrote it.
func (to *templateOrigin) String() string {
	if to.opaque {
		return to.scheme + ":" + to.pathPrefix
	}

	return to.scheme + "://" + to.host + to.pathPrefix
}

// Expander is the strategy for expanding a URI template.
type Expander interface {
	// Expand takes a value map and returns the URI resulting from that expansion.
	Expand(any) (string, error)
}

// noTemplateExpander is installed when the configured template is empty.  It makes
// the Resolver ring-only: keys already on the ring resolve, and a miss reports
// ErrNoTemplate instead of attempting a fetch from an empty location.  This is what
// an application that configured refresh sources but no resolve template gets.
type noTemplateExpander struct{}

func (noTemplateExpander) Expand(any) (string, error) {
	return "", ErrNoTemplate
}

// NewExpander constructs an Expander from a URI template.
func NewExpander(rawTemplate string) (Expander, error) {
	return uritemplates.Parse(rawTemplate)
}

// Resolver allows synchronous resolution of keys.
type Resolver interface {
	// Resolve attempts to locate a key with a given keyID (kid).
	//
	// A fetched key is returned only if it is the one asked for.  In a key set,
	// that means the key whose kid matches.  A single-key response must either
	// carry the requested kid or have had no kid at all, in which case it is
	// returned under the requested kid; a single key with a different kid is
	// reported as ErrKeyNotFound and never reaches the ring.
	//
	// A key ID that is not on the ring is validated before it is expanded into a
	// URI, by ValidateKeyID unless WithKeyIDValidator was given; a rejected key ID
	// fails with ErrInvalidKeyID, causes no fetch, and is reported to listeners as
	// a ResolveEvent with the error set and no URI.  After expansion, the location
	// must stay within the template's literal scheme, host, and path prefix, or it
	// fails with ErrLocationOutsideTemplate, again with no fetch; see
	// WithKeyIDTemplate.  A custom Expander is not subject to that check.
	//
	// Every unknown kid costs a fetch, and every kid answered with a kid-less key
	// becomes its own ring entry; the ring has no eviction.  A Resolver exposed to
	// untrusted kids can therefore be made to fetch and grow without bound, which
	// is why a jws.KeyProvider never consults one.
	Resolve(ctx context.Context, keyID string) (Key, error)

	// AddListener attaches a sink for ResolveEvents.  Only events that
	// occur after this method call will be dispatched to the given listener.
	AddListener(ResolveListener) CancelListenerFunc
}

// NewResolver constructs a Resolver from a set of options.  By default, a Resolver
// uses the DefaultLoader() and DefaultParser().
//
// If no URI template option is supplied at all, this function returns ErrNoTemplate.
// Whenever the returned error is non-nil, the returned Resolver is nil.
//
// An empty template, as from WithConfig with no Resolve.Template set, is accepted and
// yields a ring-only Resolver: keys already on the ring resolve, and any other key ID
// fails with ErrNoTemplate rather than an attempted fetch.
func NewResolver(options ...ResolverOption) (Resolver, error) {
	var (
		errs []error

		r = &resolver{
			pending:        pendingResolverRequests{},
			keyIDValidator: ValidateKeyID,
		}
	)

	for _, o := range options {
		errs = append(errs, o.applyToResolver(r))
	}

	if r.fetcher == nil {
		r.fetcher = NewFetcher()
	}

	if r.keyIDExpander == nil {
		errs = append(errs, ErrNoTemplate)
	}

	if err := errors.Join(errs...); err != nil {
		// NOTE: an explicit nil, not a nil *resolver, so that a caller comparing the
		// returned interface against nil sees what it expects.
		return nil, err
	}

	return r, nil
}

// pendingResolverRequest represents a resolve operation that is inflight.  Concurrent
// code may use this to block on the results of a resolve operation happening in another
// goroutine.
type pendingResolverRequest struct {
	keyID string
	done  chan struct{}

	// key and err are the outcome of the fetch.  They are written by the fetching
	// goroutine before done is closed, and read by waiters only after done is
	// closed, so the channel provides the necessary synchronization.
	key Key
	err error
}

// pendingResolverRequests holds the key requests that are in-flight.  Map keys
// are key IDs.  This type is not itself safe for concurrent access.
type pendingResolverRequests map[string]*pendingResolverRequest

// requestFor returns a pending request for a keyID.
//
// If wait is true, this is an existing request that is already in-flight within
// another goroutine.  In this case, the caller should wait on the request's done channel.
//
// If wait is false, this is a new request and the caller is responsible for executing
// the fetch of the key.
func (prr pendingResolverRequests) requestFor(keyID string) (r *pendingResolverRequest, wait bool) {
	r, wait = prr[keyID]
	if !wait {
		r = &pendingResolverRequest{
			keyID: keyID,
			done:  make(chan struct{}),
		}

		prr[keyID] = r
	}

	return
}

// cleanup removes the pending request.  This method needs to be guarded
// by an enclosing lock.
func (prr pendingResolverRequests) cleanup(request *pendingResolverRequest) {
	delete(prr, request.keyID)
	close(request.done)
}

// resolver is the internal Resolver implementation.
type resolver struct {
	fetcher   Fetcher
	listeners listeners

	resolveLock sync.Mutex
	pending     pendingResolverRequests
	keyRing     KeyRing

	keyIDExpander Expander

	// origin is derived from the key ID template and checked against every
	// expansion.  It is nil for a custom Expander, which has no template.
	origin *templateOrigin

	// keyIDValidator runs before a key ID is expanded into a URI.  nil disables
	// validation; see WithKeyIDValidator.
	keyIDValidator func(string) error
}

func (r *resolver) dispatch(event ResolveEvent) {
	r.listeners.visit(func(l any) {
		l.(ResolveListener).OnResolveEvent(event)
	})
}

func (r *resolver) checkKeyRing(keyID string) (k Key, ok bool) {
	if r.keyRing != nil {
		k, ok = r.keyRing.Get(keyID)
	}

	return
}

func (r *resolver) waitForKey(ctx context.Context, request *pendingResolverRequest) (k Key, err error) {
	select {
	case <-ctx.Done():
		err = ctx.Err()

	case <-request.done:
		k, err = request.key, request.err
	}

	return
}

// fetchAndRelease performs the fetch for a pending request, then releases every
// goroutine waiting on it with the outcome.  Release is guaranteed even when the
// fetch panics: waiters receive ErrFetchPanicked, and the panic continues to
// propagate in this goroutine.  Without that guarantee a panic would leave the
// request pending forever, and every later Resolve for the same key would wait
// on it.
func (r *resolver) fetchAndRelease(ctx context.Context, keyID string, request *pendingResolverRequest) (location string, k Key, err error) {
	defer func() {
		if p := recover(); p != nil {
			k, err = nil, fmt.Errorf("%w: %v", ErrFetchPanicked, p)
			defer panic(p)
		}

		if err == nil && r.keyRing != nil {
			r.keyRing.Add(k)
		}

		request.key, request.err = k, err

		r.resolveLock.Lock()
		r.pending.cleanup(request)
		r.resolveLock.Unlock()
	}()

	return r.fetchKey(ctx, keyID)
}

func (r *resolver) fetchKey(ctx context.Context, keyID string) (location string, k Key, err error) {
	location, err = r.keyIDExpander.Expand(map[string]any{
		KeyIDParameterName: keyID,
	})

	if err == nil && r.origin != nil {
		err = r.origin.check(location)
	}

	var keys []Key
	if err == nil {
		keys, _, err = r.fetcher.Fetch(ctx, location)
	}

	if err == nil {
		switch len(keys) {
		case 0:
			err = ErrKeyNotFound

		case 1:
			// a single key is the answer to the request only if it says so.  a key
			// whose kid came from the source and differs is a substitution, e.g. a
			// catch-all response, and must not be returned or cached under either
			// kid.  a key that had no kid at all is taken to be the requested one,
			// and adopts the requested kid so the ring can serve it next time.
			k = keys[0]
			switch {
			case k.KeyID() == keyID:
				// exact match

			case keyIDGenerated(k):
				k = withKeyID(k, keyID)

			default:
				k = nil
				err = ErrKeyNotFound
			}

		default:
			// scan a key set looking for the key in question
			for _, candidate := range keys {
				if candidate.KeyID() == keyID {
					k = candidate
					break
				}
			}

			if k == nil {
				err = ErrKeyNotFound
			}
		}
	}

	return
}

func (r *resolver) Resolve(ctx context.Context, keyID string) (k Key, err error) {
	var ok bool
	if k, ok = r.checkKeyRing(keyID); ok {
		return
	}

	// the ring's contents came from a trusted source, so a hit above needs no
	// validation.  a miss is about to become a URI, and that does.  a rejection
	// is dispatched like any other failed resolve, with no URI, so that listeners
	// can log and count a probe.
	if r.keyIDValidator != nil {
		if verr := r.keyIDValidator(keyID); verr != nil {
			if !errors.Is(verr, ErrInvalidKeyID) {
				verr = fmt.Errorf("%w: %w", ErrInvalidKeyID, verr)
			}

			r.dispatch(ResolveEvent{
				KeyID: keyID,
				Err:   verr,
			})

			return nil, verr
		}
	}

	r.resolveLock.Lock()
	if k, ok = r.checkKeyRing(keyID); ok {
		r.resolveLock.Unlock()
		return
	}

	request, wait := r.pending.requestFor(keyID)
	r.resolveLock.Unlock()

	if wait {
		// another goroutine is currently fetching the key, so wait for it to be done
		return r.waitForKey(ctx, request)
	}

	// this is the goroutine that is now responsible for fetching the key
	var location string
	location, k, err = r.fetchAndRelease(ctx, keyID, request)

	r.dispatch(ResolveEvent{
		URI:   redactURI(location),
		Key:   k,
		KeyID: keyID,
		Err:   err,
	})

	return
}

func (r *resolver) AddListener(l ResolveListener) CancelListenerFunc {
	return r.listeners.addListener(l)
}
