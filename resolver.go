// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"fmt"
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

	// ErrFetchPanicked is returned to goroutines that were waiting on a fetch which
	// panicked in another goroutine.  The panic itself propagates in the goroutine
	// that performed the fetch.
	ErrFetchPanicked = errors.New("the fetch for that key panicked")
)

// ResolveEvent holds information about a key ID that has been resolved.
type ResolveEvent struct {
	// URI is the actual, expanded URI used to obtain the key material.
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
	// a ResolveEvent with the error set and no URI.
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
		URI:   location,
		Key:   k,
		KeyID: keyID,
		Err:   err,
	})

	return
}

func (r *resolver) AddListener(l ResolveListener) CancelListenerFunc {
	return r.listeners.addListener(l)
}
