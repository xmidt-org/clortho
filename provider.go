// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/xmidt-org/chronon"
)

// SourceStatus is the last outcome for one source, as reported by
// Provider.Status.
type SourceStatus struct {
	// URI is the source's URI with any password redacted.  It matches
	// RefreshSource.URI otherwise.
	URI string

	// LastRetrieved is when the source last loaded successfully.  A 304 counts.
	// Zero if it never has.
	LastRetrieved time.Time

	// LastStatusCode is the status of the last HTTP response, including a 304
	// or an error status.  Zero for a file source, or when the last attempt got
	// no response at all.
	LastStatusCode int

	// LastErr is the error from the last attempt, or nil if it succeeded.
	LastErr error
}

// sourceState is what the Provider tracks per source, guarded by
// Provider.stateLock.
type sourceState struct {
	status SourceStatus

	// lastAttempt is when the source was last loaded, successfully or not.  It
	// rate-limits early refreshes.
	lastAttempt time.Time

	// lastModified is the Last-Modified of the last successful HTTP load, sent
	// back as If-Modified-Since.
	lastModified time.Time
}

// Provider supplies verification keys.  It is the one thing clortho makes,
// and it is named for the role it fills: it is what a caller hands to
// jwt.WithKeyProvider.
//
// A Provider polls its sources for their complete key sets and serves lookups
// from that.  It never fetches a key on demand, so a token cannot cause a
// request; see VerifyConfig.RefreshOnUnknownKeyID for the one opt-in
// exception.
type Provider struct {
	sources []RefreshSource
	verify  VerifyConfig

	ring      ring
	listeners listeners
	clock     chronon.Clock

	stateLock sync.Mutex
	states    []sourceState

	runLock sync.Mutex
	runCtx  context.Context
	cancel  context.CancelFunc
	tasks   []*refreshTask
	done    chan struct{}
}

var _ jws.KeyProvider = (*Provider)(nil)

// New builds a Provider from a Config.  It rejects a Config with no sources
// (ErrNoKeySources), a source whose scheme is not file, http, or https
// (ErrUnsupportedScheme), and a duplicate source URI.  Every problem is
// reported, joined, rather than just the first.
//
// The returned Provider is not running; call Start.
func New(cfg Config) (*Provider, error) {
	sources, err := normalizeSources(cfg.Sources)
	if err != nil {
		return nil, err
	}

	p := &Provider{
		sources: sources,
		verify:  cfg.Verify,
		clock:   chronon.SystemClock(),
		states:  make([]sourceState, len(sources)),
	}

	for i, s := range sources {
		p.states[i].status.URI = redactURI(s.URI)
	}

	return p, nil
}

// Start begins refreshing every source.  It returns once the refresh loops are
// running; it does not wait for the first fetch.  Use Status to decide when
// the Provider is ready to serve.  The context governs only this call, not
// the life of the loops; see Stop.
//
// Start returns ErrAlreadyStarted if the Provider is running.
func (p *Provider) Start(context.Context) error {
	p.runLock.Lock()
	defer p.runLock.Unlock()

	if p.cancel != nil {
		return ErrAlreadyStarted
	}

	p.runCtx, p.cancel = context.WithCancel(context.Background())
	p.done = make(chan struct{})
	p.tasks = make([]*refreshTask, len(p.sources))

	var wg sync.WaitGroup
	for i := range p.sources {
		p.tasks[i] = newRefreshTask(p, i)
		wg.Add(1)
		go func(t *refreshTask) {
			defer wg.Done()
			t.run(p.runCtx)
		}(p.tasks[i])
	}

	go func(done chan struct{}) {
		wg.Wait()
		close(done)
	}(p.done)

	return nil
}

// Stop ends the refresh loops and waits for them to exit, or for ctx to end.
// The ring keeps its keys, and Start may be called again.
//
// Stop returns ErrNotStarted if the Provider is not running.
func (p *Provider) Stop(ctx context.Context) error {
	p.runLock.Lock()
	defer p.runLock.Unlock()

	if p.cancel == nil {
		return ErrNotStarted
	}

	p.cancel()
	p.cancel, p.runCtx, p.tasks = nil, nil, nil

	select {
	case <-p.done:
		return nil

	case <-ctx.Done():
		return ctx.Err()
	}
}

// AddListener registers a sink for RefreshEvents.  Only events after this call
// are delivered.  The returned closure removes the listener and is idempotent.
func (p *Provider) AddListener(l Listener) CancelListenerFunc {
	return p.listeners.addListener(l)
}

func (p *Provider) dispatch(event RefreshEvent) {
	p.listeners.visit(func(l any) {
		l.(Listener).OnRefreshEvent(event)
	})
}

// KeyIDs lists the key IDs currently on the ring, sorted, for health endpoints.
func (p *Provider) KeyIDs() []string {
	return p.ring.keyIDs()
}

// Status reports the state of every source, in Config order.  A service's
// readiness check decides what ready means from this: for example, every
// source has a non-zero LastRetrieved, or at least one does.
func (p *Provider) Status() []SourceStatus {
	p.stateLock.Lock()
	defer p.stateLock.Unlock()

	status := make([]SourceStatus, len(p.states))
	for i := range p.states {
		status[i] = p.states[i].status
	}

	return status
}

// FetchKeys satisfies jws.KeyProvider, and is the only way a key leaves the
// Provider.  It looks the protected header's kid up on the ring, applies the
// VerifyConfig checks, and offers the key to jwx under the header's alg.  jwx
// then decides whether the key can serve that algorithm.
//
// Errors carry sentinels for errors.Is: ErrMissingKeyID, ErrKeyNotFound,
// ErrMissingAlgorithm, ErrKeyUsage, and ErrKeyAlgorithm.
func (p *Provider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, _ *jws.Message) error {
	headers := sig.ProtectedHeaders()
	keyID, ok := headers.KeyID()
	if !ok || keyID == "" {
		return fmt.Errorf(`%w: protected header has no "kid"`, ErrMissingKeyID)
	}

	key, ok := p.lookup(ctx, keyID)
	if !ok {
		return fmt.Errorf("%w: %q", ErrKeyNotFound, keyID)
	}

	if !p.verify.IgnoreKeyUsage {
		if usage, ok := key.KeyUsage(); ok && usage != "" && usage != jwk.ForSignature.String() {
			return fmt.Errorf("%w: key %q has use %q", ErrKeyUsage, keyID, usage)
		}
	}

	alg, ok := headers.Algorithm()
	if !ok {
		return ErrMissingAlgorithm
	}

	if !p.verify.IgnoreKeyAlgorithm {
		if keyAlg, ok := key.Algorithm(); ok && keyAlg.String() != "" && keyAlg.String() != alg.String() {
			return fmt.Errorf("%w: key %q has alg %q, header has %q", ErrKeyAlgorithm, keyID, keyAlg.String(), alg.String())
		}
	}

	sink.Key(alg, key)
	return nil
}

// lookup finds a key on the ring.  On a miss with RefreshOnUnknownKeyID set
// and the Provider running, it asks every source for an early refresh, waits,
// and looks again.
func (p *Provider) lookup(ctx context.Context, keyID string) (jwk.Key, bool) {
	if key, ok := p.ring.get(keyID); ok {
		return key, true
	}

	if !p.verify.RefreshOnUnknownKeyID {
		return nil, false
	}

	p.runLock.Lock()
	tasks, runCtx := p.tasks, p.runCtx
	p.runLock.Unlock()
	if len(tasks) == 0 {
		return nil, false
	}

	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Add(1)
		go func(t *refreshTask) {
			defer wg.Done()
			t.requestRefresh(ctx, runCtx)
		}(t)
	}

	wg.Wait()
	return p.ring.get(keyID)
}
