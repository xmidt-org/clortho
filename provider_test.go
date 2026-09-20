// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/chronon"
)

// eventListener collects refresh events on a channel.
type eventListener struct {
	events chan RefreshEvent
}

func newEventListener() *eventListener {
	return &eventListener{events: make(chan RefreshEvent, 100)}
}

func (l *eventListener) OnRefreshEvent(e RefreshEvent) { l.events <- e }

// next waits for an event or fails the test.
func (l *eventListener) next(t *testing.T) RefreshEvent {
	select {
	case e := <-l.events:
		return e

	case <-time.After(5 * time.Second):
		require.Fail(t, "no refresh event arrived")
		return RefreshEvent{}
	}
}

// none asserts that no event arrives for a short while.
func (l *eventListener) none(t *testing.T) {
	select {
	case e := <-l.events:
		require.Fail(t, "unexpected refresh event", "%+v", e)

	case <-time.After(100 * time.Millisecond):
	}
}

// keyServer serves whatever key set it is told to and counts requests.  A
// test that sets gate makes every request block until openGate is called;
// the gate is opened on cleanup regardless, so a failed test cannot hang on
// the server's shutdown.
type keyServer struct {
	*httptest.Server
	lock     sync.Mutex
	body     []byte
	status   int
	requests atomic.Int32
	gate     chan struct{}
	gateOnce sync.Once
}

// openGate releases every request blocked on the gate, once.
func (ks *keyServer) openGate() {
	ks.gateOnce.Do(func() {
		if ks.gate != nil {
			close(ks.gate)
		}
	})
}

func newKeyServer(t *testing.T, keys ...jwk.Key) *keyServer {
	ks := &keyServer{status: http.StatusOK}
	ks.serve(t, keys...)
	ks.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ks.gate != nil {
			<-ks.gate
		}

		ks.requests.Add(1)
		ks.lock.Lock()
		body, status := ks.body, ks.status
		ks.lock.Unlock()

		w.WriteHeader(status)
		_, _ = w.Write(body)
	}))
	t.Cleanup(ks.Close)
	t.Cleanup(ks.openGate) // runs before Close, since cleanups are LIFO
	return ks
}

func (ks *keyServer) serve(t *testing.T, keys ...jwk.Key) {
	body := jwkSetJSON(t, keys...)
	ks.lock.Lock()
	ks.body, ks.status = body, http.StatusOK
	ks.lock.Unlock()
}

func (ks *keyServer) fail(status int) {
	ks.lock.Lock()
	ks.status = status
	ks.lock.Unlock()
}

// testClock is a fake clock that records every timer the refresh loop arms,
// so a test can move time to the next refresh.  It subscribes at creation,
// before Start, so no timer is missed.
type testClock struct {
	*chronon.FakeClock
	timers chan chronon.FakeTimer
}

func newTestClock() *testClock {
	tc := &testClock{
		FakeClock: chronon.NewFakeClock(time.Now()),
		timers:    make(chan chronon.FakeTimer, 16),
	}

	tc.NotifyOnTimer(tc.timers)
	return tc
}

// advanceToTimer moves the clock to the next timer the refresh loop armed.
func (tc *testClock) advanceToTimer(t *testing.T) {
	select {
	case timer := <-tc.timers:
		tc.Set(timer.When())

	case <-time.After(5 * time.Second):
		require.Fail(t, "the refresh loop never armed a timer")
	}
}

// testProvider builds a Provider over the given config with a test clock and
// an event listener attached, and starts it.  The first refresh event of each
// source is consumed so that the ring is populated when this returns.
func testProvider(t *testing.T, cfg Config) (*Provider, *testClock, *eventListener) {
	p, err := New(cfg)
	require.NoError(t, err)

	fc := newTestClock()
	p.clock = fc
	l := newEventListener()
	p.AddListener(l)
	require.NoError(t, p.Start(context.Background()))
	t.Cleanup(func() { _ = p.Stop(context.Background()) })

	for range cfg.Sources {
		l.next(t)
	}

	return p, fc, l
}

// sign produces a compact JWS with the given kid and algorithm.
func sign(t *testing.T, raw any, alg jwa.SignatureAlgorithm, kid string) []byte {
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.KeyIDKey, kid))
	compact, err := jws.Sign([]byte("payload"), jws.WithKey(alg, raw, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return compact
}

// unverifiedSignature parses a compact JWS with the given protected header,
// without verifying it, so that FetchKeys can be handed odd headers.
func unverifiedSignature(t *testing.T, protected string) *jws.Signature {
	enc := base64.RawURLEncoding
	compact := enc.EncodeToString([]byte(protected)) + "." + enc.EncodeToString([]byte("payload")) + "." + enc.EncodeToString([]byte("sig"))
	msg, err := jws.ParseString(compact)
	require.NoError(t, err)
	return msg.Signatures()[0]
}

// recordingSink remembers what FetchKeys offered.
type recordingSink struct {
	alg jwa.SignatureAlgorithm
	key any
}

func (rs *recordingSink) Key(alg jwa.SignatureAlgorithm, key any) { rs.alg, rs.key = alg, key }

func TestProviderStartRefreshesEverySource(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	one := newKeyServer(t, publicJWK(t, rsaKey, "a", nil))
	two := newKeyServer(t, publicJWK(t, ecKey, "b", nil))

	p, _, _ := testProvider(t, Config{Sources: []RefreshSource{{URI: one.URL}, {URI: two.URL}}})
	assert.Equal(t, []string{"a", "b"}, p.KeyIDs())

	status := p.Status()
	require.Len(t, status, 2)
	for _, s := range status {
		assert.False(t, s.LastRetrieved.IsZero())
		assert.Equal(t, http.StatusOK, s.LastStatusCode)
		assert.NoError(t, s.LastErr)
	}
}

func TestProviderStatusBeforeStart(t *testing.T) {
	p, err := New(Config{Sources: []RefreshSource{{URI: "https://keys.example.com/jwks"}}})
	require.NoError(t, err)

	status := p.Status()
	require.Len(t, status, 1)
	assert.Equal(t, "https://keys.example.com/jwks", status[0].URI)
	assert.True(t, status[0].LastRetrieved.IsZero())
	assert.Zero(t, status[0].LastStatusCode)
	assert.NoError(t, status[0].LastErr)
	assert.Empty(t, p.KeyIDs())
}

func TestProviderStartTwice(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "a", nil))
	p, _, _ := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	assert.ErrorIs(t, p.Start(context.Background()), ErrAlreadyStarted)
}

func TestProviderStopWhenNotStarted(t *testing.T) {
	p, err := New(Config{Sources: []RefreshSource{{URI: "https://keys.example.com/jwks"}}})
	require.NoError(t, err)
	assert.ErrorIs(t, p.Stop(context.Background()), ErrNotStarted)
}

func TestProviderStopThenStartAgain(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "a", nil))
	p, _, l := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	require.NoError(t, p.Stop(context.Background()))
	assert.ErrorIs(t, p.Stop(context.Background()), ErrNotStarted)
	require.NoError(t, p.Start(context.Background()))
	l.next(t)
	assert.Equal(t, int32(2), server.requests.Load())
}

func TestProviderStopHonorsTheContext(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "a", nil))
	p, _, _ := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := p.Stop(ctx)
	assert.True(t, err == nil || errors.Is(err, context.Canceled))
}

func TestProviderRefreshEventDescribesTheFirstLoad(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "b", nil), publicJWK(t, ecKey, "a", nil))

	p, err := New(Config{Sources: []RefreshSource{{URI: server.URL}}})
	require.NoError(t, err)
	l := newEventListener()
	p.AddListener(l)
	require.NoError(t, p.Start(context.Background()))
	defer func() { _ = p.Stop(context.Background()) }()

	e := l.next(t)
	assert.Equal(t, server.URL, e.URI)
	assert.NoError(t, e.Err)
	assert.Equal(t, []string{"a", "b"}, e.KeyIDs)
	assert.Equal(t, []string{"a", "b"}, e.NewKeyIDs)
	assert.Empty(t, e.DeletedKeyIDs)
}

func TestProviderRefreshesOnTheTimer(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "a", nil))
	p, fc, l := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	server.serve(t, publicJWK(t, ecKey, "b", nil))
	fc.advanceToTimer(t)

	e := l.next(t)
	assert.NoError(t, e.Err)
	assert.Equal(t, []string{"b"}, e.KeyIDs)
	assert.Equal(t, []string{"b"}, e.NewKeyIDs)
	assert.Equal(t, []string{"a"}, e.DeletedKeyIDs)
	assert.Equal(t, []string{"b"}, p.KeyIDs())
	assert.Equal(t, int32(2), server.requests.Load())
}

func TestProviderRefreshFailureKeepsTheLastGoodKeys(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "a", nil))
	p, fc, l := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})
	retrieved := p.Status()[0].LastRetrieved

	server.fail(http.StatusInternalServerError)
	fc.Add(time.Second)
	fc.advanceToTimer(t)

	e := l.next(t)
	var httpErr *HTTPError
	require.ErrorAs(t, e.Err, &httpErr)
	assert.Equal(t, []string{"a"}, e.KeyIDs)
	assert.Empty(t, e.NewKeyIDs)
	assert.Empty(t, e.DeletedKeyIDs)
	assert.Equal(t, []string{"a"}, p.KeyIDs())

	status := p.Status()[0]
	assert.Equal(t, retrieved, status.LastRetrieved)
	assert.Equal(t, http.StatusInternalServerError, status.LastStatusCode)
	assert.ErrorAs(t, status.LastErr, &httpErr)
}

func TestProviderRefreshRejectsABadSetAndKeepsTheLastGoodKeys(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "a", nil))
	p, fc, l := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	noKid, err := jwk.Import[jwk.Key](&rsaKey.PublicKey)
	require.NoError(t, err)
	server.serve(t, noKid)
	fc.advanceToTimer(t)

	e := l.next(t)
	assert.ErrorIs(t, e.Err, ErrMissingKeyID)
	assert.Equal(t, []string{"a"}, e.KeyIDs)
	assert.Equal(t, []string{"a"}, p.KeyIDs())
	assert.ErrorIs(t, p.Status()[0].LastErr, ErrMissingKeyID)
}

func TestProviderRefreshNotModified(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	var since string
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		since = r.Header.Get("If-Modified-Since")
		if since != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		_, _ = w.Write(jwkSetJSON(t, publicJWK(t, rsaKey, "a", nil)))
	}))
	defer server.Close()

	p, fc, l := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})
	first := p.Status()[0].LastRetrieved

	fc.Add(time.Second)
	fc.advanceToTimer(t)
	e := l.next(t)
	assert.NoError(t, e.Err)
	assert.Equal(t, []string{"a"}, e.KeyIDs)
	assert.Empty(t, e.NewKeyIDs)
	assert.Empty(t, e.DeletedKeyIDs)
	assert.Equal(t, "Wed, 21 Oct 2015 07:28:00 GMT", since)
	assert.Equal(t, 2, requests)

	status := p.Status()[0]
	assert.Equal(t, http.StatusNotModified, status.LastStatusCode)
	assert.True(t, status.LastRetrieved.After(first), "a 304 is a successful refresh")
	assert.NoError(t, status.LastErr)
}

func TestProviderRejectsAKeyIDAnotherSourceSupplies(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	first := newKeyServer(t, publicJWK(t, rsaKey, "shared", nil))
	second := newKeyServer(t, publicJWK(t, ecKey, "shared", nil), publicJWK(t, ecKey, "only-second", nil))
	second.gate = make(chan struct{})

	p, err := New(Config{Sources: []RefreshSource{{URI: first.URL}, {URI: second.URL}}})
	require.NoError(t, err)
	l := newEventListener()
	p.AddListener(l)
	require.NoError(t, p.Start(context.Background()))
	defer func() { _ = p.Stop(context.Background()) }()

	e := l.next(t)
	require.Equal(t, first.URL, e.URI)
	second.openGate()

	e = l.next(t)
	assert.Equal(t, second.URL, e.URI)
	assert.ErrorIs(t, e.Err, ErrDuplicateKeyID)
	assert.Empty(t, e.KeyIDs)
	assert.Equal(t, []string{"shared"}, p.KeyIDs())

	k, ok := p.ring.get("shared")
	require.True(t, ok)
	assert.Equal(t, jwa.RSA(), k.KeyType(), "the first source's key must be the one kept")
}

func TestProviderFileSource(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	path := filepath.Join(t.TempDir(), "keys.json")
	require.NoError(t, os.WriteFile(path, jwkSetJSON(t, publicJWK(t, rsaKey, "a", nil)), 0o600))

	p, fc, l := testProvider(t, Config{Sources: []RefreshSource{{URI: path}}})
	assert.Equal(t, []string{"a"}, p.KeyIDs())
	status := p.Status()[0]
	assert.Zero(t, status.LastStatusCode)
	assert.False(t, status.LastRetrieved.IsZero())

	require.NoError(t, os.WriteFile(path, jwkSetJSON(t, publicJWK(t, ecKey, "b", nil)), 0o600))
	fc.advanceToTimer(t)
	e := l.next(t)
	assert.NoError(t, e.Err)
	assert.Equal(t, []string{"b"}, p.KeyIDs())
}

func TestProviderRedactsCredentialsInEventsAndStatus(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "a", nil))
	uri := "http://user:hunter2@" + server.Listener.Addr().String() + "/"

	p, err := New(Config{Sources: []RefreshSource{{URI: uri}}})
	require.NoError(t, err)
	l := newEventListener()
	p.AddListener(l)
	require.NoError(t, p.Start(context.Background()))
	defer func() { _ = p.Stop(context.Background()) }()

	e := l.next(t)
	assert.NotContains(t, e.URI, "hunter2")
	assert.Contains(t, e.URI, "user:xxxxx@")
	assert.NotContains(t, p.Status()[0].URI, "hunter2")
}

func TestProviderCancelListener(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "a", nil))

	p, err := New(Config{Sources: []RefreshSource{{URI: server.URL}}})
	require.NoError(t, err)
	fc := newTestClock()
	p.clock = fc
	l := newEventListener()
	cancel := p.AddListener(l)
	require.NoError(t, p.Start(context.Background()))
	defer func() { _ = p.Stop(context.Background()) }()

	l.next(t)
	cancel()
	cancel()
	fc.advanceToTimer(t)
	l.none(t)
}

func TestProviderVerifiesAToken(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newKeyServer(t,
		publicJWK(t, rsaKey, "rsa", nil),
		publicJWK(t, ecKey, "ec", map[string]any{"use": "sig", "alg": "ES256"}),
	)
	p, _, _ := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	payload, err := jws.Verify(sign(t, rsaKey, jwa.RS256(), "rsa"), jws.WithKeyProvider(p))
	require.NoError(t, err)
	assert.Equal(t, "payload", string(payload))

	payload, err = jws.Verify(sign(t, ecKey, jwa.ES256(), "ec"), jws.WithKeyProvider(p))
	require.NoError(t, err)
	assert.Equal(t, "payload", string(payload))
}

func TestProviderRejectsATokenSignedByAnUnknownKey(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", nil))
	p, _, _ := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	_, err := jws.Verify(sign(t, ecKey, jwa.ES256(), "ec"), jws.WithKeyProvider(p))
	assert.ErrorIs(t, err, ErrKeyNotFound)
	assert.Equal(t, int32(1), server.requests.Load(), "an unknown key ID must not cause a request")
}

func TestProviderRejectsATokenWithTheWrongKey(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", nil))
	p, _, _ := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	_, err := jws.Verify(sign(t, ecKey, jwa.ES256(), "rsa"), jws.WithKeyProvider(p))
	assert.Error(t, err)
}

func TestProviderFetchKeysMissingKeyID(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", nil))
	p, _, _ := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	var sink recordingSink
	err := p.FetchKeys(context.Background(), &sink, unverifiedSignature(t, `{"alg":"RS256"}`), nil)
	assert.ErrorIs(t, err, ErrMissingKeyID)
	assert.Nil(t, sink.key)
}

func TestProviderFetchKeysMissingAlgorithm(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", nil))
	p, _, _ := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	var sink recordingSink
	err := p.FetchKeys(context.Background(), &sink, unverifiedSignature(t, `{"kid":"rsa"}`), nil)
	assert.ErrorIs(t, err, ErrMissingAlgorithm)
	assert.Nil(t, sink.key)
}

func TestProviderFetchKeysOffersTheKeyUnderTheHeaderAlgorithm(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", nil))
	p, _, _ := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	var sink recordingSink
	err := p.FetchKeys(context.Background(), &sink, unverifiedSignature(t, `{"kid":"rsa","alg":"PS256"}`), nil)
	require.NoError(t, err)
	assert.Equal(t, jwa.PS256(), sink.alg)
	key, ok := sink.key.(jwk.Key)
	require.True(t, ok)
	kid, _ := key.KeyID()
	assert.Equal(t, "rsa", kid)
}

func TestProviderRejectsAKeyNotMarkedForSignatures(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "enc", map[string]any{"use": "enc"}))
	p, _, _ := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	_, err := jws.Verify(sign(t, rsaKey, jwa.RS256(), "enc"), jws.WithKeyProvider(p))
	assert.ErrorIs(t, err, ErrKeyUsage)
}

func TestProviderIgnoreKeyUsage(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "enc", map[string]any{"use": "enc"}))
	p, _, _ := testProvider(t, Config{
		Sources: []RefreshSource{{URI: server.URL}},
		Verify:  VerifyConfig{IgnoreKeyUsage: true},
	})

	_, err := jws.Verify(sign(t, rsaKey, jwa.RS256(), "enc"), jws.WithKeyProvider(p))
	assert.NoError(t, err)
}

func TestProviderRejectsAnAlgorithmTheKeyDoesNotAllow(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", map[string]any{"alg": "RS256"}))
	p, _, _ := testProvider(t, Config{Sources: []RefreshSource{{URI: server.URL}}})

	_, err := jws.Verify(sign(t, rsaKey, jwa.PS256(), "rsa"), jws.WithKeyProvider(p))
	assert.ErrorIs(t, err, ErrKeyAlgorithm)

	_, err = jws.Verify(sign(t, rsaKey, jwa.RS256(), "rsa"), jws.WithKeyProvider(p))
	assert.NoError(t, err)
}

func TestProviderIgnoreKeyAlgorithm(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", map[string]any{"alg": "RS256"}))
	p, _, _ := testProvider(t, Config{
		Sources: []RefreshSource{{URI: server.URL}},
		Verify:  VerifyConfig{IgnoreKeyAlgorithm: true},
	})

	_, err := jws.Verify(sign(t, rsaKey, jwa.PS256(), "rsa"), jws.WithKeyProvider(p))
	assert.NoError(t, err)
}

func TestProviderRefreshOnUnknownKeyID(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", nil))
	p, fc, l := testProvider(t, Config{
		Sources: []RefreshSource{{URI: server.URL, RefreshInterval: time.Hour, MinRefreshInterval: 10 * time.Minute}},
		Verify:  VerifyConfig{RefreshOnUnknownKeyID: true},
	})

	// the key rotates, and a token signed with it arrives after the minimum
	// interval has passed
	server.serve(t, publicJWK(t, rsaKey, "rsa", nil), publicJWK(t, ecKey, "ec", nil))
	fc.Add(10 * time.Minute)

	payload, err := jws.Verify(sign(t, ecKey, jwa.ES256(), "ec"), jws.WithKeyProvider(p))
	require.NoError(t, err)
	assert.Equal(t, "payload", string(payload))
	assert.Equal(t, int32(2), server.requests.Load())

	e := l.next(t)
	assert.Equal(t, []string{"ec"}, e.NewKeyIDs)
}

func TestProviderRefreshOnUnknownKeyIDIsRateLimited(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", nil))
	p, fc, _ := testProvider(t, Config{
		Sources: []RefreshSource{{URI: server.URL, RefreshInterval: time.Hour, MinRefreshInterval: 10 * time.Minute}},
		Verify:  VerifyConfig{RefreshOnUnknownKeyID: true},
	})

	// inside the minimum interval, an unknown key ID fails without a request
	server.serve(t, publicJWK(t, rsaKey, "rsa", nil), publicJWK(t, ecKey, "ec", nil))
	fc.Add(9 * time.Minute)
	_, err := jws.Verify(sign(t, ecKey, jwa.ES256(), "ec"), jws.WithKeyProvider(p))
	assert.ErrorIs(t, err, ErrKeyNotFound)
	assert.Equal(t, int32(1), server.requests.Load())

	// once the interval has passed, the same token verifies
	fc.Add(time.Minute)
	_, err = jws.Verify(sign(t, ecKey, jwa.ES256(), "ec"), jws.WithKeyProvider(p))
	assert.NoError(t, err)
	assert.Equal(t, int32(2), server.requests.Load())
}

func TestProviderRefreshOnUnknownKeyIDStillMisses(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", nil))
	p, fc, _ := testProvider(t, Config{
		Sources: []RefreshSource{{URI: server.URL, RefreshInterval: time.Hour, MinRefreshInterval: 10 * time.Minute}},
		Verify:  VerifyConfig{RefreshOnUnknownKeyID: true},
	})

	fc.Add(10 * time.Minute)
	_, err := jws.Verify(sign(t, ecKey, jwa.ES256(), "ec"), jws.WithKeyProvider(p))
	assert.ErrorIs(t, err, ErrKeyNotFound)
	assert.Equal(t, int32(2), server.requests.Load(), "the refresh happened, and the key still was not there")
}

func TestProviderRefreshOnUnknownKeyIDWhenNotRunning(t *testing.T) {
	p, err := New(Config{
		Sources: []RefreshSource{{URI: "https://keys.example.com/jwks"}},
		Verify:  VerifyConfig{RefreshOnUnknownKeyID: true},
	})
	require.NoError(t, err)

	var sink recordingSink
	err = p.FetchKeys(context.Background(), &sink, unverifiedSignature(t, `{"kid":"x","alg":"RS256"}`), nil)
	assert.ErrorIs(t, err, ErrKeyNotFound)
}

func TestProviderRefreshOnUnknownKeyIDHonorsTheCallersContext(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", nil))
	p, fc, _ := testProvider(t, Config{
		Sources: []RefreshSource{{URI: server.URL, RefreshInterval: time.Hour, MinRefreshInterval: 10 * time.Minute}},
		Verify:  VerifyConfig{RefreshOnUnknownKeyID: true},
	})

	server.gate = make(chan struct{})
	fc.Add(10 * time.Minute)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// the first lookup triggers a refresh that blocks on the gated server, and
	// gives up when its context expires
	var sink recordingSink
	err := p.FetchKeys(ctx, &sink, unverifiedSignature(t, `{"kid":"ec","alg":"ES256"}`), nil)
	assert.ErrorIs(t, err, ErrKeyNotFound)

	// the loop is still busy, so a second lookup cannot even hand its request
	// over before its context expires
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	err = p.FetchKeys(ctx2, &sink, unverifiedSignature(t, `{"kid":"ec","alg":"ES256"}`), nil)
	assert.ErrorIs(t, err, ErrKeyNotFound)
	server.openGate()
	_ = ecKey
}

func TestProviderRefreshOnUnknownKeyIDWhenStoppedMidLookup(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newKeyServer(t, publicJWK(t, rsaKey, "rsa", nil))
	p, fc, _ := testProvider(t, Config{
		Sources: []RefreshSource{{URI: server.URL, RefreshInterval: time.Hour, MinRefreshInterval: 10 * time.Minute}},
		Verify:  VerifyConfig{RefreshOnUnknownKeyID: true},
	})

	server.gate = make(chan struct{})
	fc.Add(10 * time.Minute)

	// one lookup is waiting on the gated refresh; a second cannot hand over its
	// request while the loop is busy.  Stopping releases both.
	results := make(chan error, 2)
	for range 2 {
		go func() {
			var sink recordingSink
			results <- p.FetchKeys(context.Background(), &sink, unverifiedSignature(t, `{"kid":"ec","alg":"ES256"}`), nil)
		}()
	}

	require.Eventually(t, func() bool { return server.requests.Load() == 1 && len(results) == 0 }, time.Second, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, p.Stop(stopCtx))

	for range 2 {
		select {
		case err := <-results:
			assert.ErrorIs(t, err, ErrKeyNotFound)

		case <-time.After(5 * time.Second):
			require.Fail(t, "a lookup was not released by Stop")
		}
	}

	server.openGate()
}
