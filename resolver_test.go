// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

const (
	testKeyIDURL = "https://example.com/{keyID}"
	testKeyURL   = "https://example.com/testKey"

	// resolverTestKey is a known, good key for testing the Resolver code
	resolverTestKey = `
{
    "kid": "testKey",
    "p": "5I2R0qjqeBsdkOIOiIKwzJUhcqJrH2Q_V0EuNCCjrKBl6TNuX6t8ToLV2o57yu1nT4B4R2UVQOsRfi3y7ZpnvwK8b997vCC2M3jnTJ56SBYF9mO46fsRP3OeuRw8A0owTCXw8TbSYIuQw-agBME2N50u3Lgk1lTqZBCZ9U5tsHc",
    "kty": "RSA",
    "q": "qjf1QXyLlX8wxiEqyP0D1cLQCjnoKnlWQjKCFX54wexU92a6zjc6k5dAOCRNXWlttbZgGZnNBjIc0aYfYeYNfIP1BBQr094AjG7p6j6cSXKi2qwZG63PLgSsoUvp_W22jpqdnmA7oXYE-epl2gF2q1QGOrW2yMx4n2sJKI6AW7s",
    "d": "E5DzvlXUCubwPHNWo-H5L3r572hxsrGcKHSJhTrRh5IRv_h7rEMlZ-umMIpem_7yn3yjpMlxkcf2E20usXGsM0lRRo5iqM--tFlDesY-PcJA4QWiVkCm0HQlhKq8LFFJ3BD-FPlbqLU5a9vQppmJ26aW4UYCXfTMzx7p31SxDv84IZkiWlnuuJzl2TkfPxMxf8g7zFd2Ea3kPjBX8ZH_lLt4fNCGL1BGc7_cRKopnmL3r_o8sPI5NU4dC2WKkeXsnOdAMhbyxttP3i5a1S9rpdOs_H6xO2M-F0pEklQ35MZSSlBjnl9MDvEF6pyrqOwnRRJU2Uf-orgWx-3ArjyuqQ",
    "e": "AQAB",
    "qi": "vRxU0W7YQz3EIaFE3-2RJv5tjXz_6nrBagHtqF30MrfgkdDmlXAqwQVm3-5KZwa7vt2AAaafx2F_lxlpUoIHaOj04sr80HLm7DvrW6t5JZLXWXE-7BurTywO4EKugcjawh387jEQzo9cPwkEj-Sm-IwkpFMzE93lQw5slf4zKRI",
    "dp": "ugnKozE_-hgITwDTV6caBs11dnxiuiC9tmamF2RiFohRrCtjMpjCDJ5POSI1_g6Uw5ANWAAd9sPhb1YzodjHjiHKBT5i19XAudE2ZZWyb68Nl2vA_ySQ-5c_oeorp3niKnnP0GkRgejZI708j-I-IbLejGeQBK8GRAGHcLgwbS0",
    "dq": "RKDREjkbsgeY65j9vhE81Zd491aHg3BuVbw1dGMMXuthCmpx0Ki1xkHKE5iXVJ0oLYY9UrUO03uq4OAAcSEmuNgfFijnzsEIKZaiWt4pdvdwL4gJi35VNLGPxGxuB86PNwmhmPQltqB1uylFLVM_vC3hYRRYgLbnvyaRh7eEivc",
    "n": "l_f4Niwf0T9Cya4tuj0yGnXhIGnbFOmyRgsactAWZuXEO8ZYXp8l5TZe5-2HM5ARbYBOrornCbG4n82UjvfbvmR_57fzmOuogV1Btx4Q_WfmXzgbi1iuyS0kvBvv88mTyrCjSH46rXG22vacQhV-bZkLtOhiqUQakxMkxzj9BHGp-ubjOW7N6FOC8nIRARWN3S8QJLEMX28RDOsHHa7xdD9-29hTcLbv0NuE-ISKG6DW8hhLAWZBwpF4WKukfpeH8difnq31vvGwmW2cqss7WTBVxP6sOQ_NHUnU_og_PyjIcl0bO6QTysPSb5eQ5fv0ovtDWSGzuMzSF3ljhVoz7Q"
}`

	// resolverTestKeySet is JWK set that contains the resolveTestKey and
	// a couple of other keys.
	resolverTestKeySet = `
{
    "keys": [
        {
            "kty": "oct",
            "k": "1bzFnOuMfzKvFYUpggi5U6YfOfI9opANo0NBhgxoyCV_LNMaxhhZeseOV0AxM4lS3zlYpe6GCwA6dsknsJk6ANtWnwoCbRiKN3icLfJ238fEsdHjZSmP16twfnRo3G25Xg8JelJLXnbY1sGdb8a3J8GreGA8n6KxVlZ6NPjE9X0"
        },
        {
		    "kid": "testKey",
            "p": "5I2R0qjqeBsdkOIOiIKwzJUhcqJrH2Q_V0EuNCCjrKBl6TNuX6t8ToLV2o57yu1nT4B4R2UVQOsRfi3y7ZpnvwK8b997vCC2M3jnTJ56SBYF9mO46fsRP3OeuRw8A0owTCXw8TbSYIuQw-agBME2N50u3Lgk1lTqZBCZ9U5tsHc",
            "kty": "RSA",
            "q": "qjf1QXyLlX8wxiEqyP0D1cLQCjnoKnlWQjKCFX54wexU92a6zjc6k5dAOCRNXWlttbZgGZnNBjIc0aYfYeYNfIP1BBQr094AjG7p6j6cSXKi2qwZG63PLgSsoUvp_W22jpqdnmA7oXYE-epl2gF2q1QGOrW2yMx4n2sJKI6AW7s",
            "d": "E5DzvlXUCubwPHNWo-H5L3r572hxsrGcKHSJhTrRh5IRv_h7rEMlZ-umMIpem_7yn3yjpMlxkcf2E20usXGsM0lRRo5iqM--tFlDesY-PcJA4QWiVkCm0HQlhKq8LFFJ3BD-FPlbqLU5a9vQppmJ26aW4UYCXfTMzx7p31SxDv84IZkiWlnuuJzl2TkfPxMxf8g7zFd2Ea3kPjBX8ZH_lLt4fNCGL1BGc7_cRKopnmL3r_o8sPI5NU4dC2WKkeXsnOdAMhbyxttP3i5a1S9rpdOs_H6xO2M-F0pEklQ35MZSSlBjnl9MDvEF6pyrqOwnRRJU2Uf-orgWx-3ArjyuqQ",
            "e": "AQAB",
            "qi": "vRxU0W7YQz3EIaFE3-2RJv5tjXz_6nrBagHtqF30MrfgkdDmlXAqwQVm3-5KZwa7vt2AAaafx2F_lxlpUoIHaOj04sr80HLm7DvrW6t5JZLXWXE-7BurTywO4EKugcjawh387jEQzo9cPwkEj-Sm-IwkpFMzE93lQw5slf4zKRI",
            "dp": "ugnKozE_-hgITwDTV6caBs11dnxiuiC9tmamF2RiFohRrCtjMpjCDJ5POSI1_g6Uw5ANWAAd9sPhb1YzodjHjiHKBT5i19XAudE2ZZWyb68Nl2vA_ySQ-5c_oeorp3niKnnP0GkRgejZI708j-I-IbLejGeQBK8GRAGHcLgwbS0",
            "dq": "RKDREjkbsgeY65j9vhE81Zd491aHg3BuVbw1dGMMXuthCmpx0Ki1xkHKE5iXVJ0oLYY9UrUO03uq4OAAcSEmuNgfFijnzsEIKZaiWt4pdvdwL4gJi35VNLGPxGxuB86PNwmhmPQltqB1uylFLVM_vC3hYRRYgLbnvyaRh7eEivc",
            "n": "l_f4Niwf0T9Cya4tuj0yGnXhIGnbFOmyRgsactAWZuXEO8ZYXp8l5TZe5-2HM5ARbYBOrornCbG4n82UjvfbvmR_57fzmOuogV1Btx4Q_WfmXzgbi1iuyS0kvBvv88mTyrCjSH46rXG22vacQhV-bZkLtOhiqUQakxMkxzj9BHGp-ubjOW7N6FOC8nIRARWN3S8QJLEMX28RDOsHHa7xdD9-29hTcLbv0NuE-ISKG6DW8hhLAWZBwpF4WKukfpeH8difnq31vvGwmW2cqss7WTBVxP6sOQ_NHUnU_og_PyjIcl0bO6QTysPSb5eQ5fv0ovtDWSGzuMzSF3ljhVoz7Q"
        },
        {
		    "kid": "anotherKey",
            "kty": "OKP",
            "d": "AmXEBENjL8hKtEqC2WPS00hgdDaNEzKRkZX1vhZaaII",
            "crv": "Ed25519",
            "x": "RMK6ix73LXxbfjIxcxPTcsl9--B3osUQfk600q2HXs8"
        }]
}`
)

type ResolverSuite struct {
	suite.Suite

	testKey    Key
	testKeySet []Key
}

func (suite *ResolverSuite) SetupTest() {
	p, err := NewParser()
	suite.Require().NoError(err)
	suite.Require().NotNil(p)

	keys, err := p.Parse(MediaTypeJWK, []byte(resolverTestKey))
	suite.Require().NoError(err)
	suite.Len(keys, 1)
	suite.testKey = keys[0]

	keys, err = p.Parse(MediaTypeJWKSet, []byte(resolverTestKeySet))
	suite.Require().NoError(err)
	suite.Require().Len(keys, 3)
	suite.testKeySet = keys
}

func (suite *ResolverSuite) newResolver(options ...ResolverOption) Resolver {
	r, err := NewResolver(options...)
	suite.Require().NoError(err)
	suite.Require().NotNil(r)
	return r
}

func (suite *ResolverSuite) TestNoKeyIDTemplate() {
	r, err := NewResolver()
	suite.Require().Error(err)
	suite.ErrorIs(err, ErrNoTemplate)

	// suite.Nil would accept a nil *resolver inside a non-nil Resolver, which is
	// exactly what a caller's "if r != nil" guard does not accept.
	suite.True(r == nil, "a failed constructor must return a nil interface, got %#v", r)
}

// TestOptionError checks that a failing option yields a nil Resolver even when
// a template was supplied, i.e. a caller never gets a Resolver alongside an error.
func (suite *ResolverSuite) TestOptionError() {
	expectedErr := errors.New("expected option failure")
	failingOption := resolverOptionFunc(func(*resolver) error {
		return expectedErr
	})

	r, err := NewResolver(
		WithKeyIDTemplate(testKeyIDURL),
		failingOption,
	)

	suite.Require().Error(err)
	suite.ErrorIs(err, expectedErr)
	suite.NotErrorIs(err, ErrNoTemplate)
	suite.True(r == nil, "a failed constructor must return a nil interface, got %#v", r)
}

func (suite *ResolverSuite) TestDefault() {
	r := suite.newResolver(
		WithKeyIDTemplate(testKeyIDURL),
	)

	suite.Require().IsType((*resolver)(nil), r)
	suite.NotNil(r.(*resolver).fetcher)
}

func (suite *ResolverSuite) TestSingleKey() {
	var (
		f = new(mockFetcher)
		r = suite.newResolver(
			WithFetcher(f),
			WithKeyIDTemplate(testKeyIDURL),
		)
	)

	f.ExpectFetch(context.Background(), testKeyURL).
		Return([]Key{suite.testKey}, ContentMeta{}, nil).
		Twice()

	key, err := r.Resolve(context.Background(), "testKey")
	suite.Require().NoError(err)
	suite.Require().NotNil(key)
	suite.Equal(suite.testKey, key)

	// Because there is no key ring, this should fetch again
	key, err = r.Resolve(context.Background(), "testKey")
	suite.Require().NoError(err)
	suite.Require().NotNil(key)
	suite.Equal(suite.testKey, key)

	f.AssertExpectations(suite.T())
}

func (suite *ResolverSuite) TestMultipleKeys() {
	var (
		f = new(mockFetcher)
		r = suite.newResolver(
			WithFetcher(f),
			WithKeyIDTemplate(testKeyIDURL),
		)
	)

	f.ExpectFetch(context.Background(), testKeyURL).
		Return(suite.testKeySet, ContentMeta{}, nil).
		Twice()

	key, err := r.Resolve(context.Background(), "testKey")
	suite.Require().NoError(err)
	suite.Require().NotNil(key)
	suite.Equal(suite.testKey, key)

	// Because there is no key ring, this should fetch again
	key, err = r.Resolve(context.Background(), "testKey")
	suite.Require().NoError(err)
	suite.Require().NotNil(key)
	suite.Equal(suite.testKey, key)

	f.AssertExpectations(suite.T())
}

func (suite *ResolverSuite) TestWithKeyRing() {
	var (
		keyRing  = NewKeyRing()
		listener = new(mockResolveListener)

		f = new(mockFetcher)
		r = suite.newResolver(
			WithKeyRing(keyRing),
			WithFetcher(f),
			WithKeyIDTemplate(testKeyIDURL),
		)
	)

	f.ExpectFetch(context.Background(), testKeyURL).
		Return(suite.testKeySet, ContentMeta{}, nil).
		Twice()

	listener.ExpectOnResolveEvent(ResolveEvent{
		URI:   testKeyURL,
		KeyID: "testKey",
		Key:   suite.testKey,
		Err:   nil,
	}).Once()

	cancel := r.AddListener(listener)

	key, err := r.Resolve(context.Background(), "testKey")
	suite.Require().NoError(err)
	suite.Require().NotNil(key)
	suite.Equal(suite.testKey, key)

	// There is a key ring, so the key should be cached
	key, ok := keyRing.Get("testKey")
	suite.True(ok)
	suite.Equal(suite.testKey, key)

	key, err = r.Resolve(context.Background(), "testKey")
	suite.Require().NoError(err)
	suite.Require().NotNil(key)
	suite.Equal(suite.testKey, key)

	// Delete the cached key, and cancel the listener.
	suite.Equal(1, keyRing.Remove("testKey"))
	cancel()

	key, err = r.Resolve(context.Background(), "testKey")
	suite.Require().NoError(err)
	suite.Require().NotNil(key)
	suite.Equal(suite.testKey, key)

	key, ok = keyRing.Get("testKey")
	suite.True(ok)
	suite.Equal(suite.testKey, key)

	f.AssertExpectations(suite.T())
}

func (suite *ResolverSuite) TestNoKey() {
	var (
		f = new(mockFetcher)
		r = suite.newResolver(
			WithFetcher(f),
			WithKeyIDTemplate(testKeyIDURL),
		)
	)

	f.ExpectFetch(context.Background(), testKeyURL).
		Return([]Key{}, ContentMeta{}, nil).
		Twice()

	key, err := r.Resolve(context.Background(), "testKey")
	suite.Nil(key)
	suite.ErrorIs(err, ErrKeyNotFound)

	// Because there is no key ring, this should fetch again
	key, err = r.Resolve(context.Background(), "testKey")
	suite.Nil(key)
	suite.ErrorIs(err, ErrKeyNotFound)

	f.AssertExpectations(suite.T())
}

func (suite *ResolverSuite) TestMissingKey() {
	var (
		f = new(mockFetcher)
		r = suite.newResolver(
			WithFetcher(f),
			WithKeyIDTemplate(testKeyIDURL),
		)
	)

	f.ExpectFetch(context.Background(), "https://example.com/nosuchKey").
		Return(suite.testKeySet, ContentMeta{}, nil).
		Once()

	key, err := r.Resolve(context.Background(), "nosuchKey")
	suite.Nil(key)
	suite.ErrorIs(err, ErrKeyNotFound)

	f.AssertExpectations(suite.T())
}

func (suite *ResolverSuite) TestFetcherError() {
	var (
		expectedError = errors.New("expected")

		f = new(mockFetcher)
		r = suite.newResolver(
			WithFetcher(f),
			WithKeyIDTemplate(testKeyIDURL),
		)
	)

	f.ExpectFetch(context.Background(), testKeyURL).
		Return([]Key{}, ContentMeta{}, expectedError).
		Once()

	key, err := r.Resolve(context.Background(), "testKey")
	suite.Nil(key)
	suite.ErrorIs(err, expectedError)

	f.AssertExpectations(suite.T())
}

func (suite *ResolverSuite) TestConcurrentFetch() {
	type result struct {
		key Key
		err error
	}

	var (
		keyRing  = NewKeyRing()
		listener = new(mockResolveListener)

		f = new(mockFetcher)
		r = suite.newResolver(
			WithKeyRing(keyRing),
			WithFetcher(f),
			WithKeyIDTemplate(testKeyIDURL),
		)

		fetchReady = new(sync.WaitGroup)
		results    = make(chan result, 3)
	)

	f.ExpectFetch(context.Background(), testKeyURL).
		Return([]Key{suite.testKey}, ContentMeta{}, nil).
		Once()

	listener.ExpectOnResolveEvent(ResolveEvent{
		URI:   testKeyURL,
		KeyID: "testKey",
		Key:   suite.testKey,
		Err:   nil,
	}).Once()

	r.AddListener(listener)

	// spawn several requests, only one of which should actually call the Fetcher
	for range 3 {
		fetchReady.Add(1)
		go func() {
			fetchReady.Done()
			key, err := r.Resolve(context.Background(), "testKey")
			results <- result{key: key, err: err}
		}()
	}

	fetchReady.Wait() // make sure all goroutines have started
	timeout := time.After(15 * time.Second)
	for range 3 {
		select {
		case <-timeout:
			suite.Fail("Not all resolve calls finished")

		case result := <-results:
			suite.NoError(result.err)
			suite.Equal(suite.testKey, result.key)
		}
	}

	key, ok := keyRing.Get("testKey")
	suite.True(ok)
	suite.Equal(suite.testKey, key)

	f.AssertExpectations(suite.T())
}

// TestPlainContext is the documented use of a Resolver: default options, an HTTP
// key template, and whatever context the caller has on hand.  Nothing in the
// Resolver API asks the caller to seed a ContentMeta, so this must work without one.
func (suite *ResolverSuite) TestPlainContext() {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		suite.Equal("/keys/testKey", req.URL.Path)
		rw.Header().Set("Content-Type", MediaTypeJWK)
		_, _ = rw.Write([]byte(resolverTestKey))
	}))
	defer server.Close()

	r := suite.newResolver(
		WithKeyIDTemplate(server.URL + "/keys/{keyID}"),
	)

	suite.Require().NotPanics(func() {
		k, err := r.Resolve(context.Background(), "testKey")
		suite.Require().NoError(err)
		suite.Require().NotNil(k)
		suite.Equal("testKey", k.KeyID())
	})
}

// resolveResult is what a Resolve call running in its own goroutine produced.
type resolveResult struct {
	key Key
	err error
}

// observedRing wraps a KeyRing and reports every Get on a channel.  A Resolve
// call consults the ring twice before it either fetches or waits: once without
// the lock and once with it, immediately before it registers with the pending
// requests.  Counting Gets therefore tells a test exactly when a goroutine has
// committed to fetching or waiting, without sleeping and without racing the
// scheduler.
type observedRing struct {
	KeyRing
	gets chan struct{}
}

func newObservedRing(keys ...Key) *observedRing {
	return &observedRing{
		KeyRing: NewKeyRing(keys...),
		gets:    make(chan struct{}, 64),
	}
}

func (or *observedRing) Get(keyID string) (Key, bool) {
	or.gets <- struct{}{}
	return or.KeyRing.Get(keyID)
}

// awaitGets blocks until the ring has been consulted n more times.
func (suite *ResolverSuite) awaitGets(ring *observedRing, n int) {
	for range n {
		select {
		case <-ring.gets:
		case <-time.After(5 * time.Second):
			suite.Require().FailNow("timed out waiting for ring lookups")
		}
	}
}

// resolveAsync runs Resolve in a goroutine and returns the channel that will
// carry its result.
func (suite *ResolverSuite) resolveAsync(ctx context.Context, r Resolver, keyID string) <-chan resolveResult {
	results := make(chan resolveResult, 1)
	go func() {
		key, err := r.Resolve(ctx, keyID)
		results <- resolveResult{key: key, err: err}
	}()

	return results
}

// await returns the result of a resolveAsync call, failing the test if it never arrives.
func (suite *ResolverSuite) await(results <-chan resolveResult) resolveResult {
	select {
	case result := <-results:
		return result
	case <-time.After(5 * time.Second):
		suite.Require().FailNow("Resolve did not return")
		return resolveResult{}
	}
}

// waiterFixture sets up a Resolver whose single fetch blocks until the test
// releases it.  The first Resolve call becomes the fetcher; any subsequent call
// for the same kid must wait in waitForKey.
type waiterFixture struct {
	ring    *observedRing
	fetcher *mockFetcher
	r       Resolver
	started chan struct{}
	release chan struct{}
}

func (suite *ResolverSuite) newWaiterFixture() *waiterFixture {
	wf := &waiterFixture{
		ring:    newObservedRing(),
		fetcher: new(mockFetcher),
		started: make(chan struct{}),
		release: make(chan struct{}),
	}

	wf.r = suite.newResolver(
		WithKeyRing(wf.ring),
		WithFetcher(wf.fetcher),
		WithKeyIDTemplate(testKeyIDURL),
	)

	return wf
}

// expectBlockingFetch arranges for exactly one Fetch that signals started and
// then blocks until release is closed, returning the given values.
func (wf *waiterFixture) expectBlockingFetch(keys []Key, err error) {
	wf.fetcher.ExpectFetchCtx(func(context.Context) bool { return true }, testKeyURL).
		Run(func(mock.Arguments) {
			close(wf.started)
			<-wf.release
		}).
		Return(keys, ContentMeta{}, err).
		Once()
}

// startFetcher starts the Resolve call that will perform the fetch and blocks
// until it is inside the Fetcher.
func (suite *ResolverSuite) startFetcher(ctx context.Context, wf *waiterFixture) <-chan resolveResult {
	results := suite.resolveAsync(ctx, wf.r, "testKey")
	select {
	case <-wf.started:
	case <-time.After(5 * time.Second):
		suite.Require().FailNow("fetch never started")
	}

	// the fetcher consulted the ring twice on its way in
	suite.awaitGets(wf.ring, 2)
	return results
}

// startWaiter starts a Resolve call that must wait on the in-flight fetch, and
// blocks until it has registered as a waiter.
func (suite *ResolverSuite) startWaiter(ctx context.Context, wf *waiterFixture) <-chan resolveResult {
	results := suite.resolveAsync(ctx, wf.r, "testKey")

	// the second Get happens under the resolve lock, immediately before the
	// waiter registers.  once it has been observed, the fetcher cannot clean up
	// until the waiter has registered, because cleanup needs the same lock.
	suite.awaitGets(wf.ring, 2)
	return results
}

// TestWaitForKeyKeyDelivered is the happy path for a waiter: the fetch succeeds
// and both the fetching goroutine and the waiter receive the key.
func (suite *ResolverSuite) TestWaitForKeyKeyDelivered() {
	wf := suite.newWaiterFixture()
	wf.expectBlockingFetch([]Key{suite.testKey}, nil)

	fetcher := suite.startFetcher(context.Background(), wf)
	waiter := suite.startWaiter(context.Background(), wf)
	close(wf.release)

	for _, results := range []<-chan resolveResult{fetcher, waiter} {
		result := suite.await(results)
		suite.NoError(result.err)
		suite.Equal(suite.testKey, result.key)
	}

	wf.fetcher.AssertExpectations(suite.T())
}

// TestWaitForKeyKeyNotFound is the one case where a waiter legitimately sees
// ErrKeyNotFound: the fetch succeeded and the key simply was not there.
func (suite *ResolverSuite) TestWaitForKeyKeyNotFound() {
	wf := suite.newWaiterFixture()
	wf.expectBlockingFetch([]Key{}, nil)

	fetcher := suite.startFetcher(context.Background(), wf)
	waiter := suite.startWaiter(context.Background(), wf)
	close(wf.release)

	for _, results := range []<-chan resolveResult{fetcher, waiter} {
		result := suite.await(results)
		suite.ErrorIs(result.err, ErrKeyNotFound)
		suite.Nil(result.key)
	}

	wf.fetcher.AssertExpectations(suite.T())
}

// TestWaitForKeyFetchError covers a failed fetch.  The goroutine that fetched
// sees the cause.  A waiter must see the same cause, not a claim that the key
// does not exist.
func (suite *ResolverSuite) TestWaitForKeyFetchError() {
	expectedErr := errors.New("expected fetch failure")
	wf := suite.newWaiterFixture()
	wf.expectBlockingFetch(nil, expectedErr)

	fetcher := suite.startFetcher(context.Background(), wf)
	waiter := suite.startWaiter(context.Background(), wf)
	close(wf.release)

	result := suite.await(fetcher)
	suite.ErrorIs(result.err, expectedErr)
	suite.Nil(result.key)

	result = suite.await(waiter)
	suite.ErrorIs(result.err, expectedErr, "waiter should see the fetch error, got: %v", result.err)
	suite.NotErrorIs(result.err, ErrKeyNotFound, "the key was never looked for, so it cannot be 'not found'")
	suite.Nil(result.key)

	wf.fetcher.AssertExpectations(suite.T())
}

// TestWaitForKeyWaiterContextCanceled covers a waiter that gives up before the
// fetch completes.  It must return promptly with its own context error, and the
// fetch must be unaffected.
func (suite *ResolverSuite) TestWaitForKeyWaiterContextCanceled() {
	wf := suite.newWaiterFixture()
	wf.expectBlockingFetch([]Key{suite.testKey}, nil)

	fetcher := suite.startFetcher(context.Background(), wf)

	waiterCtx, cancel := context.WithCancel(context.Background())
	waiter := suite.startWaiter(waiterCtx, wf)
	cancel()

	// the fetch is still blocked, so this can only have come from waitForKey
	result := suite.await(waiter)
	suite.ErrorIs(result.err, context.Canceled)
	suite.Nil(result.key)

	close(wf.release)
	result = suite.await(fetcher)
	suite.NoError(result.err)
	suite.Equal(suite.testKey, result.key)

	wf.fetcher.AssertExpectations(suite.T())
}

// TestWaitForKeyFetcherContextCanceled covers the fetch being canceled.  The
// fetch runs under the first caller's context, so when that caller gives up
// the fetch is canceled for everyone.  A waiter with a perfectly good context
// of its own must at least learn that the fetch was canceled, rather than
// being told the key does not exist.
func (suite *ResolverSuite) TestWaitForKeyFetcherContextCanceled() {
	wf := suite.newWaiterFixture()
	wf.fetcher.ExpectFetchCtx(func(context.Context) bool { return true }, testKeyURL).
		Run(func(args mock.Arguments) {
			close(wf.started)
			<-args.Get(0).(context.Context).Done()
		}).
		Return([]Key(nil), ContentMeta{}, context.Canceled).
		Once()

	fetcherCtx, cancel := context.WithCancel(context.Background())
	fetcher := suite.startFetcher(fetcherCtx, wf)
	waiter := suite.startWaiter(context.Background(), wf)
	cancel()

	result := suite.await(fetcher)
	suite.ErrorIs(result.err, context.Canceled)

	result = suite.await(waiter)
	suite.ErrorIs(result.err, context.Canceled, "waiter should learn the fetch was canceled, got: %v", result.err)
	suite.NotErrorIs(result.err, ErrKeyNotFound)
	suite.Nil(result.key)

	wf.fetcher.AssertExpectations(suite.T())
}

// TestFetcherPanic checks that a panic inside the Fetcher does not strand the kid.
// The pending request must be cleaned up even when the fetch does not return
// normally; otherwise every later Resolve for that kid waits on a request that
// will never complete.
func (suite *ResolverSuite) TestFetcherPanic() {
	wf := suite.newWaiterFixture()

	// the first fetch panics; the second, if it is allowed to happen, succeeds
	wf.fetcher.ExpectFetchCtx(func(context.Context) bool { return true }, testKeyURL).
		Run(func(mock.Arguments) { panic("expected fetcher panic") }).
		Once()
	wf.fetcher.ExpectFetchCtx(func(context.Context) bool { return true }, testKeyURL).
		Return([]Key{suite.testKey}, ContentMeta{}, nil).
		Once()

	suite.Require().PanicsWithValue("expected fetcher panic", func() {
		_, _ = wf.r.Resolve(context.Background(), "testKey")
	})

	// a later caller for the same kid must get a fresh fetch, not a hung wait
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	key, err := wf.r.Resolve(ctx, "testKey")
	suite.Require().NoError(err, "Resolve after a fetcher panic should fetch again, got: %v", err)
	suite.Equal(suite.testKey, key)

	wf.fetcher.AssertExpectations(suite.T())
}

// TestRingCheckedUnderLock covers the second ring lookup: a key that arrives
// between the unlocked check and acquiring the lock must be returned without a
// fetch.
func (suite *ResolverSuite) TestRingCheckedUnderLock() {
	var (
		ring    = newObservedRing()
		fetcher = new(mockFetcher) // expects no calls
		r       = suite.newResolver(
			WithKeyRing(ring),
			WithFetcher(fetcher),
			WithKeyIDTemplate(testKeyIDURL),
		)
	)

	// hold the resolve lock so that Resolve blocks between its two ring checks
	r.(*resolver).resolveLock.Lock()
	results := suite.resolveAsync(context.Background(), r, "testKey")
	suite.awaitGets(ring, 1) // the unlocked check, a miss

	ring.Add(suite.testKey)
	r.(*resolver).resolveLock.Unlock()

	result := suite.await(results)
	suite.NoError(result.err)
	suite.Equal(suite.testKey, result.key)

	fetcher.AssertExpectations(suite.T())
}

func TestResolver(t *testing.T) {
	suite.Run(t, new(ResolverSuite))
}
