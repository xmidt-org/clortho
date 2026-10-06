// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/chronon"
)

// themisServer answers the way themis does: one key per request at
// /keys/<kid>, as a JWK with no kid in it when the Accept header is exactly
// application/json, and as PEM for anything else.  It records every request.
type themisServer struct {
	*httptest.Server

	lock       sync.Mutex
	keys       map[string][]byte
	status     int
	retryAfter string
	maxAge     string
	paths      []string
	hosts      []string
	accepts    []string

	// gate, when set before a request arrives, holds that request until it is
	// closed.  It is closed on cleanup so that a failed test cannot hang.
	gate     chan struct{}
	gateOnce sync.Once
}

func newThemisServer(t *testing.T) *themisServer {
	ts := &themisServer{keys: make(map[string][]byte)}
	ts.Server = httptest.NewServer(http.HandlerFunc(ts.serve))
	t.Cleanup(ts.Close)
	t.Cleanup(ts.openGate)
	return ts
}

func (ts *themisServer) serve(w http.ResponseWriter, r *http.Request) {
	ts.lock.Lock()
	ts.paths = append(ts.paths, r.URL.RequestURI())
	ts.hosts = append(ts.hosts, r.Host)
	ts.accepts = append(ts.accepts, r.Header.Get("Accept"))
	gate := ts.gate
	ts.lock.Unlock()

	if gate != nil {
		<-gate
	}

	ts.lock.Lock()
	body, found := ts.keys[strings.TrimPrefix(r.URL.Path, "/keys/")]
	status, retryAfter, maxAge := ts.status, ts.retryAfter, ts.maxAge
	ts.lock.Unlock()

	switch {
	case status != 0:
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}

		w.WriteHeader(status)

	case !found:
		http.NotFound(w, r)

	case r.Header.Get("Accept") != "application/json":
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte("-----BEGIN PUBLIC KEY-----\nnot what clortho asked for\n-----END PUBLIC KEY-----\n"))

	default:
		if maxAge != "" {
			w.Header().Set("Cache-Control", "max-age="+maxAge)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

func (ts *themisServer) openGate() {
	ts.gateOnce.Do(func() {
		ts.lock.Lock()
		defer ts.lock.Unlock()
		if ts.gate != nil {
			close(ts.gate)
		}
	})
}

func (ts *themisServer) closeGate() {
	ts.lock.Lock()
	ts.gate = make(chan struct{})
	ts.lock.Unlock()
}

// set changes how the server answers, under its lock.
func (ts *themisServer) set(change func(*themisServer)) {
	ts.lock.Lock()
	defer ts.lock.Unlock()
	change(ts)
}

// add serves raw key material under a key ID, as themis does: a JWK that does
// not say what its own key ID is.
func (ts *themisServer) add(t *testing.T, keyID string, raw any, members map[string]any) {
	k, err := jwk.Import[jwk.Key](raw)
	require.NoError(t, err)
	for name, value := range members {
		require.NoError(t, k.Set(name, value))
	}

	body, err := json.Marshal(k)
	require.NoError(t, err)
	ts.set(func(ts *themisServer) { ts.keys[keyID] = body })
}

func (ts *themisServer) requests() []string {
	ts.lock.Lock()
	defer ts.lock.Unlock()
	return append([]string(nil), ts.paths...)
}

func (ts *themisServer) template() string {
	return ts.URL + "/keys/{keyID}"
}

// fetchRecorder collects fetch events on a channel.
type fetchRecorder struct {
	events chan FetchEvent
}

func (r *fetchRecorder) OnFetchEvent(e FetchEvent) { r.events <- e }

func (r *fetchRecorder) next(t *testing.T) FetchEvent {
	select {
	case e := <-r.events:
		return e

	case <-time.After(5 * time.Second):
		require.FailNow(t, "no fetch event arrived")
		return FetchEvent{}
	}
}

// testPerKey builds a PerKeyProvider against a themis-like server, with a
// fake clock and an event recorder.  configure may adjust the config first.
func testPerKey(t *testing.T, server *themisServer, configure func(*PerKeyConfig)) (*PerKeyProvider, *chronon.FakeClock, *fetchRecorder) {
	cfg := PerKeyConfig{Template: server.template(), Client: testClient()}
	if configure != nil {
		configure(&cfg)
	}

	p, err := NewPerKeyProvider(cfg)
	require.NoError(t, err)

	fc := chronon.NewFakeClock(time.Now())
	p.clock = fc
	rec := &fetchRecorder{events: make(chan FetchEvent, 4096)}
	p.AddListener(rec)
	return p, fc, rec
}

// ask does one lookup for a key ID, as jwx would for an RS256 token.
func ask(t *testing.T, p *PerKeyProvider, keyID string) error {
	header, err := json.Marshal(map[string]string{"kid": keyID, "alg": "RS256"})
	require.NoError(t, err)

	var sink recordingSink
	return p.FetchKeys(context.Background(), &sink, unverifiedSignature(t, string(header)), nil)
}

func TestNewPerKeyProviderRejectsABadConfig(t *testing.T) {
	client := testClient()
	tests := []struct {
		name     string
		cfg      PerKeyConfig
		expected error
	}{
		{"no template", PerKeyConfig{Client: client}, ErrInvalidTemplate},
		{"no placeholder", PerKeyConfig{Template: "https://keys.example.com/keys/", Client: client}, ErrInvalidTemplate},
		{"one placeholder where it may be, and one where it may not", PerKeyConfig{Template: "https://keys.example.com/{keyID}#{keyID}", Client: client}, ErrInvalidTemplate},
		{"the old placeholder name", PerKeyConfig{Template: "https://keys.example.com/keys/{key_name}", Client: client}, ErrInvalidTemplate},
		{"placeholder in the server name", PerKeyConfig{Template: "https://{keyID}.example.com/keys", Client: client}, ErrInvalidTemplate},
		{"placeholder ends the server name", PerKeyConfig{Template: "https://keys.example.com{keyID}/keys", Client: client}, ErrInvalidTemplate},
		{"placeholder is the server name", PerKeyConfig{Template: "https://{keyID}/keys", Client: client}, ErrInvalidTemplate},
		{"placeholder in the user name", PerKeyConfig{Template: "https://{keyID}@keys.example.com/keys", Client: client}, ErrInvalidTemplate},
		{"placeholder in the password", PerKeyConfig{Template: "https://user:{keyID}@keys.example.com/keys", Client: client}, ErrInvalidTemplate},
		{"placeholder in the port", PerKeyConfig{Template: "https://keys.example.com:{keyID}/keys", Client: client}, ErrInvalidTemplate},
		{"placeholder in a fragment", PerKeyConfig{Template: "https://keys.example.com/keys#{keyID}", Client: client}, ErrInvalidTemplate},
		{"no server name", PerKeyConfig{Template: "https:///keys/{keyID}", Client: client}, ErrInvalidTemplate},
		{"unparseable before the placeholder", PerKeyConfig{Template: "https://[::1/keys/{keyID}", Client: client}, ErrInvalidTemplate},
		{"unparseable after the placeholder", PerKeyConfig{Template: "https://keys.example.com/keys/{keyID}%zz", Client: client}, ErrInvalidTemplate},
		{"a file template", PerKeyConfig{Template: "file:///etc/keys/{keyID}", Client: client}, ErrUnsupportedScheme},
		{"a bare path", PerKeyConfig{Template: "/etc/keys/{keyID}", Client: client}, ErrUnsupportedScheme},
		{"no client", PerKeyConfig{Template: "https://keys.example.com/keys/{keyID}"}, ErrMissingClient},
		{
			"an allowed key ID that is not valid",
			PerKeyConfig{Template: "https://keys.example.com/keys/{keyID}", Client: client, AllowedKeyIDs: []string{"good", "../bad"}},
			ErrInvalidKeyID,
		},
		{
			"allowed key IDs only, with none",
			PerKeyConfig{Template: "https://keys.example.com/keys/{keyID}", Client: client, AllowedKeyIDsOnly: true},
			ErrNoAllowedKeyIDs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewPerKeyProvider(tt.cfg)
			assert.ErrorIs(t, err, tt.expected)
			assert.Nil(t, p)
		})
	}
}

func TestNewPerKeyProviderAcceptsAGoodTemplate(t *testing.T) {
	for _, template := range []string{
		"http://themis/keys/{keyID}",
		"https://themis.example.com:8443/keys/{keyID}",
		"https://themis.example.com/keys/{keyID}/key.json",
		"https://themis.example.com/keys?kid={keyID}",
		"https://themis.example.com?kid={keyID}",
		"https://themis.example.com/{keyID}/{keyID}.json",
		"https://user:secret@themis.example.com/keys/{keyID}",
	} {
		p, err := NewPerKeyProvider(PerKeyConfig{Template: template, Client: testClient()})
		assert.NoError(t, err, template)
		assert.NotNil(t, p, template)
	}
}

func TestNewPerKeyProviderReportsEveryProblemAtOnce(t *testing.T) {
	_, err := NewPerKeyProvider(PerKeyConfig{AllowedKeyIDs: []string{"a/b"}})
	assert.ErrorIs(t, err, ErrInvalidTemplate)
	assert.ErrorIs(t, err, ErrMissingClient)
	assert.ErrorIs(t, err, ErrInvalidKeyID)
}

func TestNewPerKeyProviderNeverQuotesTheTemplate(t *testing.T) {
	// none of these can be redacted reliably, so none is echoed
	for _, template := range []string{
		"https://user:" + "hunter2" + "@keys.example.com/keys/",
		"https://user:" + "hunter2" + "@[::1/keys/{keyID}",
		"ftp://user:" + "hunter2" + "@keys.example.com/{keyID}",
	} {
		_, err := NewPerKeyProvider(PerKeyConfig{Template: template, Client: testClient()})
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "hunter2")
	}
}

func TestNewPerKeyProviderFillsDefaults(t *testing.T) {
	p, err := NewPerKeyProvider(PerKeyConfig{Template: "https://keys.example.com/keys/{keyID}", Client: testClient()})
	require.NoError(t, err)

	assert.Equal(t, DefaultFetchRateLimit, p.cfg.FetchRateLimit)
	assert.Equal(t, DefaultCacheTime, p.cfg.CacheTime)
	assert.Equal(t, DefaultMinCacheTime, p.cfg.MinCacheTime)
	assert.Equal(t, DefaultMaxCacheTime, p.cfg.MaxCacheTime)
	assert.Equal(t, DefaultNotFoundCoolDown, p.cfg.NotFoundCoolDown)
	assert.Equal(t, DefaultFailureCoolDown, p.cfg.FailureCoolDown)
	assert.Equal(t, DefaultMaxResponseBytes, p.cfg.MaxResponseBytes)
	assert.Empty(t, p.KeyIDs(), "nothing is fetched until a token asks")
}

func TestNewPerKeyProviderKeepsExplicitValues(t *testing.T) {
	client := &http.Client{Timeout: 5 * time.Second}
	allowed := []string{"a", "b"}
	p, err := NewPerKeyProvider(PerKeyConfig{
		Template:          "https://keys.example.com/keys/{keyID}",
		Client:            client,
		AllowedKeyIDs:     allowed,
		AllowedKeyIDsOnly: true,
		FetchRateLimit:    time.Second,
		CacheTime:         time.Hour,
		MinCacheTime:      time.Minute,
		MaxCacheTime:      2 * time.Hour,
		NotFoundCoolDown:  3 * time.Minute,
		FailureCoolDown:   4 * time.Second,
		MaxResponseBytes:  1024,
		Verify:            VerifyConfig{IgnoreKeyUsage: true},
	})
	require.NoError(t, err)

	assert.Same(t, client, p.cfg.Client)
	assert.True(t, p.cfg.AllowedKeyIDsOnly)
	assert.Equal(t, time.Second, p.cfg.FetchRateLimit)
	assert.Equal(t, time.Hour, p.cfg.CacheTime)
	assert.Equal(t, time.Minute, p.cfg.MinCacheTime)
	assert.Equal(t, 2*time.Hour, p.cfg.MaxCacheTime)
	assert.Equal(t, 3*time.Minute, p.cfg.NotFoundCoolDown)
	assert.Equal(t, 4*time.Second, p.cfg.FailureCoolDown)
	assert.Equal(t, int64(1024), p.cfg.MaxResponseBytes)
	assert.True(t, p.cfg.Verify.IgnoreKeyUsage)

	// the caller's slice is not kept
	allowed[0] = "changed"
	assert.True(t, p.allowed["a"])
	assert.Equal(t, []string{"a", "b"}, p.cfg.AllowedKeyIDs)
}

func TestNewPerKeyProviderRaisesAMaxBelowTheMin(t *testing.T) {
	p, err := NewPerKeyProvider(PerKeyConfig{
		Template:     "https://keys.example.com/keys/{keyID}",
		Client:       testClient(),
		MinCacheTime: time.Hour,
		MaxCacheTime: time.Minute,
	})
	require.NoError(t, err)
	assert.Equal(t, time.Hour, p.cfg.MaxCacheTime)
}

func TestCheckKeyIDPlacement(t *testing.T) {
	// a number stands in for the key ID here.  unlike {keyID} it parses
	// anywhere, so each case reaches the examination of the part it is in
	// instead of being refused by the parser first.
	const keyID = "8675309"
	tests := []struct {
		name     string
		uri      string
		expected error

		// says is the part of the URL the error must name, so that each check
		// is seen to be the one that refused
		says string
	}{
		{"in the path", "https://keys.example.com/keys/8675309", nil, ""},
		{"in the path, with more after it", "https://keys.example.com/keys/8675309/key.json", nil, ""},
		{"in the query", "https://keys.example.com/keys?kid=8675309", nil, ""},
		{"in the query, with no path", "https://keys.example.com?kid=8675309", nil, ""},
		{"credentials elsewhere are fine", "https://user:secret@keys.example.com/keys/8675309", nil, ""},
		{"is the server name", "https://8675309/keys", ErrInvalidTemplate, "server name"},
		{"starts the server name", "https://8675309.example.com/keys", ErrInvalidTemplate, "server name"},
		{"ends the server name", "https://keys.example.com8675309/keys", ErrInvalidTemplate, "server name"},
		{"is the port", "https://keys.example.com:8675309/keys", ErrInvalidTemplate, "port"},
		{"is the user name", "https://8675309@keys.example.com/keys", ErrInvalidTemplate, "credentials"},
		{"is the password", "https://user:8675309@keys.example.com/keys", ErrInvalidTemplate, "credentials"},
		{"in the fragment", "https://keys.example.com/keys#8675309", ErrInvalidTemplate, "fragment"},
		{"nowhere", "https://keys.example.com/keys", ErrInvalidTemplate, "path or the query"},
		{"no server", "https:///keys/8675309", ErrInvalidTemplate, "no server"},
		{"does not parse", "https://[::1/keys/8675309", ErrInvalidTemplate, "parsed"},
		{"a file", "file:///etc/keys/8675309", ErrUnsupportedScheme, "scheme"},
		{"no scheme", "/etc/keys/8675309", ErrUnsupportedScheme, "scheme"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkKeyIDPlacement(tt.uri, keyID)
			if tt.expected == nil {
				assert.NoError(t, err)
				return
			}

			assert.ErrorIs(t, err, tt.expected)
			assert.ErrorContains(t, err, tt.says)
		})
	}
}

func TestValidateKeyID(t *testing.T) {
	valid := []string{
		"a", "docker", "themis-2017-01", "key_1", "v1.2", "A-Z_a-z.0-9",
		strings.Repeat("k", maxKeyIDLength),
	}
	for _, keyID := range valid {
		assert.NoError(t, validateKeyID(keyID), keyID)
	}

	invalid := []string{
		"", "..", "a..b", "../etc/passwd", "a/b", `a\b`, "a?x=1", "a#b", "a%2Fb",
		"a b", "a\tb", "a\nb", "a:b", "a@b", "a&b", "a=b", "a+b", "a;b", "a,b",
		"{keyID}", "clé", "\x00",
		strings.Repeat("k", maxKeyIDLength+1),
	}
	for _, keyID := range invalid {
		assert.ErrorIs(t, validateKeyID(keyID), ErrInvalidKeyID, "%q", keyID)
	}
}

func TestPerKeyProviderVerifiesATokenFromThemis(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "docker", &rsaKey.PublicKey, nil)
	p, _, rec := testPerKey(t, server, nil)

	payload, err := jws.Verify(sign(t, rsaKey, jwa.RS256(), "docker"), jws.WithKeyProvider(p))
	require.NoError(t, err)
	assert.Equal(t, "payload", string(payload))

	// themis was asked for exactly that key, in the one way that gets a JWK
	assert.Equal(t, []string{"/keys/docker"}, server.requests())
	assert.Equal(t, []string{"application/json"}, server.accepts)
	assert.Equal(t, []string{"docker"}, p.KeyIDs())

	e := rec.next(t)
	assert.Equal(t, "docker", e.KeyID)
	assert.Equal(t, server.template(), e.URI)
	assert.NoError(t, e.Err)

	// the key had no kid of its own, and took the one that was asked for
	kid, ok := p.entries["docker"].key.KeyID()
	assert.True(t, ok)
	assert.Equal(t, "docker", kid)
}

func TestPerKeyProviderRejectsATokenSignedByAnotherKey(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "docker", &rsaKey.PublicKey, nil)
	p, _, _ := testPerKey(t, server, nil)

	// the token names a real key ID, and was signed by something else
	_, err := jws.Verify(sign(t, ecKey, jwa.ES256(), "docker"), jws.WithKeyProvider(p))
	assert.Error(t, err)
}

func TestPerKeyProviderHoldsAFetchedKey(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	p, _, _ := testPerKey(t, server, nil)

	for range 50 {
		require.NoError(t, ask(t, p, "a"))
	}

	assert.Len(t, server.requests(), 1, "a held key needs no request")
}

func TestPerKeyProviderSharesOneRequestBetweenLookups(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	server.closeGate()
	p, _, _ := testPerKey(t, server, nil)

	const lookups = 25
	results := make(chan error, lookups)
	for range lookups {
		go func() { results <- ask(t, p, "a") }()
	}

	// every lookup is now waiting on the one request the server is holding
	require.Eventually(t, func() bool { return len(server.requests()) == 1 }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	server.openGate()

	for range lookups {
		assert.NoError(t, <-results)
	}

	assert.Len(t, server.requests(), 1)
}

func TestPerKeyProviderNeverPutsABadKeyIDInAURL(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	p, _, rec := testPerKey(t, server, nil)

	for _, keyID := range []string{
		"..", "../a", "a/../a", "a/b", `a\b`, "a?x=1", "a#b", "a%2Fb", "a b",
		"a:b", "a@evil.example.com", "evil.example.com/a", "{keyID}",
		strings.Repeat("k", maxKeyIDLength+1),
	} {
		err := ask(t, p, keyID)
		assert.ErrorIs(t, err, ErrKeyNotFound, "%q", keyID)
		assert.ErrorIs(t, err, ErrInvalidKeyID, "%q", keyID)
	}

	assert.Empty(t, server.requests(), "a key ID that fails the check never reaches the server")
	assert.Empty(t, rec.events)
	assert.Empty(t, p.entries, "and nothing is remembered about it")
}

func TestPerKeyProviderKeepsEveryRequestOnTheConfiguredServer(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	valid := []string{"a", "themis-2017-01", "key_1", "v1.2", "a.b.c", "evil.example.com"}
	for _, keyID := range valid {
		server.add(t, keyID, &rsaKey.PublicKey, nil)
	}

	p, _, _ := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = valid })
	for _, keyID := range valid {
		require.NoError(t, ask(t, p, keyID), keyID)
	}

	// every request came to this server, at the path the template gives
	host := strings.TrimPrefix(server.URL, "http://")
	require.Len(t, server.hosts, len(valid))
	for i, keyID := range valid {
		assert.Equal(t, host, server.hosts[i])
		assert.Equal(t, "/keys/"+keyID, server.paths[i])
	}
}

func TestPerKeyProviderPutsTheKeyIDWhereTheTemplateSays(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	p, _, _ := testPerKey(t, server, func(cfg *PerKeyConfig) {
		cfg.Template = server.URL + "/keys/{keyID}?format=jwk&also={keyID}"
	})

	// every placeholder is filled in, wherever the template has one
	require.NoError(t, ask(t, p, "a"))
	assert.Equal(t, []string{"/keys/a?format=jwk&also=a"}, server.requests())
}

func TestPerKeyProviderLimitsFetchesForInventedKeyIDs(t *testing.T) {
	server := newThemisServer(t)
	p, fc, _ := testPerKey(t, server, nil)

	// a flood of key IDs nobody has seen before costs the server one request
	for i := range 1000 {
		assert.ErrorIs(t, ask(t, p, fmt.Sprintf("invented-%d", i)), ErrKeyNotFound)
	}

	assert.Len(t, server.requests(), 1)

	// and one more each time the limit passes
	fc.Add(DefaultFetchRateLimit - time.Second)
	assert.ErrorIs(t, ask(t, p, "still-too-soon"), ErrKeyNotFound)
	assert.Len(t, server.requests(), 1)

	fc.Add(time.Second)
	for i := range 1000 {
		assert.ErrorIs(t, ask(t, p, fmt.Sprintf("second-wave-%d", i)), ErrKeyNotFound)
	}

	assert.Len(t, server.requests(), 2)
}

func TestPerKeyProviderRemembersOnlyWhatItFetched(t *testing.T) {
	server := newThemisServer(t)
	p, fc, _ := testPerKey(t, server, nil)

	// a day of flood, with the clock moving so that the limit keeps opening
	const waves = 200
	for wave := range waves {
		for i := range 20 {
			_ = ask(t, p, fmt.Sprintf("invented-%d-%d", wave, i))
		}

		fc.Add(DefaultFetchRateLimit)
	}

	// one fetch per wave, and each is forgotten once its cool-down is over
	assert.Len(t, server.requests(), waves)
	remembered := int(DefaultNotFoundCoolDown / DefaultFetchRateLimit)
	assert.LessOrEqual(t, len(p.entries), remembered)

	// when the flood ends, the next fetch clears the rest
	fc.Add(DefaultNotFoundCoolDown)
	_ = ask(t, p, "one-more")
	assert.Len(t, p.entries, 1)
}

func TestPerKeyProviderExemptsAllowedKeyIDsFromTheLimit(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "real", &rsaKey.PublicKey, nil)
	server.add(t, "also-real", &rsaKey.PublicKey, nil)
	p, _, _ := testPerKey(t, server, func(cfg *PerKeyConfig) {
		cfg.AllowedKeyIDs = []string{"real", "also-real"}
	})

	// the flood uses up the limit
	for i := range 100 {
		assert.ErrorIs(t, ask(t, p, fmt.Sprintf("invented-%d", i)), ErrKeyNotFound)
	}

	// the keys the operator listed are fetched all the same
	assert.NoError(t, ask(t, p, "real"))
	assert.NoError(t, ask(t, p, "also-real"))
	assert.Equal(t, []string{"/keys/invented-0", "/keys/real", "/keys/also-real"}, server.requests())

	// and fetching them does not use up the limit for the others
	p2, _, _ := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = []string{"real"} })
	require.NoError(t, ask(t, p2, "real"))
	assert.True(t, p2.lastUnlisted.IsZero())
}

func TestPerKeyProviderAllowedKeyIDsOnly(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "real", &rsaKey.PublicKey, nil)
	server.add(t, "unlisted", &rsaKey.PublicKey, nil)
	p, fc, rec := testPerKey(t, server, func(cfg *PerKeyConfig) {
		cfg.AllowedKeyIDs = []string{"real"}
		cfg.AllowedKeyIDsOnly = true
	})

	// nothing off the list is ever fetched, however long we wait, even a key
	// the server really has
	for i := range 100 {
		assert.ErrorIs(t, ask(t, p, fmt.Sprintf("invented-%d", i)), ErrKeyNotFound)
		fc.Add(DefaultFetchRateLimit)
	}

	assert.ErrorIs(t, ask(t, p, "unlisted"), ErrKeyNotFound)
	assert.Empty(t, server.requests())
	assert.Empty(t, rec.events)
	assert.Empty(t, p.entries)

	assert.NoError(t, ask(t, p, "real"))
	assert.Equal(t, []string{"/keys/real"}, server.requests())
}

func TestPerKeyProviderCoolsDownAfterNoSuchKey(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	p, fc, rec := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = []string{"late"} })

	assert.ErrorIs(t, ask(t, p, "late"), ErrKeyNotFound)
	var httpErr *HTTPError
	require.ErrorAs(t, rec.next(t).Err, &httpErr)
	assert.Equal(t, http.StatusNotFound, httpErr.StatusCode)

	// the server answered clearly, so it is not asked again for a long while,
	// even though the key has since appeared
	server.add(t, "late", &rsaKey.PublicKey, nil)
	fc.Add(DefaultNotFoundCoolDown - time.Second)
	assert.ErrorIs(t, ask(t, p, "late"), ErrKeyNotFound)
	assert.Len(t, server.requests(), 1)

	fc.Add(time.Second)
	assert.NoError(t, ask(t, p, "late"))
	assert.Len(t, server.requests(), 2)
}

func TestPerKeyProviderTreatsGoneAsNoSuchKey(t *testing.T) {
	server := newThemisServer(t)
	server.set(func(ts *themisServer) { ts.status = http.StatusGone })
	p, fc, _ := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = []string{"a"} })

	assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound)
	fc.Add(DefaultFailureCoolDown)
	assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound)
	assert.Len(t, server.requests(), 1, "the long cool-down applies, not the short one")
}

func TestPerKeyProviderCoolsDownBrieflyWhenTheServerCannotAnswer(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	server.set(func(ts *themisServer) { ts.status = http.StatusInternalServerError })
	p, fc, _ := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = []string{"a"} })

	assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound)

	// real traffic keeps asking, and the struggling server is left alone
	for range 100 {
		assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound)
	}

	assert.Len(t, server.requests(), 1)

	// the outage was brief, and so is the wait
	server.set(func(ts *themisServer) { ts.status = 0 })
	fc.Add(DefaultFailureCoolDown)
	assert.NoError(t, ask(t, p, "a"))
	assert.Len(t, server.requests(), 2)
}

func TestPerKeyProviderCoolsDownWhenNothingAnswersAtAll(t *testing.T) {
	server := newThemisServer(t)
	template := server.template()
	server.Close()

	p, err := NewPerKeyProvider(PerKeyConfig{Template: template, Client: testClient(), AllowedKeyIDs: []string{"a"}})
	require.NoError(t, err)
	fc := chronon.NewFakeClock(time.Now())
	p.clock = fc

	assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound)
	p.lock.Lock()
	coolDown := p.entries["a"].coolDown
	p.lock.Unlock()
	assert.Equal(t, fc.Now().Add(DefaultFailureCoolDown), coolDown)
}

func TestPerKeyProviderHonorsRetryAfter(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	server.set(func(ts *themisServer) {
		ts.status, ts.retryAfter = http.StatusServiceUnavailable, "120"
	})
	p, fc, _ := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = []string{"a"} })

	assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound)
	server.set(func(ts *themisServer) { ts.status = 0 })

	// the short cool-down has passed, but the server asked for longer
	fc.Add(DefaultFailureCoolDown)
	assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound)
	assert.Len(t, server.requests(), 1)

	fc.Add(2*time.Minute - DefaultFailureCoolDown)
	assert.NoError(t, ask(t, p, "a"))
	assert.Len(t, server.requests(), 2)
}

func TestPerKeyProviderCapsRetryAfter(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	server.set(func(ts *themisServer) {
		ts.status, ts.retryAfter = http.StatusTooManyRequests, "31536000"
	})
	p, fc, _ := testPerKey(t, server, func(cfg *PerKeyConfig) {
		cfg.AllowedKeyIDs = []string{"a"}
		cfg.MaxCacheTime = time.Hour
	})

	assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound)
	server.set(func(ts *themisServer) { ts.status = 0 })

	fc.Add(time.Hour)
	assert.NoError(t, ask(t, p, "a"), "a year was asked for, and the maximum is an hour")
}

func TestPerKeyProviderFetchesAgainWhenTheCacheTimeIsUp(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	tests := []struct {
		name   string
		maxAge string
		held   time.Duration
	}{
		{"the server does not say", "", DefaultCacheTime},
		{"the server says an hour", "3600", time.Hour},
		{"the server says a second, and the minimum applies", "1", DefaultMinCacheTime},
		{"the server says a year, and the maximum applies", "31536000", DefaultMaxCacheTime},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newThemisServer(t)
			server.add(t, "a", &rsaKey.PublicKey, nil)
			server.set(func(ts *themisServer) { ts.maxAge = tt.maxAge })
			p, fc, _ := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = []string{"a"} })

			require.NoError(t, ask(t, p, "a"))
			fc.Add(tt.held - time.Second)
			require.NoError(t, ask(t, p, "a"))
			assert.Len(t, server.requests(), 1, "still held")

			fc.Add(time.Second)
			require.NoError(t, ask(t, p, "a"))
			assert.Len(t, server.requests(), 2, "fetched again")
		})
	}
}

func TestPerKeyProviderUsesTheConfiguredCacheTime(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	p, fc, _ := testPerKey(t, server, func(cfg *PerKeyConfig) {
		cfg.AllowedKeyIDs = []string{"a"}
		cfg.CacheTime = time.Hour
	})

	require.NoError(t, ask(t, p, "a"))
	fc.Add(time.Hour)
	require.NoError(t, ask(t, p, "a"))
	assert.Len(t, server.requests(), 2)
}

func TestPerKeyProviderPicksUpAReplacedKey(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	p, fc, _ := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = []string{"a"} })

	require.NoError(t, ask(t, p, "a"))
	server.add(t, "a", &ecKey.PublicKey, nil)
	fc.Add(DefaultCacheTime)
	require.NoError(t, ask(t, p, "a"))

	p.lock.Lock()
	defer p.lock.Unlock()
	assert.Equal(t, jwa.EC(), p.entries["a"].key.KeyType())
}

func TestPerKeyProviderKeepsServingWhenTheServerCannotAnswer(t *testing.T) {
	rsaKey, ecKey := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	p, fc, rec := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = []string{"a"} })

	require.NoError(t, ask(t, p, "a"))
	require.NoError(t, rec.next(t).Err)

	// the key's time is up, and the server is down
	server.set(func(ts *themisServer) { ts.status = http.StatusInternalServerError })
	fc.Add(DefaultCacheTime)
	assert.NoError(t, ask(t, p, "a"), "the old key keeps serving")
	assert.Error(t, rec.next(t).Err)
	assert.Len(t, server.requests(), 2)

	// it goes on serving through the cool-down, without asking again
	for range 50 {
		assert.NoError(t, ask(t, p, "a"))
	}

	assert.Len(t, server.requests(), 2)
	assert.Equal(t, []string{"a"}, p.KeyIDs())

	// each time the cool-down passes it asks once more, and still serves
	fc.Add(DefaultFailureCoolDown)
	assert.NoError(t, ask(t, p, "a"))
	assert.Len(t, server.requests(), 3)

	// when the server is back, the next attempt brings the current key
	server.add(t, "a", &ecKey.PublicKey, nil)
	server.set(func(ts *themisServer) { ts.status = 0 })
	fc.Add(DefaultFailureCoolDown)
	assert.NoError(t, ask(t, p, "a"))
	assert.Len(t, server.requests(), 4)

	p.lock.Lock()
	defer p.lock.Unlock()
	assert.Equal(t, jwa.EC(), p.entries["a"].key.KeyType())
}

func TestPerKeyProviderDropsAKeyTheServerNoLongerHas(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	p, fc, _ := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = []string{"a"} })

	require.NoError(t, ask(t, p, "a"))
	server.set(func(ts *themisServer) { delete(ts.keys, "a") })

	// the key's time is up, and the server says it is gone
	fc.Add(DefaultCacheTime)
	assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound, "it is dropped at once")
	assert.Empty(t, p.KeyIDs())
	assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound)
	assert.Len(t, server.requests(), 2)
}

func TestPerKeyProviderKeepsServingWhenTheLimitRefusesARefetch(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "unlisted", &rsaKey.PublicKey, nil)
	p, fc, _ := testPerKey(t, server, nil)

	require.NoError(t, ask(t, p, "unlisted"))

	// the key's time is up, and a flood has just used the limit
	fc.Add(DefaultCacheTime)
	assert.ErrorIs(t, ask(t, p, "invented"), ErrKeyNotFound)
	assert.NoError(t, ask(t, p, "unlisted"), "the old key serves until it can be fetched again")
	assert.Equal(t, []string{"/keys/unlisted", "/keys/invented"}, server.requests())

	fc.Add(DefaultFetchRateLimit)
	assert.NoError(t, ask(t, p, "unlisted"))
	assert.Len(t, server.requests(), 3)
}

func TestPerKeyProviderRejectsAKeyItCannotUse(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	tests := []struct {
		name     string
		arrange  func(t *testing.T, server *themisServer, cfg *PerKeyConfig)
		expected error
		longWait bool
	}{
		{
			name: "a symmetric key",
			arrange: func(_ *testing.T, server *themisServer, _ *PerKeyConfig) {
				server.set(func(ts *themisServer) { ts.keys["a"] = []byte(`{"kty":"oct","k":"c2VjcmV0"}`) })
			},
			expected: ErrSymmetricKey,
			longWait: true,
		},
		{
			name: "a key that says it is a different key",
			arrange: func(t *testing.T, server *themisServer, _ *PerKeyConfig) {
				server.add(t, "a", &rsaKey.PublicKey, map[string]any{jwk.KeyIDKey: "b"})
			},
			expected: ErrKeyIDMismatch,
			longWait: true,
		},
		{
			name: "a body over the limit",
			arrange: func(t *testing.T, server *themisServer, cfg *PerKeyConfig) {
				server.add(t, "a", &rsaKey.PublicKey, nil)
				cfg.MaxResponseBytes = 16
			},
			expected: ErrResponseTooLarge,
			longWait: true,
		},
		{
			name: "a body that is not a key",
			arrange: func(_ *testing.T, server *themisServer, _ *PerKeyConfig) {
				server.set(func(ts *themisServer) { ts.keys["a"] = []byte(`<html>down for maintenance</html>`) })
			},
			longWait: false,
		},
		{
			name: "a key set where one key was asked for",
			arrange: func(t *testing.T, server *themisServer, _ *PerKeyConfig) {
				set := jwkSetJSON(t, publicJWK(t, &rsaKey.PublicKey, "a", nil))
				server.set(func(ts *themisServer) { ts.keys["a"] = set })
			},
			longWait: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newThemisServer(t)
			p, fc, rec := testPerKey(t, server, func(cfg *PerKeyConfig) {
				cfg.AllowedKeyIDs = []string{"a"}
				tt.arrange(t, server, cfg)
			})

			assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound)
			e := rec.next(t)
			require.Error(t, e.Err)
			if tt.expected != nil {
				assert.ErrorIs(t, e.Err, tt.expected)
			}

			assert.Empty(t, p.KeyIDs())

			// the short cool-down is over.  a key the server chose to serve
			// will be the same key, so that waits out the long one.
			fc.Add(DefaultFailureCoolDown)
			assert.ErrorIs(t, ask(t, p, "a"), ErrKeyNotFound)
			if tt.longWait {
				assert.Len(t, server.requests(), 1)
			} else {
				assert.Len(t, server.requests(), 2)
			}
		})
	}
}

func TestPerKeyProviderKeepsTheOldKeyWhenTheNewOneIsRejected(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	p, fc, rec := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = []string{"a"} })

	require.NoError(t, ask(t, p, "a"))
	require.NoError(t, rec.next(t).Err)

	server.set(func(ts *themisServer) { ts.keys["a"] = []byte(`{"kty":"oct","k":"c2VjcmV0"}`) })
	fc.Add(DefaultCacheTime)
	assert.NoError(t, ask(t, p, "a"), "the last good key keeps serving")
	assert.ErrorIs(t, rec.next(t).Err, ErrSymmetricKey)

	p.lock.Lock()
	defer p.lock.Unlock()
	assert.Equal(t, jwa.RSA(), p.entries["a"].key.KeyType())
}

func TestPerKeyProviderGetsPEMWithoutTheExactAcceptHeader(t *testing.T) {
	// this pins the reason the Accept header is what it is: the themis-like
	// server answers anything else with PEM, which is not a key clortho reads
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)

	c, err := loadHTTP(context.Background(), httpGet{
		client:   testClient(),
		uri:      server.URL + "/keys/a",
		accept:   acceptHeader,
		maxBytes: DefaultMaxResponseBytes,
	})
	require.NoError(t, err)
	_, err = parseKey(c.data, "a")
	assert.Error(t, err)

	c, err = loadHTTP(context.Background(), httpGet{
		client:   testClient(),
		uri:      server.URL + "/keys/a",
		accept:   perKeyAccept,
		maxBytes: DefaultMaxResponseBytes,
	})
	require.NoError(t, err)
	_, err = parseKey(c.data, "a")
	assert.NoError(t, err)
}

func TestPerKeyProviderReducesAPrivateKeyToItsPublicForm(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "leaked", rsaKey, nil)
	p, _, _ := testPerKey(t, server, nil)

	require.NoError(t, ask(t, p, "leaked"))

	p.lock.Lock()
	defer p.lock.Unlock()
	held, err := json.Marshal(p.entries["leaked"].key)
	require.NoError(t, err)

	var members map[string]any
	require.NoError(t, json.Unmarshal(held, &members))
	assert.NotContains(t, members, "d", "the private exponent must not be held")
	assert.Contains(t, members, "n")
}

func TestPerKeyProviderStopsWaitingWhenTheCallerDoes(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	server.closeGate()
	p, _, rec := testPerKey(t, server, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var sink recordingSink
	err := p.FetchKeys(ctx, &sink, unverifiedSignature(t, `{"kid":"a","alg":"RS256"}`), nil)
	assert.ErrorIs(t, err, ErrKeyNotFound)

	// the fetch was not canceled with the caller: it finishes, and the key is
	// there for the next token without another request
	server.openGate()
	require.NoError(t, rec.next(t).Err)
	assert.NoError(t, ask(t, p, "a"))
	assert.Len(t, server.requests(), 1)
}

func TestPerKeyProviderServesTheOldKeyToACallerThatStopsWaiting(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	p, fc, rec := testPerKey(t, server, nil)

	require.NoError(t, ask(t, p, "a"))
	require.NoError(t, rec.next(t).Err)

	// the key's time is up, and the refetch is slow
	server.closeGate()
	fc.Add(DefaultCacheTime)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	var sink recordingSink
	err := p.FetchKeys(ctx, &sink, unverifiedSignature(t, `{"kid":"a","alg":"RS256"}`), nil)
	assert.NoError(t, err)
	assert.NotNil(t, sink.key)

	server.openGate()
	require.NoError(t, rec.next(t).Err)
}

func TestPerKeyProviderAppliesTheVerifyChecks(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "plain", &rsaKey.PublicKey, nil)
	server.add(t, "for-encryption", &rsaKey.PublicKey, map[string]any{jwk.KeyUsageKey: "enc"})
	server.add(t, "rs512-only", &rsaKey.PublicKey, map[string]any{jwk.AlgorithmKey: jwa.RS512()})
	allowed := []string{"plain", "for-encryption", "rs512-only"}

	strict, _, _ := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = allowed })
	assert.NoError(t, ask(t, strict, "plain"))
	assert.ErrorIs(t, ask(t, strict, "for-encryption"), ErrKeyUsage)
	assert.ErrorIs(t, ask(t, strict, "rs512-only"), ErrKeyAlgorithm)

	lenient, _, _ := testPerKey(t, server, func(cfg *PerKeyConfig) {
		cfg.AllowedKeyIDs = allowed
		cfg.Verify = VerifyConfig{IgnoreKeyUsage: true, IgnoreKeyAlgorithm: true}
	})
	assert.NoError(t, ask(t, lenient, "for-encryption"))
	assert.NoError(t, ask(t, lenient, "rs512-only"))

	var sink recordingSink
	err := strict.FetchKeys(context.Background(), &sink, unverifiedSignature(t, `{"alg":"RS256"}`), nil)
	assert.ErrorIs(t, err, ErrMissingKeyID)

	err = strict.FetchKeys(context.Background(), &sink, unverifiedSignature(t, `{"kid":"plain"}`), nil)
	assert.ErrorIs(t, err, ErrMissingAlgorithm)
}

func TestPerKeyProviderOffersTheKeyUnderTheTokensAlgorithm(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	p, _, _ := testPerKey(t, server, nil)

	var sink recordingSink
	err := p.FetchKeys(context.Background(), &sink, unverifiedSignature(t, `{"kid":"a","alg":"RS384"}`), nil)
	require.NoError(t, err)
	assert.Equal(t, jwa.RS384(), sink.alg)
	assert.NotNil(t, sink.key)
}

func TestPerKeyProviderKeyIDsListsWhatIsHeld(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	for _, keyID := range []string{"c", "a", "b"} {
		server.add(t, keyID, &rsaKey.PublicKey, nil)
	}

	p, _, _ := testPerKey(t, server, func(cfg *PerKeyConfig) {
		cfg.AllowedKeyIDs = []string{"a", "b", "c", "missing"}
	})

	for _, keyID := range []string{"c", "a", "b"} {
		require.NoError(t, ask(t, p, keyID))
	}

	// a key ID that was asked for and not found is remembered, but not held
	assert.ErrorIs(t, ask(t, p, "missing"), ErrKeyNotFound)
	assert.Equal(t, []string{"a", "b", "c"}, p.KeyIDs())
}

func TestPerKeyProviderRedactsCredentialsInEventsAndErrors(t *testing.T) {
	server := newThemisServer(t)
	withPassword := strings.Replace(server.URL, "http://", "http://user:"+"hunter2"+"@", 1)
	p, _, rec := testPerKey(t, server, func(cfg *PerKeyConfig) {
		cfg.Template = withPassword + "/keys/{keyID}"
	})

	assert.ErrorIs(t, ask(t, p, "missing"), ErrKeyNotFound)
	e := rec.next(t)
	assert.NotContains(t, e.URI, "hunter2")
	assert.Contains(t, e.URI, "user:xxxxx@")
	assert.True(t, strings.HasSuffix(e.URI, "/keys/{keyID}"), "the template is reported, not the expanded URL")
	require.Error(t, e.Err)
	assert.NotContains(t, e.Err.Error(), "hunter2")
}

func TestPerKeyProviderCancelListener(t *testing.T) {
	rsaKey, _ := testPrivateKeys(t)
	server := newThemisServer(t)
	server.add(t, "a", &rsaKey.PublicKey, nil)
	server.add(t, "b", &rsaKey.PublicKey, nil)
	p, _, rec := testPerKey(t, server, func(cfg *PerKeyConfig) { cfg.AllowedKeyIDs = []string{"a", "b"} })

	second := &fetchRecorder{events: make(chan FetchEvent, 8)}
	cancel := p.AddListener(second)

	require.NoError(t, ask(t, p, "a"))
	rec.next(t)
	second.next(t)

	cancel()
	cancel()
	require.NoError(t, ask(t, p, "b"))
	rec.next(t)
	assert.Empty(t, second.events)
}
