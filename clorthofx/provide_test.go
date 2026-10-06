// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthofx

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/clortho"
	"github.com/xmidt-org/clortho/clorthometrics"
	"github.com/xmidt-org/touchstone"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

var (
	keyOnce    sync.Once
	privateKey *rsa.PrivateKey
	publicJWK  []byte
)

// testKey generates the signing key once and its public JWK under kid "kid-1".
func testKey(t *testing.T) (*rsa.PrivateKey, []byte) {
	keyOnce.Do(func() {
		var err error
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		jk, err := jwk.Import[jwk.Key](&privateKey.PublicKey)
		require.NoError(t, err)
		require.NoError(t, jk.Set(jwk.KeyIDKey, "kid-1"))
		publicJWK, err = json.Marshal(jk)
		require.NoError(t, err)
	})

	return privateKey, publicJWK
}

// signedJWS signs a payload with the test key, carrying kid "kid-1".
func signedJWS(t *testing.T) []byte {
	key, _ := testKey(t)
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.KeyIDKey, "kid-1"))
	signed, err := jws.Sign([]byte(`{"sub":"test"}`), jws.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)
	return signed
}

// keyServer serves the test key as a single JWK.
func keyServer(t *testing.T) *httptest.Server {
	_, jwkJSON := testKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk+json")
		_, _ = w.Write(jwkJSON)
	}))
	t.Cleanup(server.Close)
	return server
}

// perKeyServer serves the test key the way themis does: one key per request
// at /keys/<kid>, and only for the test key's ID.  It counts its requests.
type perKeyServer struct {
	*httptest.Server
	requests atomic.Int32
}

func newPerKeyServer(t *testing.T) *perKeyServer {
	_, jwkJSON := testKey(t)
	s := new(perKeyServer)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		if strings.TrimPrefix(r.URL.Path, "/keys/") != "kid-1" {
			http.NotFound(w, r)
			return
		}

		_, _ = w.Write(jwkJSON)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *perKeyServer) config() clortho.PerKeyConfig {
	return clortho.PerKeyConfig{Template: s.URL + "/keys/{keyID}", Client: s.Client()}
}

// keySetConfig is a config for a KeySetProvider that reads the test key.
func keySetConfig(server *httptest.Server) clortho.KeySetConfig {
	return clortho.KeySetConfig{Sources: []clortho.RefreshSource{{URI: server.URL, Client: server.Client()}}}
}

// fixedConfig is a config for a FixedKeyProvider that holds the test key.
func fixedConfig(t *testing.T) clortho.FixedKeyConfig {
	_, jwkJSON := testKey(t)
	return clortho.FixedKeyConfig{Keys: []clortho.FixedKey{{KeyID: "kid-1", Key: string(jwkJSON)}}}
}

// waitForKeys blocks until the KeySetProvider has loaded a key.
func waitForKeys(t *testing.T, p *clortho.KeySetProvider) {
	require.Eventually(t, func() bool { return len(p.KeyIDs()) > 0 }, 5*time.Second, 10*time.Millisecond)
}

// verify checks the test token against a provider.
func verify(t *testing.T, kp jws.KeyProvider) {
	payload, err := jws.Verify(signedJWS(t), jws.WithKeyProvider(kp))
	require.NoError(t, err)
	assert.JSONEq(t, `{"sub":"test"}`, string(payload))
}

func TestProvideRequiresAConfig(t *testing.T) {
	var kp jws.KeyProvider
	app := fx.New(fx.NopLogger, Provide(), fx.Populate(&kp))
	assert.ErrorContains(t, app.Err(), "clorthofx.Config")
}

func TestProvideRejectsAConfigThatAsksForNothing(t *testing.T) {
	var kp jws.KeyProvider
	app := fx.New(fx.NopLogger, Provide(), fx.Supply(Config{}), fx.Populate(&kp))
	assert.ErrorIs(t, app.Err(), ErrNoProviders)
	assert.Nil(t, kp)
}

func TestProvideReportsEveryBadConfigAndSaysWhichItIs(t *testing.T) {
	server := keyServer(t)
	cfg := Config{
		KeySets: []clortho.KeySetConfig{keySetConfig(server), {}},
		PerKeys: []clortho.PerKeyConfig{{Template: "https://keys.example.com/keys/{keyID}"}},
		Fixed:   []clortho.FixedKeyConfig{fixedConfig(t), {}},
	}

	// fx.New fails without having to be told to, since the module builds its
	// providers at startup
	app := fx.New(fx.NopLogger, Provide(), fx.Supply(cfg))
	err := app.Err()
	assert.ErrorIs(t, err, clortho.ErrNoKeySources)
	assert.ErrorIs(t, err, clortho.ErrMissingClient)
	assert.ErrorIs(t, err, clortho.ErrNoFixedKeys)
	assert.ErrorContains(t, err, "key set provider 1")
	assert.ErrorContains(t, err, "per-key provider 0")
	assert.ErrorContains(t, err, "fixed key provider 1")
}

func TestProvideAKeySetProvider(t *testing.T) {
	server := keyServer(t)

	var (
		kp      jws.KeyProvider
		keySets []*clortho.KeySetProvider
		perKeys []*clortho.PerKeyProvider
		fixed   []*clortho.FixedKeyProvider
	)

	app := fxtest.New(t,
		Provide(),
		fx.Supply(Config{KeySets: []clortho.KeySetConfig{keySetConfig(server)}}),
		fx.Populate(&kp, &keySets, &perKeys, &fixed),
	)
	require.NoError(t, app.Err())
	app.RequireStart()

	require.Len(t, keySets, 1)
	assert.Empty(t, perKeys)
	assert.Empty(t, fixed)
	waitForKeys(t, keySets[0])
	verify(t, kp)

	status := keySets[0].Status()
	require.Len(t, status, 1)
	assert.Equal(t, http.StatusOK, status[0].LastStatusCode)

	// the provider stops with the application
	app.RequireStop()
	assert.ErrorIs(t, keySets[0].Stop(t.Context()), clortho.ErrNotStarted)
}

func TestProvideAPerKeyProvider(t *testing.T) {
	server := newPerKeyServer(t)

	var (
		kp      jws.KeyProvider
		perKeys []*clortho.PerKeyProvider
	)

	app := fxtest.New(t,
		Provide(),
		fx.Supply(Config{PerKeys: []clortho.PerKeyConfig{server.config()}}),
		fx.Populate(&kp, &perKeys),
	)
	app.RequireStart()
	defer app.RequireStop()

	require.Len(t, perKeys, 1)
	assert.Empty(t, perKeys[0].KeyIDs(), "nothing is fetched until a token asks")
	verify(t, kp)
	assert.Equal(t, []string{"kid-1"}, perKeys[0].KeyIDs())
	assert.Equal(t, int32(1), server.requests.Load())
}

func TestProvideAFixedKeyProvider(t *testing.T) {
	var (
		kp    jws.KeyProvider
		fixed []*clortho.FixedKeyProvider
	)

	app := fxtest.New(t,
		Provide(),
		fx.Supply(Config{Fixed: []clortho.FixedKeyConfig{fixedConfig(t)}}),
		fx.Populate(&kp, &fixed),
	)
	app.RequireStart()
	defer app.RequireStop()

	require.Len(t, fixed, 1)
	assert.Equal(t, []string{"kid-1"}, fixed[0].KeyIDs())
	verify(t, kp)
}

func TestProvideSeveralOfEachKind(t *testing.T) {
	one, two := keyServer(t), keyServer(t)
	perKeyOne, perKeyTwo := newPerKeyServer(t), newPerKeyServer(t)

	var (
		keySets []*clortho.KeySetProvider
		perKeys []*clortho.PerKeyProvider
		fixed   []*clortho.FixedKeyProvider
	)

	app := fxtest.New(t,
		Provide(),
		fx.Supply(Config{
			KeySets: []clortho.KeySetConfig{keySetConfig(one), keySetConfig(two)},
			PerKeys: []clortho.PerKeyConfig{perKeyOne.config(), perKeyTwo.config()},
			Fixed:   []clortho.FixedKeyConfig{fixedConfig(t), fixedConfig(t)},
		}),
		fx.Populate(&keySets, &perKeys, &fixed),
	)
	app.RequireStart()

	// each list is in the order of its configs
	require.Len(t, keySets, 2)
	require.Len(t, perKeys, 2)
	require.Len(t, fixed, 2)
	assert.Equal(t, one.URL, keySets[0].Status()[0].URI)
	assert.Equal(t, two.URL, keySets[1].Status()[0].URI)

	// every KeySetProvider is started and stopped with the application
	waitForKeys(t, keySets[0])
	waitForKeys(t, keySets[1])
	app.RequireStop()
	assert.ErrorIs(t, keySets[0].Stop(t.Context()), clortho.ErrNotStarted)
	assert.ErrorIs(t, keySets[1].Stop(t.Context()), clortho.ErrNotStarted)
}

func TestProvideAsksAPerKeyProviderLastAndOnlyWhenNeeded(t *testing.T) {
	perKey := newPerKeyServer(t)

	var kp jws.KeyProvider
	app := fxtest.New(t,
		Provide(),
		fx.Supply(Config{
			// listed first here, and still asked last
			PerKeys: []clortho.PerKeyConfig{perKey.config()},
			Fixed:   []clortho.FixedKeyConfig{fixedConfig(t)},
		}),
		fx.Populate(&kp),
	)
	app.RequireStart()
	defer app.RequireStop()

	// the fixed key provider holds the key, so the token never reaches the
	// provider that would have fetched for it
	for range 20 {
		verify(t, kp)
	}

	assert.Zero(t, perKey.requests.Load())
}

func TestProvideFallsThroughToAPerKeyProvider(t *testing.T) {
	keySetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(keySetServer.Close)
	perKey := newPerKeyServer(t)

	var (
		kp      jws.KeyProvider
		keySets []*clortho.KeySetProvider
	)

	app := fxtest.New(t,
		Provide(),
		fx.Supply(Config{
			KeySets: []clortho.KeySetConfig{keySetConfig(keySetServer)},
			PerKeys: []clortho.PerKeyConfig{perKey.config()},
		}),
		fx.Populate(&kp, &keySets),
	)
	app.RequireStart()
	defer app.RequireStop()

	// the key set has loaded and holds no keys, so the per-key provider is asked
	require.Eventually(t, func() bool { return !keySets[0].Status()[0].LastRetrieved.IsZero() }, 5*time.Second, 10*time.Millisecond)
	verify(t, kp)
	assert.Equal(t, int32(1), perKey.requests.Load())
}

func TestProvideReportsAKeyNoProviderHas(t *testing.T) {
	var kp jws.KeyProvider
	app := fxtest.New(t,
		Provide(),
		fx.Supply(Config{Fixed: []clortho.FixedKeyConfig{fixedConfig(t), fixedConfig(t)}}),
		fx.Populate(&kp),
	)
	app.RequireStart()
	defer app.RequireStop()

	key, _ := testKey(t)
	headers := jws.NewHeaders()
	require.NoError(t, headers.Set(jws.KeyIDKey, "unknown"))
	signed, err := jws.Sign([]byte(`{}`), jws.WithKey(jwa.RS256(), key, jws.WithProtectedHeaders(headers)))
	require.NoError(t, err)

	_, err = jws.Verify(signed, jws.WithKeyProvider(kp))
	assert.ErrorIs(t, err, clortho.ErrKeyNotFound)
}

func TestProvideLogsRefreshesAndFetches(t *testing.T) {
	keySetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"keys":[]}`))
	}))
	t.Cleanup(keySetServer.Close)
	perKey := newPerKeyServer(t)
	core, logs := observer.New(zapcore.InfoLevel)

	var kp jws.KeyProvider
	app := fxtest.New(t,
		Provide(),
		fx.Supply(Config{
			KeySets: []clortho.KeySetConfig{keySetConfig(keySetServer)},
			PerKeys: []clortho.PerKeyConfig{perKey.config()},
		}),
		fx.Supply(zap.New(core)),
		fx.Populate(&kp),
	)
	app.RequireStart()
	defer app.RequireStop()

	require.Eventually(t, func() bool { return logs.FilterMessage("key refresh").Len() > 0 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, Module, logs.FilterMessage("key refresh").All()[0].LoggerName)

	verify(t, kp)
	require.Eventually(t, func() bool { return logs.FilterMessage("key fetch").Len() > 0 }, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, Module, logs.FilterMessage("key fetch").All()[0].LoggerName)
}

func TestProvideRecordsMetricsForEveryProvider(t *testing.T) {
	one, two := keyServer(t), keyServer(t)
	perKey := newPerKeyServer(t)
	registry := prometheus.NewPedanticRegistry()
	factory := touchstone.NewFactory(touchstone.Config{}, zap.NewNop(), registry)

	var (
		keySets []*clortho.KeySetProvider
		perKeys []*clortho.PerKeyProvider
	)

	// two providers of one kind share the one listener, so the metrics are
	// registered once and the application still starts
	app := fxtest.New(t,
		Provide(),
		fx.Supply(Config{
			KeySets: []clortho.KeySetConfig{keySetConfig(one), keySetConfig(two)},
			PerKeys: []clortho.PerKeyConfig{perKey.config()},
		}),
		fx.Supply(factory),
		fx.Populate(&keySets, &perKeys),
	)
	app.RequireStart()
	defer app.RequireStop()
	waitForKeys(t, keySets[0])
	waitForKeys(t, keySets[1])

	// ask the per-key provider directly, since the key set providers hold the key
	_, err := jws.Verify(signedJWS(t), jws.WithKeyProvider(perKeys[0]))
	require.NoError(t, err)

	series := func(name string) int {
		families, err := registry.Gather()
		require.NoError(t, err)
		for _, f := range families {
			if f.GetName() == name {
				return len(f.GetMetric())
			}
		}

		return 0
	}

	require.Eventually(t, func() bool { return series(clorthometrics.RefreshTotalName) == 2 }, 5*time.Second, 10*time.Millisecond,
		"one series for each key set source")
	require.Eventually(t, func() bool { return series(clorthometrics.FetchTotalName) == 1 }, 5*time.Second, 10*time.Millisecond)
}

func TestProvideFailsWhenMetricsCollide(t *testing.T) {
	server := keyServer(t)
	registry := prometheus.NewPedanticRegistry()
	factory := touchstone.NewFactory(touchstone.Config{}, zap.NewNop(), registry)
	_, err := factory.NewCounterVec(prometheus.CounterOpts{Name: clorthometrics.RefreshTotalName, Help: "taken"}, clorthometrics.SourceLabel)
	require.NoError(t, err)

	var kp jws.KeyProvider
	app := fx.New(fx.NopLogger,
		Provide(),
		fx.Supply(Config{KeySets: []clortho.KeySetConfig{keySetConfig(server)}}),
		fx.Supply(factory),
		fx.Populate(&kp),
	)
	assert.Error(t, app.Err())
	assert.Nil(t, kp)
}
