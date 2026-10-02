// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthofx

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
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

// waitForKeys blocks until the Provider has loaded a key.
func waitForKeys(t *testing.T, p *clortho.Provider) {
	require.Eventually(t, func() bool { return len(p.KeyIDs()) > 0 }, 5*time.Second, 10*time.Millisecond)
}

func TestProvideRequiresAConfig(t *testing.T) {
	var p *clortho.Provider
	app := fx.New(fx.NopLogger, Provide(), fx.Populate(&p))
	assert.ErrorContains(t, app.Err(), "clortho.Config")
	assert.Nil(t, p)
}

func TestProvideRejectsABadConfig(t *testing.T) {
	var p *clortho.Provider
	app := fx.New(fx.NopLogger, Provide(), fx.Supply(clortho.Config{}), fx.Populate(&p))
	assert.ErrorIs(t, app.Err(), clortho.ErrNoKeySources)
	assert.Nil(t, p)
}

func TestProvideVerifiesATokenOnceStarted(t *testing.T) {
	server := keyServer(t)

	var (
		p  *clortho.Provider
		kp jws.KeyProvider
	)

	app := fxtest.New(t,
		Provide(),
		fx.Supply(clortho.Config{Sources: []clortho.RefreshSource{{URI: server.URL}}}),
		fx.Populate(&p, &kp),
	)
	require.NoError(t, app.Err())
	app.RequireStart()
	defer app.RequireStop()

	require.NotNil(t, p)
	require.NotNil(t, kp)
	waitForKeys(t, p)

	payload, err := jws.Verify(signedJWS(t), jws.WithKeyProvider(kp))
	require.NoError(t, err)
	assert.JSONEq(t, `{"sub":"test"}`, string(payload))

	status := p.Status()
	require.Len(t, status, 1)
	assert.Equal(t, http.StatusOK, status[0].LastStatusCode)
}

func TestProvideStopsTheProviderWithTheApplication(t *testing.T) {
	server := keyServer(t)

	var p *clortho.Provider
	app := fxtest.New(t,
		Provide(),
		fx.Supply(clortho.Config{Sources: []clortho.RefreshSource{{URI: server.URL}}}),
		fx.Populate(&p),
	)
	app.RequireStart()
	waitForKeys(t, p)
	app.RequireStop()

	assert.ErrorIs(t, p.Stop(t.Context()), clortho.ErrNotStarted)
}

func TestProvideLogsRefreshes(t *testing.T) {
	server := keyServer(t)
	core, logs := observer.New(zapcore.InfoLevel)

	var p *clortho.Provider
	app := fxtest.New(t,
		Provide(),
		fx.Supply(clortho.Config{Sources: []clortho.RefreshSource{{URI: server.URL}}}),
		fx.Supply(zap.New(core)),
		fx.Populate(&p),
	)
	app.RequireStart()
	defer app.RequireStop()
	waitForKeys(t, p)

	require.Eventually(t, func() bool { return logs.FilterMessage("key refresh").Len() > 0 }, 5*time.Second, 10*time.Millisecond)
	entry := logs.FilterMessage("key refresh").All()[0]
	assert.Equal(t, Module, entry.LoggerName)
}

func TestProvideRecordsMetrics(t *testing.T) {
	server := keyServer(t)
	registry := prometheus.NewPedanticRegistry()
	factory := touchstone.NewFactory(touchstone.Config{}, zap.NewNop(), registry)

	var p *clortho.Provider
	app := fxtest.New(t,
		Provide(),
		fx.Supply(clortho.Config{Sources: []clortho.RefreshSource{{URI: server.URL}}}),
		fx.Supply(factory),
		fx.Populate(&p),
	)
	app.RequireStart()
	defer app.RequireStop()
	waitForKeys(t, p)

	require.Eventually(t, func() bool {
		families, err := registry.Gather()
		require.NoError(t, err)
		for _, f := range families {
			if f.GetName() == clorthometrics.RefreshTotalName {
				return true
			}
		}

		return false
	}, 5*time.Second, 10*time.Millisecond)
}

func TestProvideFailsWhenMetricsCollide(t *testing.T) {
	server := keyServer(t)
	registry := prometheus.NewPedanticRegistry()
	factory := touchstone.NewFactory(touchstone.Config{}, zap.NewNop(), registry)
	_, err := factory.NewCounterVec(prometheus.CounterOpts{Name: clorthometrics.RefreshTotalName, Help: "taken"}, clorthometrics.SourceLabel)
	require.NoError(t, err)

	var p *clortho.Provider
	app := fx.New(fx.NopLogger,
		Provide(),
		fx.Supply(clortho.Config{Sources: []clortho.RefreshSource{{URI: server.URL}}}),
		fx.Supply(factory),
		fx.Populate(&p),
	)
	assert.Error(t, app.Err())
	assert.Nil(t, p)
}
