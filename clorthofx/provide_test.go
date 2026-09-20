// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthofx

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/suite"
	"github.com/xmidt-org/clortho"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"gopkg.in/h2non/gock.v1"
)

type ProvideSuite struct {
	suite.Suite

	privateKey *rsa.PrivateKey

	// publicJWK is the JSON of the public half of privateKey, with kid "kid-1"
	publicJWK []byte

	// publicKey is the same key as a clortho.Key, for adding to a ring directly
	publicKey clortho.Key

	// secret is a shared HMAC secret, and symmetricKey the clortho.Key holding it
	// under kid "hmac-1", as it would arrive from a JWKS or a local file
	secret       []byte
	symmetricKey clortho.Key
}

func (suite *ProvideSuite) SetupSuite() {
	var err error
	suite.privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	suite.Require().NoError(err)

	jk, err := jwk.Import[jwk.Key](&suite.privateKey.PublicKey)
	suite.Require().NoError(err)
	suite.Require().NoError(jk.Set(jwk.KeyIDKey, "kid-1"))

	suite.publicJWK, err = json.Marshal(jk)
	suite.Require().NoError(err)

	p, err := clortho.NewParser()
	suite.Require().NoError(err)
	keys, err := p.Parse(clortho.MediaTypeJWK, suite.publicJWK)
	suite.Require().NoError(err)
	suite.Require().Len(keys, 1)
	suite.publicKey = keys[0]

	suite.secret = make([]byte, 32)
	_, err = rand.Read(suite.secret)
	suite.Require().NoError(err)

	sk, err := jwk.Import[jwk.Key](suite.secret)
	suite.Require().NoError(err)
	suite.Require().NoError(sk.Set(jwk.KeyIDKey, "hmac-1"))
	secretJWK, err := json.Marshal(sk)
	suite.Require().NoError(err)

	keys, err = p.Parse(clortho.MediaTypeJWK, secretJWK)
	suite.Require().NoError(err)
	suite.Require().Len(keys, 1)
	suite.symmetricKey = keys[0]
}

// newHMACJWS signs a JWS with the suite's shared secret, carrying kid "hmac-1".
func (suite *ProvideSuite) newHMACJWS() []byte {
	headers := jws.NewHeaders()
	suite.Require().NoError(headers.Set(jws.KeyIDKey, "hmac-1"))

	signed, err := jws.Sign(
		[]byte(`{"sub":"test"}`),
		jws.WithKey(jwa.HS256(), suite.secret, jws.WithProtectedHeaders(headers)),
	)

	suite.Require().NoError(err)
	return signed
}

// newSignedJWS signs a JWS with the suite's key, carrying kid "kid-1".
func (suite *ProvideSuite) newSignedJWS() []byte {
	headers := jws.NewHeaders()
	suite.Require().NoError(headers.Set(jws.KeyIDKey, "kid-1"))

	signed, err := jws.Sign(
		[]byte(`{"sub":"test"}`),
		jws.WithKey(jwa.RS256(), suite.privateKey, jws.WithProtectedHeaders(headers)),
	)

	suite.Require().NoError(err)
	return signed
}

// newJWKServer serves the suite's public key as a single JWK.
func (suite *ProvideSuite) newJWKServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", clortho.MediaTypeJWK)
		_, _ = rw.Write(suite.publicJWK)
	}))
}

func (suite *ProvideSuite) TearDownTest() {
	gock.OffAll()
}

// newFxTest creates a test App using the supplied options
func (suite *ProvideSuite) newFxTest(o ...fx.Option) *fxtest.App {
	app := fxtest.New(
		suite.T(),
		o...,
	)

	suite.Require().NotNil(app)
	suite.Require().NoError(app.Err())
	return app
}

func (suite *ProvideSuite) TestDefaults() {
	var (
		kr        clortho.KeyRing
		resolver  clortho.Resolver
		refresher clortho.Refresher

		app = suite.newFxTest(
			Provide(),
			fx.Populate(
				&kr,
				&resolver,
				&refresher,
			),
		)
	)

	app.RequireStart()

	suite.Require().NotNil(kr)
	suite.Require().NotNil(resolver)
	suite.Require().NotNil(refresher)

	// TODO: how best to test the refresher here?

	key, err := resolver.Resolve(
		clortho.SetContentMeta(context.Background(), clortho.ContentMeta{}),
		"test",
	)

	suite.Nil(key)
	suite.Error(err)

	app.RequireStop()
}

// TestResolverNoTemplate checks the module's Resolver for an application with
// no resolve template configured, which is every refresh-only consumer.  The
// module still provides a Resolver; it serves the ring and reports ErrNoTemplate
// on a miss.
func (suite *ProvideSuite) TestResolverNoTemplate() {
	var (
		kr       clortho.KeyRing
		resolver clortho.Resolver

		app = suite.newFxTest(
			Provide(),
			fx.Populate(&kr, &resolver),
		)
	)

	app.RequireStart()
	defer app.RequireStop()

	key, err := resolver.Resolve(context.Background(), "kid-1")
	suite.Nil(key)
	suite.ErrorIs(err, clortho.ErrNoTemplate)

	kr.Add(suite.publicKey)

	key, err = resolver.Resolve(context.Background(), "kid-1")
	suite.Require().NoError(err)
	suite.Equal(suite.publicKey, key)
}

// TestKeyProvider checks that the module provides a jws.KeyProvider backed by the
// module's key ring.  With no Config the ring is fed by the application, so keys
// added to the ring are immediately usable for verification.
func (suite *ProvideSuite) TestKeyProvider() {
	var (
		kr clortho.KeyRing
		kp jws.KeyProvider

		app = suite.newFxTest(
			Provide(),
			fx.Populate(&kr, &kp),
		)
	)

	app.RequireStart()
	defer app.RequireStop()

	suite.Require().NotNil(kp)

	// nothing in the ring yet
	_, err := jws.Verify(suite.newSignedJWS(), jws.WithKeyProvider(kp))
	suite.ErrorIs(err, clortho.ErrKeyProviderKeyNotFound)

	kr.Add(suite.publicKey)

	payload, err := jws.Verify(suite.newSignedJWS(), jws.WithKeyProvider(kp))
	suite.Require().NoError(err)
	suite.JSONEq(`{"sub":"test"}`, string(payload))
}

// TestKeyProviderNoRefreshSources checks that a Config with a resolve template and
// no refresh sources fails at startup when the provider is injected, rather than
// producing a provider whose ring never fills.
func (suite *ProvideSuite) TestKeyProviderNoRefreshSources() {
	var kp jws.KeyProvider

	app := fx.New(
		fx.NopLogger,
		Provide(),
		fx.Supply(clortho.Config{
			Resolve: clortho.ResolveConfig{Template: "https://example.com/keys/{keyID}"},
		}),
		fx.Populate(&kp),
	)

	suite.Require().Error(app.Err())
	suite.ErrorIs(app.Err(), clortho.ErrNoRefreshSources)
	suite.Nil(kp)
}

// TestKeyProviderWithRefreshSources is the intended production wiring: a Config
// with a refresh source, the refresher filling the ring on start, and the provider
// verifying from it.
func (suite *ProvideSuite) TestKeyProviderWithRefreshSources() {
	server := suite.newJWKServer()
	defer server.Close()

	var (
		kr clortho.KeyRing
		kp jws.KeyProvider

		app = suite.newFxTest(
			Provide(),
			fx.Supply(clortho.Config{
				Refresh: clortho.RefreshConfig{
					Sources: []clortho.RefreshSource{{URI: server.URL + "/keys"}},
				},
			}),
			fx.Populate(&kr, &kp),
		)
	)

	app.RequireStart()
	defer app.RequireStop()

	// the refresher fetches in the background once started
	suite.Require().Eventually(func() bool { return kr.Len() == 1 }, 5*time.Second, 10*time.Millisecond)

	payload, err := jws.Verify(suite.newSignedJWS(), jws.WithKeyProvider(kp))
	suite.Require().NoError(err)
	suite.JSONEq(`{"sub":"test"}`, string(payload))
}

// TestKeyProviderDefaultsApply checks that the module's provider carries the
// core defaults: with no options supplied, a symmetric key on the ring is
// rejected.
func (suite *ProvideSuite) TestKeyProviderDefaultsApply() {
	var (
		kr clortho.KeyRing
		kp jws.KeyProvider

		app = suite.newFxTest(
			Provide(),
			fx.Populate(&kr, &kp),
		)
	)

	app.RequireStart()
	defer app.RequireStop()

	kr.Add(suite.symmetricKey)

	_, err := jws.Verify(suite.newHMACJWS(), jws.WithKeyProvider(kp))
	suite.ErrorIs(err, clortho.ErrKeyProviderSymmetricKey)
}

// TestKeyProviderOptions checks that an application can pass
// clortho.KeyProviderOption values to the module's provider, the same way it can
// pass clortho.FetcherOption values to the fetcher.  Without this, an fx-wired
// deployment that shares a secret through a local file has no way to opt in.
func (suite *ProvideSuite) TestKeyProviderOptions() {
	var (
		kr clortho.KeyRing
		kp jws.KeyProvider

		app = suite.newFxTest(
			Provide(),
			fx.Supply([]clortho.KeyProviderOption{
				clortho.WithAllowSymmetricKeys(),
			}),
			fx.Populate(&kr, &kp),
		)
	)

	app.RequireStart()
	defer app.RequireStop()

	kr.Add(suite.symmetricKey)

	payload, err := jws.Verify(suite.newHMACJWS(), jws.WithKeyProvider(kp))
	suite.Require().NoError(err)
	suite.JSONEq(`{"sub":"test"}`, string(payload))
}

// TestResolverOptions checks that an application can pass clortho.ResolverOption
// values to the module's Resolver, the same way it can for the Fetcher and the
// key provider.  Without this, an fx-wired deployment with key IDs the default
// validator rejects has no way to supply WithKeyIDValidator.
func (suite *ProvideSuite) TestResolverOptions() {
	var (
		resolver  clortho.Resolver
		customErr = errors.New("rejected by the application's validator")

		app = suite.newFxTest(
			Provide(),
			fx.Supply([]clortho.ResolverOption{
				clortho.WithKeyIDValidator(func(string) error { return customErr }),
			}),
			fx.Populate(&resolver),
		)
	)

	app.RequireStart()
	defer app.RequireStop()

	_, err := resolver.Resolve(context.Background(), "kid-1")
	suite.ErrorIs(err, customErr)
}

// TODO: flesh these tests out with gock, possibly using
// an internal package for the common testing code
func TestProvide(t *testing.T) {
	suite.Run(t, new(ProvideSuite))
}
