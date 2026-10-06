// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/xmidt-org/clortho"
)

// A source reached over http or https must be given the client to reach it
// with, and clortho uses that client exactly as given.  This one is a sound
// starting point for fetching keys.
func ExampleNewKeySetProvider() {
	client := &http.Client{
		// Bound the whole exchange.  Without a timeout, a key set server that
		// stops answering stalls the refresh, and with RefreshOnUnknownKeyID
		// on it also holds every request that is waiting for that refresh.
		Timeout: 30 * time.Second,

		// Do not follow redirects. (do not add this to allow redirects)
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},

		// Give the client a transport of its own.  http.DefaultTransport is
		// shared by the whole process, and anything in it can change it.
		Transport: &http.Transport{
			// Decide on purpose whether a proxy applies.  Leaving Proxy nil
			// means none, even when the environment names one; use
			// http.ProxyFromEnvironment to honor the environment.
			Proxy: nil,

			// The trust settings for the key set server belong here: a floor
			// on the TLS version, and a private CA or a client certificate
			// when the server calls for them.
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}

	p, err := clortho.NewKeySetProvider(clortho.KeySetConfig{
		Sources: []clortho.RefreshSource{
			{URI: "https://issuer.example.com/keys", Client: client},

			// A file source takes no client, and giving it one is an error.
			{URI: "/etc/example/keys.json"},
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, status := range p.Status() {
		fmt.Println(status.URI)
	}

	// Output:
	// https://issuer.example.com/keys
	// /etc/example/keys.json
}

// There is no default client.  An http or https source without one is
// rejected when the KeySetProvider is built, not when the first refresh fails.
func ExampleNewKeySetProvider_missingClient() {
	_, err := clortho.NewKeySetProvider(clortho.KeySetConfig{
		Sources: []clortho.RefreshSource{{URI: "https://issuer.example.com/keys"}},
	})

	fmt.Println(errors.Is(err, clortho.ErrMissingClient))
	fmt.Println(err)

	// Output:
	// true
	// an http or https source requires a Client: "https://issuer.example.com/keys"
}

// A service that takes keys from more than one place builds a provider for
// each and gives them all to jwx, which asks them in the order given.  The
// three kinds can be mixed, and there can be several of any of them.
func Example() {
	client := &http.Client{Timeout: 30 * time.Second}

	// A key written into this service's own configuration.
	fixed, err := clortho.NewFixedKeyProvider(clortho.FixedKeyConfig{
		Keys: []clortho.FixedKey{{KeyID: "break-glass", Key: examplePEM}},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// A server that publishes its keys as a set.
	keySets, err := clortho.NewKeySetProvider(clortho.KeySetConfig{
		Sources: []clortho.RefreshSource{
			{URI: "https://issuer.example.com/keys", Client: client},
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Two servers that each serve one key per request.
	themis, err := clortho.NewPerKeyProvider(clortho.PerKeyConfig{
		Template: "https://themis.example.com/keys/{keyID}",
		Client:   client,

		// This service knows every key themis has, so no other key ID is
		// ever asked for.
		AllowedKeyIDs:     []string{"themis-2026"},
		AllowedKeyIDsOnly: true,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	partner, err := clortho.NewPerKeyProvider(clortho.PerKeyConfig{
		Template: "https://keys.partner.example.net/{keyID}/key.json",
		Client:   client,
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// jwx asks the providers in this order and stops at the first key that
	// verifies the token.  The two kinds that a token cannot make send a
	// request go first, and the per-key providers last.
	options := []jws.VerifyOption{
		jws.WithKeyProvider(fixed),
		jws.WithKeyProvider(keySets),
		jws.WithKeyProvider(themis),
		jws.WithKeyProvider(partner),
	}

	// Verifying a token is then jws.Verify(token, options...).  A service
	// using bascule passes the same providers to its token parser instead,
	// each as a jwt.WithKeyProvider option.
	fmt.Println(len(options), "providers")

	// Output:
	// 4 providers
}

// A PerKeyProvider fetches each key from a server that serves one key per
// request, at the URL the template gives for that key's ID.
func ExampleNewPerKeyProvider() {
	p, err := clortho.NewPerKeyProvider(clortho.PerKeyConfig{
		// {keyID} is replaced by the key ID a token names.
		Template: "https://themis.example.com/keys/{keyID}",

		// The client is required, as it is for a KeySetProvider, and the
		// example on NewKeySetProvider shows how to build a good one.
		Client: &http.Client{Timeout: 30 * time.Second},

		// A key ID comes from a token nobody has verified yet.  Listing the
		// ones this service expects means those can always be fetched, even
		// while a flood of invented key IDs is using up the limit that
		// applies to every other.
		AllowedKeyIDs: []string{"themis-2026", "themis-2027"},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Nothing is fetched until a token asks, so nothing is held yet.
	fmt.Println(len(p.KeyIDs()), "keys held")

	// Output:
	// 0 keys held
}

// The key ID goes into a URL, so the template may only put it where it cannot
// change which server is asked.
func ExampleNewPerKeyProvider_templateInTheServerName() {
	_, err := clortho.NewPerKeyProvider(clortho.PerKeyConfig{
		Template: "https://{keyID}.example.com/keys",
		Client:   &http.Client{Timeout: 30 * time.Second},
	})

	fmt.Println(errors.Is(err, clortho.ErrInvalidTemplate))

	// Output:
	// true
}

// examplePEM and exampleJWK are the same public key, written the two ways a
// fixed key may be.
const (
	examplePEM = `
		-----BEGIN PUBLIC KEY-----
		MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/TjDSjYqcGZtvtmV+gjGmdLqO03q
		XmnwqIK24dVkPClST1e1NM7fxHBy/CwPKk/ZXxbFSdgFjGGO3kr+wcGIpA==
		-----END PUBLIC KEY-----`

	exampleJWK = `{
		"kty": "EC",
		"crv": "P-256",
		"x": "_TjDSjYqcGZtvtmV-gjGmdLqO03qXmnwqIK24dVkPCk",
		"y": "Uk9XtTTO38RwcvwsDypP2V8WxUnYBYxhjt5K_sHBiKQ"
	}`
)

// A FixedKeyProvider serves keys written into the service's own
// configuration.  A key may be PEM or a JWK, and each is given the key ID that
// tokens will name it by.
func ExampleNewFixedKeyProvider() {
	p, err := clortho.NewFixedKeyProvider(clortho.FixedKeyConfig{
		Keys: []clortho.FixedKey{
			// PEM has nowhere to say what its key ID is, so KeyID says it.
			{KeyID: "2026", Key: examplePEM},

			// A JWK may carry a kid of its own.  If it does, it must match.
			{KeyID: "2027", Key: exampleJWK},
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Nothing is ever fetched: the keys are held from the start.
	fmt.Println(p.KeyIDs())

	// Output:
	// [2026 2027]
}

// A key that cannot be used is refused when the provider is built, and the
// error says which key without quoting it.
func ExampleNewFixedKeyProvider_symmetricKey() {
	_, err := clortho.NewFixedKeyProvider(clortho.FixedKeyConfig{
		Keys: []clortho.FixedKey{
			{KeyID: "shared", Key: `{"kty":"oct","k":"c2VjcmV0"}`},
		},
	})

	fmt.Println(errors.Is(err, clortho.ErrSymmetricKey))
	fmt.Println(err)

	// Output:
	// true
	// fixed key 0, "shared": symmetric keys are not accepted: "shared"
}
