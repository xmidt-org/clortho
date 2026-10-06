// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Command perkey fetches single keys the way a clortho.PerKeyProvider does and
// prints what it found.  It is for trying clortho against a real server, and
// is meant to be run with go run:
//
//	go run ./cmd/perkey 'https://themis.example.com/keys/{keyID}' docker
//	go run ./cmd/perkey 'https://themis.example.com/keys/{keyID}' docker other
//
// Quote the template, so that the shell leaves the braces alone.  Edit
// newClient to suit the server being tried.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/xmidt-org/clortho"
)

// newClient returns the HTTP client used to reach the server.
//
// ADJUST HERE for the server being tried.  A private CA goes in RootCAs, a
// client certificate in Certificates, and a proxy other than the one the
// environment names in Proxy.
func newClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,

		// A redirect is reported as a failure and not followed, so that it is
		// seen.  Remove this to follow redirects as a browser would.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},

		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				// RootCAs:      pool,
				// Certificates: []tls.Certificate{cert},
			},
		},
	}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/perkey '<url template with {keyID}>' <key ID>...")
		os.Exit(2)
	}

	if err := run(context.Background(), os.Args[1], os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, template string, keyIDs []string) error {
	p, err := clortho.NewPerKeyProvider(clortho.PerKeyConfig{
		Template: template,
		Client:   newClient(),

		// the key IDs on the command line are the ones to fetch, and nothing
		// else is.  listing them also means none waits on the rate limit.
		AllowedKeyIDs:     keyIDs,
		AllowedKeyIDsOnly: true,

		// show every key the server serves, whatever its "use" and "alg" say
		Verify: clortho.VerifyConfig{IgnoreKeyUsage: true, IgnoreKeyAlgorithm: true},
	})
	if err != nil {
		return err
	}

	// each fetch ends in an event that says how it went
	events := make(chan clortho.FetchEvent, len(keyIDs))
	p.AddListener(listener(func(e clortho.FetchEvent) { events <- e }))

	failed, shown := 0, false
	for _, keyID := range keyIDs {
		key, lookupErr := keyFor(ctx, p, keyID)

		// a key ID given twice is already held the second time, and is not
		// fetched again, so there may be no event to wait for
		var fetchErr error
		select {
		case event := <-events:
			if !shown {
				fmt.Printf("template: %s\n\n", event.URI)
				shown = true
			}

			fetchErr = event.Err
		case <-time.After(time.Second):
		}

		switch {
		case fetchErr != nil:
			failed++
			fmt.Printf("key ID %q: the fetch failed: %v\n\n", keyID, fetchErr)

		case lookupErr != nil:
			failed++
			fmt.Printf("key ID %q: %v\n\n", keyID, lookupErr)

		default:
			fmt.Printf("key ID %q\n%s\n\n", keyID, key)
		}
	}

	if failed > 0 {
		return fmt.Errorf("%d of %d key IDs could not be fetched", failed, len(keyIDs))
	}

	return nil
}

type listener func(clortho.FetchEvent)

func (l listener) OnFetchEvent(e clortho.FetchEvent) { l(e) }

// sink receives the key a provider offers for a token.
type sink struct{ key any }

func (s *sink) Key(_ jwa.SignatureAlgorithm, key any) { s.key = key }

// keyFor asks a provider for a key the way jwx does while verifying a token,
// and returns the key as indented JSON.  No real token is needed: a provider
// looks only at the key ID and algorithm in the token's header.
func keyFor(ctx context.Context, provider jws.KeyProvider, keyID string) ([]byte, error) {
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": keyID})
	if err != nil {
		return nil, err
	}

	enc := base64.RawURLEncoding
	token := enc.EncodeToString(header) + "." + enc.EncodeToString([]byte("{}")) + "." + enc.EncodeToString([]byte("none"))
	msg, err := jws.ParseString(token)
	if err != nil {
		return nil, err
	}

	var offered sink
	if err := provider.FetchKeys(ctx, &offered, msg.Signatures()[0], msg); err != nil {
		return nil, err
	}

	return json.MarshalIndent(offered.key, "", "  ")
}
