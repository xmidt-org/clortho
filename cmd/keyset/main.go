// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

// Command keyset reads one key set the way a clortho.KeySetProvider does and
// prints what it found.  It is for trying clortho against a real server, and
// is meant to be run with go run:
//
//	go run ./cmd/keyset https://issuer.example.com/keys
//	go run ./cmd/keyset /etc/example/keys.json
//
// Edit newClient to suit the server being tried.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
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
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/keyset <url or file>")
		os.Exit(2)
	}

	if err := run(context.Background(), os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, uri string) error {
	// only a source reached over http takes a client
	source := clortho.RefreshSource{URI: uri}
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		source.Client = newClient()
	}

	p, err := clortho.NewKeySetProvider(clortho.KeySetConfig{
		Sources: []clortho.RefreshSource{source},

		// show every key the source serves, whatever its "use" and "alg" say
		Verify: clortho.VerifyConfig{IgnoreKeyUsage: true, IgnoreKeyAlgorithm: true},
	})
	if err != nil {
		return err
	}

	// the first refresh always ends in an event, whether it worked or not
	events := make(chan clortho.RefreshEvent, 1)
	p.AddListener(listener(func(e clortho.RefreshEvent) {
		select {
		case events <- e:
		default:
		}
	}))

	if err := p.Start(ctx); err != nil {
		return err
	}

	defer func() { _ = p.Stop(ctx) }()
	event := <-events

	fmt.Println("source:     ", event.URI)
	if status := p.Status()[0]; status.LastStatusCode != 0 {
		fmt.Println("http status:", status.LastStatusCode)
	}

	if event.Err != nil {
		return fmt.Errorf("the refresh failed: %w", event.Err)
	}

	fmt.Println("key set:    ", event.KeySetBytes, "bytes")
	fmt.Println("keys:       ", len(event.KeyIDs))
	for _, keyID := range event.KeyIDs {
		key, err := keyFor(ctx, p, keyID)
		if err != nil {
			return err
		}

		fmt.Printf("\nkey ID %q\n%s\n", keyID, key)
	}

	return nil
}

type listener func(clortho.RefreshEvent)

func (l listener) OnRefreshEvent(e clortho.RefreshEvent) { l(e) }

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
