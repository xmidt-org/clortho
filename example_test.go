// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho_test

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/xmidt-org/clortho"
)

// A source reached over http or https must be given the client to reach it
// with, and clortho uses that client exactly as given.  This one is a sound
// starting point for fetching keys.
func ExampleNew() {
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

	p, err := clortho.New(clortho.Config{
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
// rejected when the Provider is built, not when the first refresh fails.
func ExampleNew_missingClient() {
	_, err := clortho.New(clortho.Config{
		Sources: []clortho.RefreshSource{{URI: "https://issuer.example.com/keys"}},
	})

	fmt.Println(errors.Is(err, clortho.ErrMissingClient))
	fmt.Println(err)

	// Output:
	// true
	// an http or https source requires a Client: "https://issuer.example.com/keys"
}
