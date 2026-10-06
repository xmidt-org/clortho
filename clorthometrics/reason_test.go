// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthometrics

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/clortho"
)

func TestReason(t *testing.T) {
	// the error jwx really returns for a body that is not a key set
	_, parseErr := jwk.Parse([]byte(`<html>down for maintenance</html>`))
	require.Error(t, parseErr)

	// the error the file system really returns for a missing file
	_, statErr := os.Stat(filepath.Join(t.TempDir(), "absent.json"))
	require.Error(t, statErr)

	tests := []struct {
		name     string
		err      error
		expected string
	}{
		{"too large", fmt.Errorf("%w: 2 MiB", clortho.ErrResponseTooLarge), "too_large"},
		{"symmetric key", fmt.Errorf("%w: %q", clortho.ErrSymmetricKey, "shared"), "symmetric_key"},
		{"missing key ID", fmt.Errorf("%w: key 0", clortho.ErrMissingKeyID), "missing_key_id"},
		{"duplicate key ID", fmt.Errorf("%w: %q", clortho.ErrDuplicateKeyID, "a"), "duplicate_key_id"},
		{"key ID mismatch", fmt.Errorf("%w: asked for a", clortho.ErrKeyIDMismatch), "key_id_mismatch"},
		{
			"several faults report the first in order",
			errors.Join(fmt.Errorf("%w: key 0", clortho.ErrMissingKeyID), fmt.Errorf("%w: %q", clortho.ErrSymmetricKey, "shared")),
			"symmetric_key",
		},
		{"429", &clortho.HTTPError{StatusCode: http.StatusTooManyRequests}, "http_429"},
		{"503", &clortho.HTTPError{StatusCode: http.StatusServiceUnavailable}, "http_503"},
		{"404, wrapped", fmt.Errorf("refresh: %w", &clortho.HTTPError{StatusCode: http.StatusNotFound}), "http_404"},
		{"a status HTTP does not define", &clortho.HTTPError{StatusCode: 42}, "http_other"},
		{"another status HTTP does not define", &clortho.HTTPError{StatusCode: 600}, "http_other"},
		{"no response", &url.Error{Op: "Get", URL: "https://keys.example.com", Err: errors.New("connection refused")}, "unreachable"},
		{"timeout", context.DeadlineExceeded, "unreachable"},
		{"missing file", statErr, "unreadable_file"},
		{"path error", &fs.PathError{Op: "open", Path: "keys.json", Err: fs.ErrPermission}, "unreadable_file"},
		{"not a key set", parseErr, "unparseable"},
		{"anything else", errors.New("something else"), "other"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, reason(test.err))
		})
	}
}

// refreshError runs a real KeySetProvider against a source and returns the
// error of its first refresh, so that reason is checked against what clortho
// actually reports and not only against errors built by hand.
func refreshError(t *testing.T, source clortho.RefreshSource) error {
	// only a source reached over http takes a client
	if strings.HasPrefix(source.URI, "http") {
		source.Client = &http.Client{Timeout: 5 * time.Second}
	}
	p, err := clortho.NewKeySetProvider(clortho.KeySetConfig{Sources: []clortho.RefreshSource{source}})
	require.NoError(t, err)

	events := make(chan clortho.RefreshEvent, 1)
	p.AddListener(listenerFunc(func(e clortho.RefreshEvent) {
		select {
		case events <- e:
		default:
		}
	}))

	require.NoError(t, p.Start(context.Background()))
	defer func() { _ = p.Stop(context.Background()) }()

	e := <-events
	require.Error(t, e.Err)
	return e.Err
}

type listenerFunc func(clortho.RefreshEvent)

func (f listenerFunc) OnRefreshEvent(e clortho.RefreshEvent) { f(e) }

func TestReasonForTheErrorsAProviderReports(t *testing.T) {
	serve := func(status int, body string) string {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		}))
		t.Cleanup(server.Close)
		return server.URL
	}

	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()

	tests := []struct {
		name     string
		source   clortho.RefreshSource
		expected string
	}{
		{"too large", clortho.RefreshSource{URI: serve(http.StatusOK, `{"keys":[]}`), MaxResponseBytes: 4}, "too_large"},
		{"symmetric key", clortho.RefreshSource{URI: serve(http.StatusOK, `{"keys":[{"kty":"oct","k":"c2VjcmV0","kid":"shared"}]}`)}, "symmetric_key"},
		{"missing key ID", clortho.RefreshSource{URI: serve(http.StatusOK, `{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`)}, "missing_key_id"},
		{"service unavailable", clortho.RefreshSource{URI: serve(http.StatusServiceUnavailable, "")}, "http_503"},
		{"not a key set", clortho.RefreshSource{URI: serve(http.StatusOK, `<html>down for maintenance</html>`)}, "unparseable"},
		{"nothing listening", clortho.RefreshSource{URI: closed.URL}, "unreachable"},
		{"missing file", clortho.RefreshSource{URI: filepath.Join(t.TempDir(), "absent.json")}, "unreadable_file"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, reason(refreshError(t, test.source)))
		})
	}
}

func TestReasonForTheErrorsAPerKeyProviderReports(t *testing.T) {
	// one key per request, as themis serves them; each key ID gets a different fault
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/keys/") {
		case "symmetric":
			_, _ = w.Write([]byte(`{"kty":"oct","k":"c2VjcmV0"}`))
		case "another":
			_, _ = w.Write([]byte(`{"kty":"oct","k":"c2VjcmV0","kid":"not-what-was-asked-for"}`))
		case "mismatch":
			_, _ = w.Write([]byte(`{"kty":"EC","crv":"P-256","kid":"other","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}`))
		case "page":
			_, _ = w.Write([]byte(`<html>down for maintenance</html>`))
		case "busy":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	tests := []struct {
		keyID    string
		expected string
	}{
		{"missing", "http_404"},
		{"busy", "http_503"},
		{"symmetric", "symmetric_key"},
		{"another", "symmetric_key"},
		{"mismatch", "key_id_mismatch"},
		{"page", "unparseable"},
	}

	for _, test := range tests {
		t.Run(test.keyID, func(t *testing.T) {
			p, err := clortho.NewPerKeyProvider(clortho.PerKeyConfig{
				Template:      server.URL + "/keys/{keyID}",
				Client:        &http.Client{Timeout: 5 * time.Second},
				AllowedKeyIDs: []string{test.keyID},
			})
			require.NoError(t, err)

			events := make(chan clortho.FetchEvent, 1)
			p.AddListener(fetchListenerFunc(func(e clortho.FetchEvent) { events <- e }))

			// what the lookup returns is not the point; the fetch error is
			_, _ = jws.Verify([]byte(tokenNaming(test.keyID)), jws.WithKeyProvider(p))

			e := <-events
			require.Error(t, e.Err)
			assert.Equal(t, test.expected, reason(e.Err))
		})
	}
}

type fetchListenerFunc func(clortho.FetchEvent)

func (f fetchListenerFunc) OnFetchEvent(e clortho.FetchEvent) { f(e) }

// tokenNaming returns a compact JWS whose header names a key ID.  Its
// signature is not valid, which does not matter: the key is looked up first.
func tokenNaming(keyID string) string {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","kid":"` + keyID + `"}`))
	return header + "." + enc.EncodeToString([]byte("payload")) + "." + enc.EncodeToString([]byte("signature"))
}
