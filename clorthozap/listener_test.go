// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthozap

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xmidt-org/clortho"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

// errorListenerOption is a ListenerOption that returns an error, since no
// real option can fail.
type errorListenerOption struct {
	err error
}

func (elo errorListenerOption) applyToListener(*Listener) error { return elo.err }

// observed returns a logger that records entries at or above level.
func observed(level zapcore.Level) (*zap.Logger, *observer.ObservedLogs) {
	core, logs := observer.New(level)
	return zap.New(core), logs
}

// fields flattens an entry's fields into a map for assertions.  Arrays come
// back as []any and an error as its message.
func fields(entry observer.LoggedEntry) map[string]any {
	return entry.ContextMap()
}

func TestNewListenerDefaults(t *testing.T) {
	l, err := NewListener()
	require.NoError(t, err)
	require.NotNil(t, l)
	assert.NotNil(t, l.logger)
	assert.Equal(t, zap.InfoLevel, l.level)
}

func TestNewListenerOptionError(t *testing.T) {
	expected := errors.New("expected")
	l, err := NewListener(errorListenerOption{err: expected})
	assert.Nil(t, l)
	assert.ErrorIs(t, err, expected)
}

func TestOnRefreshEventSuccess(t *testing.T) {
	logger, logs := observed(zapcore.InfoLevel)
	l, err := NewListener(WithLogger(logger))
	require.NoError(t, err)

	l.OnRefreshEvent(clortho.RefreshEvent{
		URI:           "https://keys.example.com/jwks",
		KeyIDs:        []string{"a", "b", "c"},
		NewKeyIDs:     []string{"c"},
		DeletedKeyIDs: []string{"z"},
	})

	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.InfoLevel, entry.Level)
	assert.Equal(t, "key refresh", entry.Message)
	f := fields(entry)
	assert.Equal(t, "https://keys.example.com/jwks", f["uri"])
	assert.Equal(t, []any{"a", "b", "c"}, f["keyIDs"])
	assert.Equal(t, []any{"c"}, f["new"])
	assert.Equal(t, []any{"z"}, f["deleted"])
	assert.Nil(t, f["error"])
}

func TestOnRefreshEventCustomLevel(t *testing.T) {
	logger, logs := observed(zapcore.DebugLevel)
	l, err := NewListener(WithLogger(logger), WithLevel(zapcore.DebugLevel))
	require.NoError(t, err)

	l.OnRefreshEvent(clortho.RefreshEvent{URI: "https://keys.example.com/jwks"})

	require.Equal(t, 1, logs.Len())
	assert.Equal(t, zapcore.DebugLevel, logs.All()[0].Level)
}

func TestOnRefreshEventError(t *testing.T) {
	logger, logs := observed(zapcore.ErrorLevel)
	l, err := NewListener(WithLogger(logger), WithLevel(zapcore.DebugLevel))
	require.NoError(t, err)

	expected := errors.New("expected")
	l.OnRefreshEvent(clortho.RefreshEvent{
		URI:    "https://keys.example.com/jwks",
		Err:    expected,
		KeyIDs: []string{"a"},
	})

	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, zapcore.ErrorLevel, entry.Level, "a failure is always an error entry")
	f := fields(entry)
	assert.Equal(t, expected.Error(), f["error"])
	assert.Equal(t, []any{"a"}, f["keyIDs"])
}

func TestOnRefreshEventDisabled(t *testing.T) {
	logger, logs := observed(zapcore.PanicLevel)
	l, err := NewListener(WithLogger(logger))
	require.NoError(t, err)

	l.OnRefreshEvent(clortho.RefreshEvent{URI: "https://keys.example.com/jwks"})
	assert.Zero(t, logs.Len())
}
