// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthozap

import (
	"errors"

	"github.com/xmidt-org/clortho"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// ListenerOption is a configurable option passed to NewListener that
// can tailor the created Listener.
type ListenerOption interface {
	applyToListener(*Listener) error
}

type listenerOptionFunc func(*Listener) error

func (lof listenerOptionFunc) applyToListener(l *Listener) error {
	return lof(l)
}

// WithLogger establishes the zap Logger instance that receives output.
// By default, a Listener will use the default logger returned by zap.L().
func WithLogger(logger *zap.Logger) ListenerOption {
	return listenerOptionFunc(func(l *Listener) error {
		l.logger = logger
		return nil
	})
}

// WithLevel sets the log level for successful refreshes and fetches.  By
// default, they are logged at INFO level.
//
// A failed refresh or fetch is always logged at ERROR level, regardless of
// this option.
func WithLevel(level zapcore.Level) ListenerOption {
	return listenerOptionFunc(func(l *Listener) error {
		l.level = level
		return nil
	})
}

// Listener logs what clortho's providers do via a zap logger.  It is a
// clortho.Listener, for the refreshes of a KeySetProvider, and a
// clortho.FetchListener, for the fetches of a PerKeyProvider.  Events carry
// key IDs only, so nothing logged here is key material.
type Listener struct {
	logger *zap.Logger
	level  zapcore.Level
}

var (
	_ clortho.Listener      = (*Listener)(nil)
	_ clortho.FetchListener = (*Listener)(nil)
)

// NewListener constructs a *Listener that outputs to the supplied logger.
func NewListener(options ...ListenerOption) (l *Listener, err error) {
	l = &Listener{
		level: zap.InfoLevel,
	}

	errs := make([]error, 0, len(options))
	for _, o := range options {
		errs = append(errs, o.applyToListener(l))
	}

	if l.logger == nil {
		l.logger = zap.L()
	}

	if err = errors.Join(errs...); err != nil {
		l = nil
	}

	return
}

// OnRefreshEvent logs the outcome of one refresh: the source, the key IDs it
// now supplies, what was added and removed, and the error if it failed.
func (l *Listener) OnRefreshEvent(event clortho.RefreshEvent) {
	level := l.level
	if event.Err != nil {
		level = zapcore.ErrorLevel
	}

	ce := l.logger.Check(level, "key refresh")
	if ce == nil {
		return
	}

	ce.Write(
		zap.String("uri", event.URI),
		zap.Strings("keyIDs", event.KeyIDs),
		zap.Strings("new", event.NewKeyIDs),
		zap.Strings("deleted", event.DeletedKeyIDs),
		zap.Error(event.Err),
	)
}

// OnFetchEvent logs the outcome of one fetch by a PerKeyProvider: the
// provider's URL template, the key ID that was asked for, and the error if it
// failed.  The key ID comes from a token that had not been verified.  It has
// passed the check on what a key ID may hold, and how often one is logged is
// bounded by the provider's limits on fetching.
func (l *Listener) OnFetchEvent(event clortho.FetchEvent) {
	level := l.level
	if event.Err != nil {
		level = zapcore.ErrorLevel
	}

	ce := l.logger.Check(level, "key fetch")
	if ce == nil {
		return
	}

	ce.Write(
		zap.String("uri", event.URI),
		zap.String("keyID", event.KeyID),
		zap.Error(event.Err),
	)
}
