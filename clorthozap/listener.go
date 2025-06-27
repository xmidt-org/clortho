// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthozap

import (
	"github.com/xmidt-org/clortho"
	"go.uber.org/multierr"
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

// WithLevel sets the log level for non-error events.  By default, key refresh
// and resolve events are logged at INFO level.
//
// Errors are always logged at ERROR level.  Error events are not controlled
// by this option.
func WithLevel(level zapcore.Level) ListenerOption {
	return listenerOptionFunc(func(l *Listener) error {
		l.level = level
		return nil
	})
}

// Listener is both a clortho.RefreshListener and a clortho.ResolveListener
// that logs information about events via a supplied zap logger.
type Listener struct {
	logger *zap.Logger
	level  zapcore.Level
}

var _ clortho.RefreshListener = (*Listener)(nil)
var _ clortho.ResolveListener = (*Listener)(nil)

// NewListener constructs a *Listener that outputs to the supplied logger.
func NewListener(options ...ListenerOption) (l *Listener, err error) {
	l = &Listener{
		level: zap.InfoLevel,
	}

	for _, o := range options {
		err = multierr.Append(err, o.applyToListener(l))
	}

	if l.logger == nil {
		l.logger = zap.L()
	}

	if err != nil {
		l = nil
	}

	return
}

// OnRefreshEvent outputs structured logging about the event to the logger
// established via WithLogger when this listener was created.
func (l *Listener) OnRefreshEvent(event clortho.RefreshEvent) {
	level := l.level
	if event.Err != nil {
		level = zapcore.ErrorLevel
	}

	ce := l.logger.Check(level, "key refresh")
	if ce == nil {
		return
	}

	// save a couple of allocations by using one big slice for key IDs
	keyIDs := make([]string, 0, event.Keys.Len()+event.New.Len()+event.Deleted.Len())
	keyIDs = event.Keys.AppendKeyIDs(keyIDs)
	keyIDs = event.New.AppendKeyIDs(keyIDs)
	keyIDs = event.Deleted.AppendKeyIDs(keyIDs)

	ce.Write(
		zap.String("uri", event.URI),
		zap.Strings("keys", keyIDs[0:event.Keys.Len()]),
		zap.Strings("new", keyIDs[event.Keys.Len():event.Keys.Len()+event.New.Len()]),
		zap.Strings("deleted", keyIDs[event.Keys.Len()+event.New.Len():]),
		zap.Error(event.Err),
	)
}

// OnResolveEvent outputs structured logging about the event to the logger
// established via WithLogger when this listener was created.
func (l *Listener) OnResolveEvent(event clortho.ResolveEvent) {
	level := zapcore.InfoLevel
	if event.Err != nil {
		level = zapcore.ErrorLevel
	}

	ce := l.logger.Check(level, "key resolve")
	if ce == nil {
		return
	}

	ce.Write(
		zap.String("uri", event.URI),
		zap.String("keyID", event.KeyID),
		zap.Error(event.Err),
	)
}
