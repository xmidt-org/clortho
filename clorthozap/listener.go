/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package clorthozap

import (
	"github.com/xmidt-org/clortho"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Listener is both a clortho.RefreshListener and a clortho.ResolveListener
// that logs information about events via a supplied zap logger.
type Listener struct {
	logger *zap.Logger
}

var _ clortho.RefreshListener = (*Listener)(nil)
var _ clortho.ResolveListener = (*Listener)(nil)

// NewListener constructs a *Listener that outputs to the supplied logger.
func NewListener(l *zap.Logger) *Listener {
	return &Listener{
		logger: l,
	}
}

func (l *Listener) OnRefreshEvent(event clortho.RefreshEvent) {
	level := zapcore.InfoLevel
	if event.Err != nil {
		level = zapcore.ErrorLevel
	}

	ce := l.logger.Check(level, "key refresh")
	if ce == nil {
		return
	}

	// save a couple of allocations by using one big slice for key IDs
	keyIDs := make([]string, 0, event.Keys.Len()+event.New.Len()+event.Deleted.Len())
	for _, k := range event.Keys {
		keyIDs = append(keyIDs, k.KeyID())
	}

	for _, k := range event.New {
		keyIDs = append(keyIDs, k.KeyID())
	}

	for _, k := range event.Deleted {
		keyIDs = append(keyIDs, k.KeyID())
	}

	ce.Write(
		zap.String("uri", event.URI),
		zap.Strings("keys", keyIDs[0:event.Keys.Len()]),
		zap.Strings("new", keyIDs[event.Keys.Len():event.Keys.Len()+event.New.Len()]),
		zap.Strings("deleted", keyIDs[event.Keys.Len()+event.New.Len():]),
		zap.Error(event.Err),
	)
}

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
