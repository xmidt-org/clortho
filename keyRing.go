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

package clortho

import "sync"

// KeyAccessor is a read-only interface to a set of keys.
type KeyAccessor interface {
	// Get returns the Key associated with the given key identifier (kid).
	// If there is no such key, the second return is false.
	Get(keyID string) (Key, bool)
}

// KeyRing is a clientside cache of keys.  Implementations are always
// safe for concurrent access.
type KeyRing interface {
	KeyAccessor
	RefreshListener
}

// NewKeyRing constructs an empty KeyRing.
func NewKeyRing() KeyRing {
	return &keyRing{}
}

type keyRing struct {
	lock sync.RWMutex
	keys map[string]Key
}

func (kr *keyRing) Get(keyID string) (k Key, ok bool) {
	kr.lock.RLock()
	k, ok = kr.keys[keyID]
	kr.lock.RUnlock()
	return
}

func (kr *keyRing) OnRefreshEvent(event RefreshEvent) {
	// TODO
}
