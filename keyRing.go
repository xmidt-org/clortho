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

	// Len returns the number of keys currently in this ring.
	Len() int
}

// KeyRing is a clientside cache of keys.  Implementations are always
// safe for concurrent access.
type KeyRing interface {
	KeyAccessor
	RefreshListener
}

// NewKeyRing constructs an empty KeyRing.
func NewKeyRing() KeyRing {
	return &keyRing{
		keys: map[string]Key{},
	}
}

// keyRing is the internal KeyRing implementation.
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

func (kr *keyRing) Len() (n int) {
	kr.lock.RLock()
	n = len(kr.keys)
	kr.lock.RUnlock()
	return
}

func (kr *keyRing) OnRefreshEvent(event RefreshEvent) {
	// check if this event represents an actual change to the set of keys
	if event.Err != nil || (len(event.New) == 0 && len(event.Deleted) == 0) {
		return
	}

	kr.lock.Lock()
	defer kr.lock.Unlock()

	// reinsert all keys, not just new ones, so that we pick up any changed
	// private key attributes
	for _, key := range event.Keys {
		keyID := key.KeyID()
		if len(keyID) > 0 {
			kr.keys[keyID] = key
		}
	}

	for _, key := range event.Deleted {
		keyID := key.KeyID()
		delete(kr.keys, keyID)
	}
}
