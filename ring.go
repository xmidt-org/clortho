// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"fmt"
	"slices"
	"sync"

	"github.com/lestrrat-go/jwx/v4/jwk"
)

// ringEntry is one key on the ring and the index of the source that supplied
// it.  The source is remembered so that a key ID served by two sources is
// detected as a collision rather than silently overwritten, and so that a key
// dropped by its source is removed rather than left behind.
type ringEntry struct {
	key    jwk.Key
	source int
}

// ring is the Provider's cache of keys, one map keyed by key ID.  The zero
// value is ready to use.
type ring struct {
	lock sync.RWMutex
	keys map[string]ringEntry
}

// get returns the key with the given key ID, if any.
func (r *ring) get(keyID string) (jwk.Key, bool) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	entry, ok := r.keys[keyID]
	return entry.key, ok
}

// keyIDs returns every key ID on the ring, sorted.
func (r *ring) keyIDs() []string {
	r.lock.RLock()
	defer r.lock.RUnlock()

	keyIDs := make([]string, 0, len(r.keys))
	for keyID := range r.keys {
		keyIDs = append(keyIDs, keyID)
	}

	slices.Sort(keyIDs)
	return keyIDs
}

// keyIDsFor returns the key IDs on the ring from one source, sorted.
func (r *ring) keyIDsFor(source int) []string {
	r.lock.RLock()
	defer r.lock.RUnlock()

	return r.keyIDsForLocked(source)
}

func (r *ring) keyIDsForLocked(source int) []string {
	var keyIDs []string
	for keyID, entry := range r.keys {
		if entry.source == source {
			keyIDs = append(keyIDs, keyID)
		}
	}

	slices.Sort(keyIDs)
	return keyIDs
}

// apply replaces the set of keys from one source with next.  It returns the
// key IDs now on the ring from that source, the key IDs that were added, and
// the key IDs that were removed, each sorted.
//
// If any key in next carries a key ID that another source supplies, apply
// returns ErrDuplicateKeyID and changes nothing; the key IDs returned are then
// those the source had before.
func (r *ring) apply(source int, next []jwk.Key) (keyIDs, added, deleted []string, err error) {
	r.lock.Lock()
	defer r.lock.Unlock()

	for _, k := range next {
		keyID, _ := k.KeyID()
		if entry, ok := r.keys[keyID]; ok && entry.source != source {
			err = fmt.Errorf("%w: %q", ErrDuplicateKeyID, keyID)
			return r.keyIDsForLocked(source), nil, nil, err
		}
	}

	previous := make(map[string]bool)
	for keyID, entry := range r.keys {
		if entry.source == source {
			previous[keyID] = true
		}
	}

	if r.keys == nil {
		r.keys = make(map[string]ringEntry, len(next))
	}

	for _, k := range next {
		keyID, _ := k.KeyID()
		if !previous[keyID] {
			added = append(added, keyID)
		}

		delete(previous, keyID)
		r.keys[keyID] = ringEntry{key: k, source: source}
	}

	for keyID := range previous {
		deleted = append(deleted, keyID)
		delete(r.keys, keyID)
	}

	slices.Sort(added)
	slices.Sort(deleted)
	return r.keyIDsForLocked(source), added, deleted, nil
}
