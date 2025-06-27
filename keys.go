// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

// Keys is a sortable slice of Key instances.  Sorting is done
// by keyID, ascending.  Keys with no keyID are sorted after those
// that have a keyID.
type Keys []Key

// AppendKeyIDs appends the key Id of each key to the supplied slice,
// then returns the result.
func (ks Keys) AppendKeyIDs(v []string) []string {
	if cap(v) < len(v)+len(ks) {
		// reduce the number of allocations
		v = append(
			make([]string, 0, len(v)+len(ks)),
			v...,
		)
	}

	for _, k := range ks {
		v = append(v, k.KeyID())
	}

	return v
}

// Len returns the count of Key instances in this collection.
func (ks Keys) Len() int {
	return len(ks)
}

// Less tests if the Key at i is less than the one at j.
func (ks Keys) Less(i, j int) bool {
	left, right := ks[i].KeyID(), ks[j].KeyID()
	switch {
	case len(left) == 0:
		return false
	case len(right) == 0:
		return true
	default:
		return left < right
	}
}

// Swap switches the positions of the Keys at i and j.
func (ks Keys) Swap(i, j int) {
	ks[i], ks[j] = ks[j], ks[i]
}
