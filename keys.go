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

// Keys is a sortable slice of Key instances.  Sorting is done
// by keyID, ascending.  Keys with no keyID are sorted after those
// that have a keyID.
type Keys []Key

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
