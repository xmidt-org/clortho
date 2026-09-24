// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ringKeys(t *testing.T, kids ...string) []jwk.Key {
	rsaKey, _ := testPrivateKeys(t)
	keys := make([]jwk.Key, 0, len(kids))
	for _, kid := range kids {
		keys = append(keys, publicJWK(t, rsaKey, kid, nil))
	}

	return keys
}

func TestRingIsEmptyToStartWith(t *testing.T) {
	var r ring
	_, ok := r.get("anything")
	assert.False(t, ok)
	assert.Empty(t, r.keyIDs())
	assert.Empty(t, r.keyIDsFor(0))
}

func TestRingApplyAddsKeys(t *testing.T) {
	var r ring
	kids, added, deleted, err := r.apply(0, ringKeys(t, "b", "a"))
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, kids)
	assert.Equal(t, []string{"a", "b"}, added)
	assert.Empty(t, deleted)

	k, ok := r.get("a")
	assert.True(t, ok)
	kid, _ := k.KeyID()
	assert.Equal(t, "a", kid)
	assert.Equal(t, []string{"a", "b"}, r.keyIDs())
}

func TestRingApplyReportsOnlyChanges(t *testing.T) {
	var r ring
	_, _, _, err := r.apply(0, ringKeys(t, "a", "b"))
	require.NoError(t, err)

	kids, added, deleted, err := r.apply(0, ringKeys(t, "b", "c"))
	require.NoError(t, err)
	assert.Equal(t, []string{"b", "c"}, kids)
	assert.Equal(t, []string{"c"}, added)
	assert.Equal(t, []string{"a"}, deleted)

	_, ok := r.get("a")
	assert.False(t, ok)
	assert.Equal(t, []string{"b", "c"}, r.keyIDs())
}

func TestRingApplyReplacesAKeyUnderTheSameKeyID(t *testing.T) {
	var r ring
	_, ec := testPrivateKeys(t)
	_, _, _, err := r.apply(0, ringKeys(t, "a"))
	require.NoError(t, err)

	replacement := publicJWK(t, ec, "a", nil)
	kids, added, deleted, err := r.apply(0, []jwk.Key{replacement})
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, kids)
	assert.Empty(t, added)
	assert.Empty(t, deleted)

	k, _ := r.get("a")
	assert.Equal(t, replacement.KeyType(), k.KeyType())
}

func TestRingApplyEmptyRemovesEverythingFromThatSource(t *testing.T) {
	var r ring
	_, _, _, err := r.apply(0, ringKeys(t, "a"))
	require.NoError(t, err)
	_, _, _, err = r.apply(1, ringKeys(t, "b"))
	require.NoError(t, err)

	kids, added, deleted, err := r.apply(0, nil)
	require.NoError(t, err)
	assert.Empty(t, kids)
	assert.Empty(t, added)
	assert.Equal(t, []string{"a"}, deleted)
	assert.Equal(t, []string{"b"}, r.keyIDs())
}

func TestRingKeyIDsForReportsOneSource(t *testing.T) {
	var r ring
	_, _, _, err := r.apply(0, ringKeys(t, "a", "c"))
	require.NoError(t, err)
	_, _, _, err = r.apply(1, ringKeys(t, "b"))
	require.NoError(t, err)

	assert.Equal(t, []string{"a", "c"}, r.keyIDsFor(0))
	assert.Equal(t, []string{"b"}, r.keyIDsFor(1))
	assert.Equal(t, []string{"a", "b", "c"}, r.keyIDs())
}

func TestRingApplyRejectsAKeyIDAnotherSourceSupplies(t *testing.T) {
	var r ring
	_, _, _, err := r.apply(0, ringKeys(t, "a"))
	require.NoError(t, err)
	_, _, _, err = r.apply(1, ringKeys(t, "b"))
	require.NoError(t, err)

	kids, added, deleted, err := r.apply(1, ringKeys(t, "a", "d"))
	assert.ErrorIs(t, err, ErrDuplicateKeyID)
	assert.ErrorContains(t, err, `"a"`)
	assert.Equal(t, []string{"b"}, kids, "the ring must be untouched")
	assert.Empty(t, added)
	assert.Empty(t, deleted)
	assert.Equal(t, []string{"a", "b"}, r.keyIDs())
}

func TestRingApplyLetsASourceResupplyItsOwnKeyIDs(t *testing.T) {
	var r ring
	_, _, _, err := r.apply(0, ringKeys(t, "a"))
	require.NoError(t, err)

	kids, added, deleted, err := r.apply(0, ringKeys(t, "a"))
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, kids)
	assert.Empty(t, added)
	assert.Empty(t, deleted)
}

func TestRingApplyAllowsAKeyIDToMoveOnceItsSourceDropsIt(t *testing.T) {
	var r ring
	_, _, _, err := r.apply(0, ringKeys(t, "a"))
	require.NoError(t, err)
	_, _, _, err = r.apply(0, nil)
	require.NoError(t, err)

	kids, added, _, err := r.apply(1, ringKeys(t, "a"))
	require.NoError(t, err)
	assert.Equal(t, []string{"a"}, kids)
	assert.Equal(t, []string{"a"}, added)
}
