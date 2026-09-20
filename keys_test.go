// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/suite"
)

type KeysSuite struct {
	suite.Suite
}

func (suite *KeysSuite) TestLess() {
	keys := Keys{
		&key{keyID: "A"},
		&key{},
		&key{keyID: "B"},
	}

	suite.Require().Equal(3, keys.Len())
	suite.True(keys.Less(0, 1))
	suite.True(keys.Less(0, 2))
	suite.False(keys.Less(1, 0))
	suite.False(keys.Less(1, 1))
	suite.False(keys.Less(1, 2))
	suite.False(keys.Less(2, 0))
	suite.True(keys.Less(2, 1))
}

func (suite *KeysSuite) TestSwap() {
	keys := Keys{
		&key{keyID: "A"},
		&key{},
		&key{keyID: "B"},
	}

	suite.Require().Equal(3, keys.Len())
	keys.Swap(0, 1)
	suite.Equal("", keys[0].KeyID())
	suite.Equal("A", keys[1].KeyID())
}

func (suite *KeysSuite) TestAppendKeyIDs() {
	suite.Run("ToNil", func() {
		keyIDs := Keys{
			&key{keyID: "A"},
			&key{keyID: "B"},
		}.AppendKeyIDs(nil)

		suite.Equal([]string{"A", "B"}, keyIDs)
	})

	suite.Run("ToEmpty", func() {
		keyIDs := Keys{
			&key{keyID: "A"},
			&key{keyID: "B"},
		}.AppendKeyIDs([]string{})

		suite.Equal([]string{"A", "B"}, keyIDs)
	})

	suite.Run("ToExisting", func() {
		keyIDs := Keys{
			&key{keyID: "A"},
			&key{keyID: "B"},
		}.AppendKeyIDs([]string{"1", "2"})

		suite.Equal([]string{"1", "2", "A", "B"}, keyIDs)
	})

	suite.Run("FromNil", func() {
		keyIDs := Keys{}.AppendKeyIDs(nil)
		suite.Empty(keyIDs)
	})
}

// TestEnsureKeyIDMarksGenerated checks that a key ID assigned by EnsureKeyID is
// distinguishable from one that came from the source material.  A Resolver
// relies on that to tell "this key has a different kid" from "this key had no
// kid at all".
func (suite *KeysSuite) TestEnsureKeyIDMarksGenerated() {
	p, err := NewParser()
	suite.Require().NoError(err)

	keys, err := p.Parse(MediaTypeJWKSet, []byte(resolverTestKeySet))
	suite.Require().NoError(err)
	suite.Require().Len(keys, 3)

	withoutKid, withKid := keys[0], keys[1]
	suite.Require().Empty(withoutKid.KeyID())
	suite.Require().Equal("testKey", withKid.KeyID())

	updated, err := EnsureKeyID(withoutKid, crypto.SHA256)
	suite.Require().NoError(err)
	suite.NotEmpty(updated.KeyID())
	suite.True(keyIDGenerated(updated), "a thumbprint kid must be marked as generated")

	same, err := EnsureKeyID(withKid, crypto.SHA256)
	suite.Require().NoError(err)
	suite.Same(withKid, same)
	suite.False(keyIDGenerated(same), "a kid from the source must not be marked as generated")
}

func TestKeys(t *testing.T) {
	suite.Run(t, new(KeysSuite))
}
