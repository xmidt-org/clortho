// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"crypto"
	"encoding/base64"
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

// customKey is the smallest Key implementation a custom Parser could return:
// no kid, and a fixed thumbprint.
type customKey struct {
	raw any
}

func (customKey) KeyID() string                          { return "" }
func (customKey) KeyType() string                        { return "custom" }
func (customKey) KeyUsage() string                       { return "" }
func (ck customKey) Raw() any                            { return ck.raw }
func (customKey) Public() crypto.PublicKey               { return nil }
func (customKey) Thumbprint(crypto.Hash) ([]byte, error) { return []byte("thumbprint"), nil }

// TestEnsureKeyIDCustomKey checks that a Key implementation other than the
// package's own is given a kid rather than crashing the process.  From the
// fetcher this runs inside the refresh goroutine, where a panic is unrecovered.
func (suite *KeysSuite) TestEnsureKeyIDCustomKey() {
	original := customKey{raw: "material"}
	suite.False(keyIDGenerated(original), "a key this package never touched has no generated kid")

	var (
		updated Key
		err     error
	)

	suite.Require().NotPanics(func() {
		updated, err = EnsureKeyID(original, crypto.SHA256)
	})

	suite.Require().NoError(err)
	suite.Equal(base64.RawURLEncoding.EncodeToString([]byte("thumbprint")), updated.KeyID())
	suite.True(keyIDGenerated(updated), "the thumbprint kid must be marked as generated")

	// everything but the kid still comes from the original
	suite.Equal("custom", updated.KeyType())
	suite.Equal("material", updated.Raw())

	// and a custom key that already has a kid is returned as is
	withKid := withKeyID(original, "kid-1")
	suite.Equal("kid-1", withKid.KeyID())
	suite.False(keyIDGenerated(withKid))

	same, err := EnsureKeyID(withKid, crypto.SHA256)
	suite.Require().NoError(err)
	suite.Equal(withKid, same)
}

func TestKeys(t *testing.T) {
	suite.Run(t, new(KeysSuite))
}
