package clortho

import (
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

func TestKeys(t *testing.T) {
	suite.Run(t, new(KeysSuite))
}
