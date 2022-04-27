package clortho

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/suite"
)

type KeyRingSuite struct {
	suite.Suite
}

func (suite *KeyRingSuite) assertHasKeys(kr KeyRing, keyIDs ...string) {
	for _, keyID := range keyIDs {
		k, ok := kr.Get(keyID)
		suite.NotNil(k)
		suite.True(ok)
		suite.Equal(keyID, k.KeyID())
	}
}

func (suite *KeyRingSuite) newStubKeys(keyIDs ...string) (keys []Key) {
	keys = make([]Key, 0, len(keyIDs))
	for _, keyID := range keyIDs {
		keys = append(keys, &key{keyID: keyID})
	}

	return
}

func (suite *KeyRingSuite) newKeyRing(initialKeyIDs ...string) (kr KeyRing) {
	keys := suite.newStubKeys(initialKeyIDs...)
	kr = NewKeyRing(keys...)
	for _, keyID := range initialKeyIDs {
		k, ok := kr.Get(keyID)
		if len(keyID) > 0 {
			suite.Require().NotNil(k)
			suite.Require().True(ok)
			suite.Require().Equal(keyID, k.KeyID())
		} else {
			suite.Require().Nil(k)
			suite.Require().False(ok)
		}
	}

	return
}

func (suite *KeyRingSuite) TestEmpty() {
	kr := suite.newKeyRing()
	suite.Zero(kr.Len())
}

func (suite *KeyRingSuite) TestInitialKeys() {
	kr := suite.newKeyRing("A", "", "B")
	suite.Equal(2, kr.Len()) // the key with no key id should have been skipped
}

func (suite *KeyRingSuite) TestAddRemove() {
	kr := suite.newKeyRing("A", "B")
	suite.Equal(2, kr.Add(suite.newStubKeys("C", "D")...))
	suite.Equal(4, kr.Len())

	suite.Equal(2, kr.Remove("B", "D"))
	suite.Equal(2, kr.Len())

	suite.Equal(2, kr.Add(suite.newStubKeys("E", "", "F")...))
	suite.Equal(4, kr.Len())

	suite.Equal(0, kr.Remove("nosuch", ""))
	suite.Equal(4, kr.Len())

	suite.Equal(1, kr.Remove("A"))
	suite.Equal(3, kr.Len())
}

func (suite *KeyRingSuite) TestOnRefreshEvent() {
	kr := suite.newKeyRing()

	kr.OnRefreshEvent(RefreshEvent{})
	suite.Zero(kr.Len())

	kr.OnRefreshEvent(RefreshEvent{
		Keys: suite.newStubKeys("A", "B", ""),
	})
	suite.Equal(2, kr.Len())

	kr.OnRefreshEvent(RefreshEvent{
		Keys:    suite.newStubKeys("A", "C", ""),
		Deleted: suite.newStubKeys("B", ""),
	})
	suite.Equal(2, kr.Len())

	kr.OnRefreshEvent(RefreshEvent{
		Keys: suite.newStubKeys("ignored"),
		Err:  errors.New("expected"),
	})
	suite.Equal(2, kr.Len())
}

func TestKeyRing(t *testing.T) {
	suite.Run(t, new(KeyRingSuite))
}
