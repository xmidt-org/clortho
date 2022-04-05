package main

import (
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/suite"
)

type AttributesSuite struct {
	suite.Suite
}

func (suite *AttributesSuite) testSetToEmpty() {
	key := jwk.NewRSAPrivateKey()
	count := len(key.PrivateParams())
	suite.NoError(Attributes{}.SetTo(key))
	suite.Len(key.PrivateParams(), count)
}

func (suite *AttributesSuite) testSetToSuccess() {
	key := jwk.NewRSAPrivateKey()
	suite.NoError(Attributes{
		"simple":           "a simple value",
		"string":           "'a string'",
		"int":              "248123",
		"float":            "-38523.5634",
		"stringizedNumber": "'3422341'",
	}.SetTo(key))

	privateParams := key.PrivateParams()
	suite.Equal("a simple value", privateParams["simple"])
	suite.Equal("a string", privateParams["string"])
	suite.Equal(248123, privateParams["int"])
	suite.Equal(-38523.5634, privateParams["float"])
	suite.Equal("3422341", privateParams["stringizedNumber"])
}

func (suite *AttributesSuite) testSetToReserved() {
	key := jwk.NewRSAPrivateKey()
	count := len(key.PrivateParams())
	suite.Error(Attributes{
		jwk.KeyUsageKey: "this is a reserved attribute, so it should cause an error",
	}.SetTo(key))

	suite.Len(key.PrivateParams(), count)
}

func (suite *AttributesSuite) TestSetTo() {
	suite.Run("Empty", suite.testSetToEmpty)
	suite.Run("Success", suite.testSetToSuccess)
	suite.Run("Reserved", suite.testSetToReserved)
}

func TestAttributes(t *testing.T) {
	suite.Run(t, new(AttributesSuite))
}
