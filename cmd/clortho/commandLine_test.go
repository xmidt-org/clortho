package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/suite"
)

type RunSuite struct {
	suite.Suite

	keysDir string
}

func (suite *RunSuite) SetupSuite() {
	var err error
	suite.keysDir, err = os.MkdirTemp("", "RunSuite-")
	suite.Require().NoError(err)
	suite.T().Logf("%T using temporary directory: %s", suite, suite.keysDir)
}

func (suite *RunSuite) TearDownSuite() {
	os.RemoveAll(suite.keysDir)
}

func (suite *RunSuite) getKey(set jwk.Set, i int) jwk.Key {
	key, ok := set.Get(i)
	suite.Require().True(ok)
	return key
}

func (suite *RunSuite) keyPath(baseName string) string {
	return filepath.Join(
		suite.keysDir,
		baseName,
	)
}

func (suite *RunSuite) readStdoutOrFile(stdout *bytes.Buffer, path string) []byte {
	if path == "" {
		return stdout.Bytes()
	}

	data, err := os.ReadFile(path)
	suite.Require().NoError(err)
	return data
}

func (suite *RunSuite) readKey(expectedFormat string, stdout *bytes.Buffer, path string) (key jwk.Key) {
	var (
		data = suite.readStdoutOrFile(stdout, path)
		err  error
	)

	switch expectedFormat {
	case FormatPEM:
		key, err = jwk.ParseKey(data, jwk.WithPEM(true))
	case FormatJWK:
		key, err = jwk.ParseKey(data)
	default:
		var set jwk.Set
		set, err = jwk.Parse(data)
		if err == nil {
			suite.Require().Equal(1, set.Len())
			key = suite.getKey(set, 0)
		}
	}

	suite.Require().NoError(err)
	return
}

func (suite *RunSuite) readSet(expectPEM bool, stdout *bytes.Buffer, path string) jwk.Set {
	data := suite.readStdoutOrFile(stdout, path)

	if !expectPEM {
		// if we're expecting a set, it should fail to parse as a single key
		// this doesn't apply to non-jwk formats
		_, err := jwk.ParseKey(data)
		suite.Require().Error(err)
	}

	set, err := jwk.Parse(data, jwk.WithPEM(expectPEM))
	suite.Require().NoError(err)
	return set
}

func (suite *RunSuite) newParser() (k *kong.Kong, stdout, stderr *bytes.Buffer) {
	suite.NotPanics(func() {
		k = newParser()
	})

	suite.Require().NotNil(k)
	stdout = new(bytes.Buffer)
	stderr = new(bytes.Buffer)

	k.Stdout = stdout
	k.Stderr = stderr

	return
}

func (suite *RunSuite) run(k *kong.Kong, keyType jwa.KeyType, additionalArgs ...string) (exitCode int) {
	args := append(
		[]string{string(keyType)},
		additionalArgs...,
	)

	suite.T().Logf("arguments: %s", args)
	k.Exit = func(c int) {
		exitCode = c
	}

	suite.Require().NoError(run(k, args...))
	return
}

func (suite *RunSuite) testOutput(keyType jwa.KeyType, expectedFormat string, path string, additionalArgs ...string) func() {
	return func() {
		k, stdout, stderr := suite.newParser()
		suite.run(k, keyType, additionalArgs...)
		suite.Zero(stderr.Len())

		key := suite.readKey(expectedFormat, stdout, path)
		suite.Equal(keyType, key.KeyType())
	}
}

func (suite *RunSuite) TestOutput() {
	suite.Run("RSA", func() {
		suite.Run("Default", suite.testOutput(jwa.RSA, FormatJWKSet, ""))
	})
}

func TestRun(t *testing.T) {
	suite.Run(t, new(RunSuite))
}
