package main

import (
	"bytes"
	"strconv"
	"testing"

	"github.com/stretchr/testify/suite"
)

type RunSuite struct {
	suite.Suite
}

func (suite *RunSuite) TestValidCommand() {
	arguments := [][]string{
		{"RSA"},
		{"EC"},
		{"oct"},
		{"OKP"},
	}

	for i, args := range arguments {
		suite.Run(strconv.Itoa(i), func() {
			var (
				stdout bytes.Buffer
				stderr bytes.Buffer
			)

			k := newParser()
			k.Stdout = &stdout
			k.Stderr = &stderr
			k.Exit = func(code int) {
				suite.Zero(code)
			}

			suite.Require().NotNil(k)
			suite.NoError(run(k, args...))
		})
	}
}

func TestRun(t *testing.T) {
	suite.Run(t, new(RunSuite))
}
