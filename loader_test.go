package clortho

import (
	"context"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/suite"
)

const (
	// keyContent is a stand-in for some sort of key material.  All test files used
	// by the LoaderSuite simply use this string as the content.
	keyContent = "this is some key content"
)

type LoaderSuite struct {
	suite.Suite

	testDirectory string
}

func (suite *LoaderSuite) SetupSuite() {
	d, err := os.MkdirTemp("", "clortho.test.")
	suite.Require().NoError(err)
	suite.testDirectory = d
	suite.T().Logf("using test directory: %s", suite.testDirectory)
}

func (suite *LoaderSuite) newLoader(options ...LoaderOption) Loader {
	l, err := NewLoader(options...)
	suite.Require().NoError(err)
	suite.Require().NotNil(l)
	return l
}

// createFile creates a new file containing keyContent.
func (suite *LoaderSuite) createFile(suffix, content string) (string, os.FileInfo) {
	file, err := os.CreateTemp(suite.testDirectory, "loader.*"+suffix)
	suite.Require().NoError(err)

	path := file.Name()
	_, err = file.Write([]byte(content))
	file.Close()
	suite.Require().NoError(err)

	fi, err := os.Stat(path)
	suite.Require().NoError(err)

	return path, fi
}

func (suite *LoaderSuite) TearDownSuite() {
	os.RemoveAll(suite.testDirectory)
}

func (suite *LoaderSuite) TestDefaultFileSetup() {
	suffixes := []string{
		SuffixJSON,
		SuffixJWK,
		SuffixJWKSet,
		SuffixPEM,
	}

	for _, suffix := range suffixes {
		suite.Run(suffix, func() {
			testCases := []struct {
				prefix          string
				expectedContent string
				options         []LoaderOption
			}{
				{
					prefix:          "",
					expectedContent: "",
				},
				{
					prefix:          "file://",
					expectedContent: "",
				},
				{
					prefix:          "",
					expectedContent: keyContent,
				},
				{
					prefix:          "file://",
					expectedContent: keyContent,
				},
			}

			for i, testCase := range testCases {
				suite.Run(strconv.Itoa(i), func() {
					path, fi := suite.createFile(suffix, testCase.expectedContent)
					l := suite.newLoader()
					actualContent, actualMeta, err := l.LoadContent(context.Background(), testCase.prefix+path, ContentMeta{})
					suite.Require().NoError(err)
					suite.Equal(testCase.expectedContent, string(actualContent))
					suite.Equal(
						ContentMeta{
							LastModified: fi.ModTime(),
							Format:       suffix,
						},
						actualMeta,
					)
				})
			}
		})
	}
}

func (suite *LoaderSuite) TestCustomLoader() {
	var (
		custom = new(mockLoader)

		l = suite.newLoader(
			WithSchemes(custom, "custom"),
		)
	)

	custom.ExpectLoadContent(context.Background(), "custom://foo/bar", ContentMeta{}).
		Return([]byte(keyContent), ContentMeta{Format: MediaTypeJWK}, error(nil)).
		Once()

	content, meta, err := l.LoadContent(context.Background(), "custom://foo/bar", ContentMeta{})
	suite.NoError(err)
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.Equal(keyContent, string(content))

	custom.AssertExpectations(suite.T())
}

func (suite *LoaderSuite) TestUnsupportedScheme() {
	l := suite.newLoader()
	content, meta, err := l.LoadContent(context.Background(), "unsupported://foo/bar", ContentMeta{Format: SuffixPEM})

	suite.Empty(content)
	suite.Equal(ContentMeta{Format: SuffixPEM}, meta)
	suite.Require().Error(err)

	suite.Contains(err.Error(), "unsupported://foo/bar")
}

func TestLoader(t *testing.T) {
	suite.Run(t, new(LoaderSuite))
}
