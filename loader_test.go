package clortho

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"gopkg.in/h2non/gock.v1"
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

func (suite *LoaderSuite) TearDownTest() {
	gock.OffAll()
}

func (suite *LoaderSuite) TearDownSuite() {
	os.RemoveAll(suite.testDirectory)
}

// newLoader creates a Loader for testing.
func (suite *LoaderSuite) newLoader(options ...LoaderOption) Loader {
	l, err := NewLoader(options...)
	suite.Require().NoError(err)
	suite.Require().NotNil(l)
	return l
}

// createFile creates a new file containing the given content.
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

func (suite *LoaderSuite) TestFileLoader() {
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

func (suite *LoaderSuite) TestNotAFile() {
	l := suite.newLoader()
	content, meta, err := l.LoadContent(context.Background(), suite.testDirectory, ContentMeta{})
	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.Require().Error(err)

	var naf *NotAFileError
	suite.Require().True(errors.As(err, &naf))
	suite.Equal(suite.testDirectory, naf.Location)
	suite.Contains(naf.Error(), suite.testDirectory)
}

func (suite *LoaderSuite) TestInvalidFileURI() {
	l := suite.newLoader()
	content, meta, err := l.LoadContent(context.Background(), "file://\b\t", ContentMeta{})
	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.Require().Error(err)
}

func (suite *LoaderSuite) TestHTTPLoader() {
	suite.Run("Simple", func() {
		defer gock.Off()
		gock.New("http://getkeys.com").
			Get("/keys").
			Reply(http.StatusOK).
			BodyString(keyContent).
			SetHeader("Content-Type", MediaTypeJWK)

		l := suite.newLoader()
		content, meta, err := l.LoadContent(context.Background(), "http://getkeys.com/keys", ContentMeta{})
		suite.Equal(keyContent, string(content))
		suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
		suite.NoError(err)
		suite.True(gock.IsDone())
	})

	suite.Run("LastModified", func() {
		defer gock.Off()

		var (
			requestLastModified  = time.Now().Truncate(time.Second)
			responseLastModified = requestLastModified.Add(time.Hour)
		)

		gock.New("http://getkeys.com").
			Get("/keys").
			MatchHeader("If-Modified-Since", requestLastModified.Format(time.RFC1123)).
			Reply(http.StatusOK).
			BodyString(keyContent).
			SetHeader("Content-Type", MediaTypeJWK).
			SetHeader("Last-Modified", responseLastModified.Format(time.RFC1123))

		l := suite.newLoader()
		content, meta, err := l.LoadContent(
			context.Background(),
			"http://getkeys.com/keys",
			ContentMeta{
				LastModified: requestLastModified,
			},
		)

		suite.Equal(keyContent, string(content))
		suite.Equal(ContentMeta{Format: MediaTypeJWK, LastModified: responseLastModified}, meta)
		suite.NoError(err)
		suite.True(gock.IsDone())
	})
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
	const unsupported = "unsupported://foo/bar"
	l := suite.newLoader()
	content, meta, err := l.LoadContent(context.Background(), unsupported, ContentMeta{Format: SuffixPEM})

	suite.Empty(content)
	suite.Equal(ContentMeta{Format: SuffixPEM}, meta)
	suite.Require().Error(err)

	var use *UnsupportedSchemeError
	suite.Require().True(errors.As(err, &use))
	suite.Equal(unsupported, use.Location)
	suite.Contains(use.Error(), unsupported)
}

func TestLoader(t *testing.T) {
	suite.Run(t, new(LoaderSuite))
}
