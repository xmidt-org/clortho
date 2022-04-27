/**
 * Copyright 2022 Comcast Cable Communications Management, LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package clortho

import (
	"context"
	"errors"
	"io/fs"
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

func (suite *LoaderSuite) testFileSimple() {
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

func (suite *LoaderSuite) testFileNotAFile() {
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

func (suite *LoaderSuite) testFileInvalidURI() {
	l := suite.newLoader()
	content, meta, err := l.LoadContent(context.Background(), "file://\b\t", ContentMeta{})
	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.Require().Error(err)
}

func (suite *LoaderSuite) testFileMissing() {
	l := suite.newLoader()
	content, meta, err := l.LoadContent(context.Background(), "/no/such/file", ContentMeta{})
	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.ErrorIs(err, fs.ErrNotExist)
}

func (suite *LoaderSuite) TestFileLoader() {
	suite.Run("Simple", suite.testFileSimple)
	suite.Run("NotAFile", suite.testFileNotAFile)
	suite.Run("InvalidURI", suite.testFileInvalidURI)
	suite.Run("Missing", suite.testFileMissing)
}

func (suite *LoaderSuite) testHTTPSimple() {
	defer gock.Off()
	gock.New("http://getkeys.com").
		Get("/keys").
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK)

	content, meta, err := suite.newLoader().LoadContent(
		context.Background(),
		"http://getkeys.com/keys",
		ContentMeta{},
	)

	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.NoError(err)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPClientError() {
	expectedError := errors.New("expected")

	defer gock.Off()
	gock.New("http://getkeys.com").
		Get("/keys").
		Reply(http.StatusOK).
		SetError(expectedError)

	content, meta, err := suite.newLoader().LoadContent(
		context.Background(),
		"http://getkeys.com/keys",
		ContentMeta{},
	)

	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.ErrorIs(err, expectedError)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPCustomLoader() {
	var (
		client  = new(http.Client)
		encoder = HTTPEncoder(func(ctx context.Context, r *http.Request) error {
			r.Header.Set("Custom", "true")

			// should be a non-background context
			suite.NotNil(ctx.Done())

			return nil
		})

		l = suite.newLoader(
			WithSchemes(
				HTTPLoader{
					Client:   client,
					Encoders: []HTTPEncoder{encoder},
					Timeout:  5 * time.Minute,
				},
				"http",
			),
		)
	)

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)
	gock.New("http://getkeys.com").
		Get("/keys").
		MatchHeader("Custom", "true").
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK)

	content, meta, err := l.LoadContent(
		context.Background(),
		"http://getkeys.com/keys",
		ContentMeta{},
	)

	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.NoError(err)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPCustomLoaderDefaultClient() {
	var (
		encoder = HTTPEncoder(func(ctx context.Context, r *http.Request) error {
			r.Header.Set("Custom", "true")

			// should be a non-background context
			suite.NotNil(ctx.Done())

			return nil
		})

		l = suite.newLoader(
			WithSchemes(
				HTTPLoader{
					Encoders: []HTTPEncoder{encoder},
					Timeout:  5 * time.Minute,
				},
				"http",
			),
		)
	)

	defer gock.Off()
	gock.New("http://getkeys.com").
		Get("/keys").
		MatchHeader("Custom", "true").
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK)

	content, meta, err := l.LoadContent(
		context.Background(),
		"http://getkeys.com/keys",
		ContentMeta{},
	)

	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.NoError(err)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPCustomLoaderEncoderError() {
	var (
		expectedError = errors.New("expected")

		encoder = HTTPEncoder(func(ctx context.Context, r *http.Request) error {
			return expectedError
		})

		l = suite.newLoader(
			WithSchemes(
				HTTPLoader{
					Encoders: []HTTPEncoder{encoder},
				},
				"http",
			),
		)
	)

	defer gock.Off()

	// the encoder will return an error, so we'll never invoke the HTTP client
	content, meta, err := l.LoadContent(
		context.Background(),
		"http://getkeys.com/keys",
		ContentMeta{},
	)

	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.ErrorIs(err, expectedError)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPStatusNotModified() {
	defer gock.Off()
	gock.New("http://getkeys.com").
		Get("/keys").
		Reply(http.StatusNotModified)

	content, meta, err := suite.newLoader().LoadContent(
		context.Background(),
		"http://getkeys.com/keys",
		ContentMeta{},
	)

	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.NoError(err)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPLastModified() {
	var (
		// need to use UTC explicitly to avoid test noise
		requestLastModified  = time.Now().UTC().Truncate(time.Second)
		responseLastModified = requestLastModified.Add(time.Hour)
	)

	defer gock.Off()
	gock.New("http://getkeys.com").
		Get("/keys").
		MatchHeader("If-Modified-Since", requestLastModified.Format(time.RFC1123)).
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK).
		SetHeader("Last-Modified", responseLastModified.Format(time.RFC1123))

	content, meta, err := suite.newLoader().LoadContent(
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
}

func (suite *LoaderSuite) testHTTPLastModifiedInvalid() {
	requestLastModified := time.Now().Truncate(time.Second)

	defer gock.Off()
	gock.New("http://getkeys.com").
		Get("/keys").
		MatchHeader("If-Modified-Since", requestLastModified.Format(time.RFC1123)).
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK).
		SetHeader("Last-Modified", "this is not a valid RFC1123 timestamp")

	content, meta, err := suite.newLoader().LoadContent(
		context.Background(),
		"http://getkeys.com/keys",
		ContentMeta{
			LastModified: requestLastModified,
		},
	)

	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.NoError(err)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPCacheControl() {
	const expectedTTL = 100 * time.Second

	values := []string{
		"max-age=100",
		"no-store, max-age=100",
	}

	for _, value := range values {
		suite.Run(value, func() {
			defer gock.Off()
			gock.New("http://getkeys.com").
				Get("/keys").
				Reply(http.StatusOK).
				SetHeader("Content-Type", MediaTypeJWKSet).
				SetHeader("Cache-Control", value).
				BodyString(keyContent)

			content, meta, err := suite.newLoader().LoadContent(
				context.Background(),
				"http://getkeys.com/keys",
				ContentMeta{},
			)

			suite.Equal(keyContent, string(content))
			suite.Equal(
				ContentMeta{
					Format: MediaTypeJWKSet,
					TTL:    expectedTTL,
				},
				meta,
			)

			suite.NoError(err)
			suite.True(gock.IsDone())
		})
	}
}

func (suite *LoaderSuite) testHTTPErrorStatus() {
	// just a few examples of error codes that produce HTTPLoaderError
	errorStatusCodes := []int{
		http.StatusBadRequest,
		http.StatusNotFound,
		http.StatusInternalServerError,
	}

	for _, statusCode := range errorStatusCodes {
		suite.Run(strconv.Itoa(statusCode), func() {
			defer gock.Off()
			gock.New("http://getkeys.com").
				Get("/keys").
				Reply(statusCode)

			content, meta, err := suite.newLoader().LoadContent(
				context.Background(),
				"http://getkeys.com/keys",
				ContentMeta{},
			)

			suite.Empty(content)
			suite.Equal(ContentMeta{}, meta)
			suite.Require().Error(err)

			var hle *HTTPLoaderError
			suite.Require().ErrorAs(err, &hle)
			suite.Equal(statusCode, hle.StatusCode)
			suite.Contains(hle.Error(), "http://getkeys.com/keys")
			suite.Contains(hle.Error(), strconv.Itoa(statusCode))
		})
	}
}

func (suite *LoaderSuite) TestHTTPLoader() {
	suite.Run("Simple", suite.testHTTPSimple)
	suite.Run("ClientError", suite.testHTTPClientError)
	suite.Run("CustomLoader", suite.testHTTPCustomLoader)
	suite.Run("CustomLoader/DefaultClient", suite.testHTTPCustomLoaderDefaultClient)
	suite.Run("CustomLoader/EncoderError", suite.testHTTPCustomLoaderEncoderError)
	suite.Run("StatusNotModified", suite.testHTTPStatusNotModified)
	suite.Run("Last-Modified", suite.testHTTPLastModified)
	suite.Run("Last-Modified/Invalid", suite.testHTTPLastModifiedInvalid)
	suite.Run("Cache-Control", suite.testHTTPCacheControl)
	suite.Run("ErrorStatus", suite.testHTTPErrorStatus)
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
	suite.Require().ErrorAs(err, &use)
	suite.Equal(unsupported, use.Location)
	suite.Contains(use.Error(), unsupported)
}

func TestLoader(t *testing.T) {
	suite.Run(t, new(LoaderSuite))
}
