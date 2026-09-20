// SPDX-FileCopyrightText: 2025 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clortho

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"gopkg.in/h2non/gock.v1"
)

const (
	testHTTPSGet = "https://example.com/keys"
	testHTTPGet  = "http://example.com/keys"
	// keyContent is a stand-in for some sort of key material.  All test files used
	// by the LoaderSuite simply use this string as the content.
	keyContent = "this is some key content"
)

type LoaderSuite struct {
	suite.Suite

	testDirectory string
}

func (suite *LoaderSuite) SetupSuite() {
	d, err := os.MkdirTemp(os.TempDir(), "clortho.test.")
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
				scheme          string
				prefix          string
				expectedContent string
				options         []LoaderOption
			}{
				{
					scheme:          "",
					prefix:          "",
					expectedContent: "",
				},
				{
					scheme:          "file",
					prefix:          "file://",
					expectedContent: "",
				},
				{
					scheme:          "",
					prefix:          "",
					expectedContent: keyContent,
				},
				{
					scheme:          "file",
					prefix:          "file://",
					expectedContent: keyContent,
				},
			}

			for i, testCase := range testCases {
				suite.Run(strconv.Itoa(i), func() {
					path, fi := suite.createFile(suffix, testCase.expectedContent)
					l := suite.newLoader(WithSchemes(FileLoader{Root: os.DirFS("/")}, testCase.scheme))
					actualContent, actualMeta, err := l.LoadContent(SetContentMeta(context.Background(), ContentMeta{}), testCase.prefix+path)
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
	l := suite.newLoader(WithSchemes(FileLoader{Root: os.DirFS("/")}, ""))
	content, meta, err := l.LoadContent(SetContentMeta(context.Background(), ContentMeta{}), suite.testDirectory)
	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.Require().Error(err)

	var naf *NotAFileError
	suite.Require().True(errors.As(err, &naf))
	suite.Equal(suite.testDirectory, naf.Location)
	suite.Contains(naf.Error(), suite.testDirectory)
}

func (suite *LoaderSuite) testFileInvalidURI() {
	l := suite.newLoader(WithSchemes(FileLoader{Root: os.DirFS("/")}, "file"))
	content, meta, err := l.LoadContent(SetContentMeta(context.Background(), ContentMeta{}), "file://\b\t")
	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.Require().Error(err)
}

func (suite *LoaderSuite) testFileMissing() {
	l := suite.newLoader(WithSchemes(FileLoader{Root: os.DirFS("/")}, ""))
	content, meta, err := l.LoadContent(SetContentMeta(context.Background(), ContentMeta{}), "/no/such/file")
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

func (suite *LoaderSuite) testHTTP() {
	defer gock.Off()
	gock.New(testHTTPGet).
		Get("/keys").
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK)

	content, meta, err := suite.newLoader().LoadContent(
		SetContentMeta(context.Background(), ContentMeta{}),
		testHTTPGet,
	)

	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.NoError(err)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPS() {
	defer gock.Off()
	gock.New(testHTTPSGet).
		Get("/keys").
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK)

	content, meta, err := suite.newLoader().LoadContent(
		SetContentMeta(context.Background(), ContentMeta{}),
		testHTTPSGet,
	)

	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.NoError(err)
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
					Client:       client,
					Encoders:     []HTTPEncoder{encoder},
					Timeout:      5 * time.Minute,
					MaxReadLimit: int64(1 * 1024 * 25),
				},
				"http",
			),
		)
	)

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)
	gock.New(testHTTPGet).
		Get("/keys").
		MatchHeader("Custom", "true").
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK)

	content, meta, err := l.LoadContent(
		SetContentMeta(context.Background(), ContentMeta{}),
		testHTTPGet,
	)

	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.NoError(err)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPSClientError() {
	expectedError := errors.New("expected")

	defer gock.Off()
	gock.New(testHTTPSGet).
		Get("/keys").
		Reply(http.StatusOK).
		SetError(expectedError)

	content, meta, err := suite.newLoader().LoadContent(
		SetContentMeta(context.Background(), ContentMeta{}),
		testHTTPSGet,
	)

	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.ErrorIs(err, expectedError)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPSCustomLoader() {
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
					Client:       client,
					Encoders:     []HTTPEncoder{encoder},
					Timeout:      5 * time.Minute,
					MaxReadLimit: int64(1 * 1024 * 25),
				},
				"https",
			),
		)
	)

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)
	gock.New(testHTTPSGet).
		Get("/keys").
		MatchHeader("Custom", "true").
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK)

	content, meta, err := l.LoadContent(
		SetContentMeta(context.Background(), ContentMeta{}),
		testHTTPSGet,
	)

	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.NoError(err)
	suite.True(gock.IsDone())
}

// testHTTPSNoContentMeta verifies that a caller-supplied context carrying no
// ContentMeta is treated as the zero value: the request is sent without
// conditional headers, and the loader does not panic.  The Resolver and any
// direct caller of a Loader use ordinary contexts; only the Refresher seeds one.
func (suite *LoaderSuite) testHTTPSNoContentMeta() {
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
					Client:       client,
					Encoders:     []HTTPEncoder{encoder},
					Timeout:      5 * time.Minute,
					MaxReadLimit: int64(1 * 1024 * 25),
				},
				"https",
			),
		)
	)

	defer gock.Off()
	defer gock.RestoreClient(client)
	gock.InterceptClient(client)
	gock.New(testHTTPSGet).
		Get("/keys").
		MatchHeader("Custom", "true").
		AddMatcher(func(req *http.Request, _ *gock.Request) (bool, error) {
			// with no ContentMeta there is nothing to be conditional about
			return req.Header.Get("If-Modified-Since") == "", nil
		}).
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK)

	suite.Require().NotPanics(func() {
		content, meta, err := l.LoadContent(
			context.Background(),
			testHTTPSGet,
		)

		suite.Equal(keyContent, string(content))
		suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
		suite.NoError(err)
	})

	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPSCustomLoaderDefaultClient() {
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
					Client:       http.DefaultClient,
					Encoders:     []HTTPEncoder{encoder},
					Timeout:      5 * time.Minute,
					MaxReadLimit: int64(1 * 1024 * 25),
				},
				"https",
			),
		)
	)

	defer gock.Off()
	gock.New(testHTTPSGet).
		Get("/keys").
		MatchHeader("Custom", "true").
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK)

	content, meta, err := l.LoadContent(
		SetContentMeta(context.Background(), ContentMeta{}),
		testHTTPSGet,
	)

	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.NoError(err)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPSCustomLoaderEncoderError() {
	var (
		expectedError = errors.New("expected")

		encoder = HTTPEncoder(func(ctx context.Context, r *http.Request) error {
			return expectedError
		})

		l = suite.newLoader(
			WithSchemes(
				HTTPLoader{
					Encoders:     []HTTPEncoder{encoder},
					MaxReadLimit: int64(1 * 1024 * 25),
				},
				"https",
			),
		)
	)

	defer gock.Off()

	// the encoder will return an error, so we'll never invoke the HTTP client
	content, meta, err := l.LoadContent(
		SetContentMeta(context.Background(), ContentMeta{}),
		testHTTPSGet,
	)

	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.ErrorIs(err, expectedError)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPStatusNotModified() {
	defer gock.Off()
	gock.New(testHTTPSGet).
		Get("/keys").
		Reply(http.StatusNotModified)

	content, meta, err := suite.newLoader().LoadContent(
		SetContentMeta(context.Background(), ContentMeta{}),
		testHTTPSGet,
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
	gock.New(testHTTPSGet).
		Get("/keys").
		MatchHeader("If-Modified-Since", requestLastModified.Format(time.RFC1123)).
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK).
		SetHeader("Last-Modified", responseLastModified.Format(time.RFC1123))

	content, meta, err := suite.newLoader().LoadContent(
		SetContentMeta(context.Background(), ContentMeta{LastModified: requestLastModified}),
		testHTTPSGet,
	)

	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: MediaTypeJWK, LastModified: responseLastModified}, meta)
	suite.NoError(err)
	suite.True(gock.IsDone())
}

func (suite *LoaderSuite) testHTTPLastModifiedInvalid() {
	requestLastModified := time.Now().Truncate(time.Second)

	defer gock.Off()
	gock.New(testHTTPSGet).
		Get("/keys").
		MatchHeader("If-Modified-Since", requestLastModified.Format(time.RFC1123)).
		Reply(http.StatusOK).
		BodyString(keyContent).
		SetHeader("Content-Type", MediaTypeJWK).
		SetHeader("Last-Modified", "this is not a valid RFC1123 timestamp")

	content, meta, err := suite.newLoader().LoadContent(
		SetContentMeta(context.Background(), ContentMeta{LastModified: requestLastModified}),
		testHTTPSGet,
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
			gock.New(testHTTPSGet).
				Get("/keys").
				Reply(http.StatusOK).
				SetHeader("Content-Type", MediaTypeJWKSet).
				SetHeader("Cache-Control", value).
				BodyString(keyContent)

			content, meta, err := suite.newLoader().LoadContent(
				SetContentMeta(context.Background(), ContentMeta{}),
				testHTTPSGet,
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
			gock.New(testHTTPSGet).
				Get("/keys").
				Reply(statusCode)

			content, meta, err := suite.newLoader().LoadContent(
				SetContentMeta(context.Background(), ContentMeta{}),
				testHTTPSGet,
			)

			suite.Empty(content)
			suite.Equal(ContentMeta{}, meta)
			suite.Require().Error(err)

			var hle *HTTPLoaderError
			suite.Require().ErrorAs(err, &hle)
			suite.Equal(statusCode, hle.StatusCode)
			suite.Contains(hle.Error(), testHTTPSGet)
			suite.Contains(hle.Error(), strconv.Itoa(statusCode))
		})
	}
}

func (suite *LoaderSuite) TestHTTPLoader() {
	suite.Run("HTTP", suite.testHTTP)
	suite.Run("HTTPS", suite.testHTTPS)
	suite.Run("HTTPSClientError", suite.testHTTPSClientError)
	suite.Run("HTTPSCustomLoader", suite.testHTTPSCustomLoader)
	suite.Run("HTTPSNoContentMeta", suite.testHTTPSNoContentMeta)
	suite.Run("HTTPCustomLoader", suite.testHTTPCustomLoader)
	suite.Run("HTTPSCustomLoader/DefaultClient", suite.testHTTPSCustomLoaderDefaultClient)
	suite.Run("HTTPSCustomLoader/EncoderError", suite.testHTTPSCustomLoaderEncoderError)
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

	custom.ExpectLoadContent(context.Background(), "custom://foo/bar").
		Return([]byte(keyContent), ContentMeta{Format: MediaTypeJWK}, nil).
		Once()

	content, meta, err := l.LoadContent(context.Background(), "custom://foo/bar")
	suite.NoError(err)
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.Equal(keyContent, string(content))

	custom.AssertExpectations(suite.T())
}

func (suite *LoaderSuite) TestUnsupportedScheme() {
	const unsupported = "unsupported://foo/bar"
	l := suite.newLoader()
	content, meta, err := l.LoadContent(SetContentMeta(context.Background(), ContentMeta{Format: SuffixPEM}), unsupported)

	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.Require().Error(err)

	var use *UnsupportedSchemeError
	suite.Require().ErrorAs(err, &use)
	suite.Equal(unsupported, use.Location)
	suite.Contains(use.Error(), unsupported)
}

// newChunkedServer serves body with chunked transfer encoding, which is what a
// proxy or gateway that re-encodes responses produces.  The client then sees a
// ContentLength of -1.
func (suite *LoaderSuite) newChunkedServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", MediaTypeJWK)
		rw.Header().Set("Transfer-Encoding", "chunked")
		_, _ = rw.Write([]byte(body))
	}))
}

// newSizedServer serves body with an explicit Content-Length.
func (suite *LoaderSuite) newSizedServer(body string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", MediaTypeJWK)
		rw.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = rw.Write([]byte(body))
	}))
}

// newLimitedLoader returns a Loader whose http scheme is served by an HTTPLoader
// with the given read limit.
func (suite *LoaderSuite) newLimitedLoader(limit int64) Loader {
	return suite.newLoader(
		WithSchemes(
			HTTPLoader{
				Client:       http.DefaultClient,
				MaxReadLimit: limit,
			},
			"http",
		),
	)
}

// TestHTTPChunkedBody checks that a response with no Content-Length, i.e. chunked
// transfer encoding, is read in full.  The default loader must handle this, since
// JWKS endpoints behind proxies commonly respond this way.
func (suite *LoaderSuite) TestHTTPChunkedBody() {
	server := suite.newChunkedServer(keyContent)
	defer server.Close()

	content, meta, err := suite.newLoader().LoadContent(context.Background(), server.URL+"/keys")
	suite.Require().NoError(err)
	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
}

// TestHTTPBodyTooLarge checks that a body larger than MaxReadLimit is reported as
// exactly that, rather than as a truncated read or a parse failure downstream.
func (suite *LoaderSuite) TestHTTPBodyTooLarge() {
	server := suite.newSizedServer(keyContent)
	defer server.Close()

	limit := int64(len(keyContent) - 1)
	content, meta, err := suite.newLimitedLoader(limit).LoadContent(context.Background(), server.URL+"/keys")
	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.Require().Error(err)

	var rtle *ResponseTooLargeError
	suite.Require().ErrorAs(err, &rtle)
	suite.Equal(limit, rtle.Limit)
	suite.Contains(rtle.Location, "/keys")
}

// TestHTTPChunkedBodyTooLarge is TestHTTPBodyTooLarge for a response whose size is
// not known up front.  The limit must be enforced while reading, not from a header.
func (suite *LoaderSuite) TestHTTPChunkedBodyTooLarge() {
	server := suite.newChunkedServer(keyContent)
	defer server.Close()

	limit := int64(len(keyContent) - 1)
	content, meta, err := suite.newLimitedLoader(limit).LoadContent(context.Background(), server.URL+"/keys")
	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.Require().Error(err)

	var rtle *ResponseTooLargeError
	suite.Require().ErrorAs(err, &rtle)
	suite.Equal(limit, rtle.Limit)
}

// TestHTTPBodyAtLimit checks the boundary: a body of exactly MaxReadLimit bytes is
// not too large.
func (suite *LoaderSuite) TestHTTPBodyAtLimit() {
	server := suite.newSizedServer(keyContent)
	defer server.Close()

	content, _, err := suite.newLimitedLoader(int64(len(keyContent))).LoadContent(context.Background(), server.URL+"/keys")
	suite.Require().NoError(err)
	suite.Equal(keyContent, string(content))
}

// TestHTTPNoReadLimit checks that an HTTPLoader constructed without a MaxReadLimit
// reads the whole body, consistent with the Timeout field where zero means none.
func (suite *LoaderSuite) TestHTTPNoReadLimit() {
	server := suite.newSizedServer(keyContent)
	defer server.Close()

	content, _, err := suite.newLimitedLoader(0).LoadContent(context.Background(), server.URL+"/keys")
	suite.Require().NoError(err)
	suite.Equal(keyContent, string(content))
}

// TestHTTPLoaderReadLimit checks how MaxReadLimit maps to the limit actually
// applied when reading: a positive value is used as is, and anything else
// means no limit.
func (suite *LoaderSuite) TestHTTPLoaderReadLimit() {
	testCases := []struct {
		name     string
		max      int64
		expected int64
	}{
		{name: "Unset", max: 0, expected: math.MaxInt64 - 1},
		{name: "Negative", max: -1, expected: math.MaxInt64 - 1},
		{name: "One", max: 1, expected: 1},
		{name: "Default", max: int64(1 * 1024 * 25), expected: int64(1 * 1024 * 25)},
		{name: "Max", max: math.MaxInt64, expected: math.MaxInt64},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			hl := HTTPLoader{MaxReadLimit: tc.max}
			suite.Equal(tc.expected, hl.readLimit())
		})
	}
}

// TestResponseTooLargeError checks the error's message and that it can be
// recovered from a wrapped error by type.
func (suite *LoaderSuite) TestResponseTooLargeError() {
	var (
		rtle = &ResponseTooLargeError{
			Location: testHTTPSGet,
			Limit:    1234,
		}

		wrapped = fmt.Errorf("fetching keys: %w", rtle)
	)

	suite.Contains(rtle.Error(), testHTTPSGet)
	suite.Contains(rtle.Error(), "1234")

	var target *ResponseTooLargeError
	suite.Require().ErrorAs(wrapped, &target)
	suite.Same(rtle, target)
}

// TestHTTPBodyTruncated checks that a body which fails partway through reading
// is reported as a read error, with no content.  The server declares more bytes
// than it sends, which makes it close the connection early.
func (suite *LoaderSuite) TestHTTPBodyTruncated() {
	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", MediaTypeJWK)
		rw.Header().Set("Content-Length", strconv.Itoa(2*len(keyContent)))
		_, _ = rw.Write([]byte(keyContent))
	}))
	defer server.Close()

	content, meta, err := suite.newLoader().LoadContent(context.Background(), server.URL+"/keys")
	suite.Empty(content)
	suite.Equal(ContentMeta{}, meta)
	suite.ErrorIs(err, io.ErrUnexpectedEOF)
}

// TestDefaultFileScheme checks that a Loader from NewLoader handles file:// URIs
// without any option, as its documentation says.
func (suite *LoaderSuite) TestDefaultFileScheme() {
	path, fi := suite.createFile(".jwk", keyContent)

	content, meta, err := suite.newLoader().LoadContent(context.Background(), "file://"+path)
	suite.Require().NoError(err)
	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: ".jwk", LastModified: fi.ModTime()}, meta)
}

// TestDefaultBarePath checks that a Loader from NewLoader treats a location with
// no scheme as a file system path, as its documentation says, rather than
// handing it to the HTTP client.
func (suite *LoaderSuite) TestDefaultBarePath() {
	path, fi := suite.createFile(".pem", keyContent)

	content, meta, err := suite.newLoader().LoadContent(context.Background(), path)
	suite.Require().NoError(err)
	suite.Equal(keyContent, string(content))
	suite.Equal(ContentMeta{Format: ".pem", LastModified: fi.ModTime()}, meta)
}

func TestLoader(t *testing.T) {
	suite.Run(t, new(LoaderSuite))
}
