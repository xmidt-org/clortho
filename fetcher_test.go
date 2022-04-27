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
	"crypto"
	"errors"
	"testing"

	_ "crypto/sha512"

	"github.com/stretchr/testify/suite"
)

const (
	// jwkFetchSet is a copy of jwkSet with the second key having no kid.
	// this tests that the fetcher correctly guarantees key IDs.
	jwkFetchSet = `{
    "keys": [
        {
		    "kid": "first",
            "p": "2ywWG0C5tMTXHj8AiGT0zvX4zDREvU4u_f8_btnPAoChVUqMAWMgVjw9Jpsv7-fzlf81kdg4ElJ8f5vhfc5Fhps03Gl_xNpVCyquwOYfgz9oAV1FiLfe8m5tXpOdFtz04f7XBHKEeLpHkyd_7hOgdVr0kGMHNvHlO6gsOiZqDRc",
            "kty": "RSA",
            "q": "mLNmPjbVMlyg__tpnHZOh-kDPctA4IRwd057SnavbEo1N1FrvC6QK7uUIwvTh5_XYikugE5Rfb4I6l4Umy9mE3n_8zOLepgkptyVpbkgfXWobP_5tTS3WQJ1pdUHsMe8byOWDoscwmA5ca901NnLpUwdezuFBU-ZX4Fmacxy3mU",
            "d": "Yneu7NkdcJHjAXpYkckKtZMRiZuiCxKXPCKKsloRda7gUfWPz-mhRxhMq7C440PgiZUVrz8QRgFRblGzVQ4o0jXfiYRWJJPB47G-L96YVCgWKtAmV9e_aCqt0W5Vg0RuFHSWhPCmH3igvvAo5gqihF21wOqqRk7QNy_PxRBTy7Q_ZyNxbHoxegE3p8U2rbb--YTT6QQk57uVBZY_ROdYKOjKZBzYcXnXfK_hQZVycy863XPV-hGcHuSq7rA-0Wwe45eCjNj3qpRL0DeXAXUNj1d069Q-m6WFFleI9tvyC2ubOp0ukQQ8GlXsPcdtDMROdUVK4cDbsPMQegGuJ6zcsQ",
            "e": "AQAB",
            "qi": "QVpIcBXZCkIDXQKPgkUWG5DKu6-v1uh7S4H0-y69A3aRLVtukZMUjIQ9DTPKQwZquL6On7P1v8JIqeYHXjEkA-xwaARMViYd7xOHfkzzuZ-M8sAgRumz-axzf18YhP0kRghuajddcYTZCKfZDOkj8RjEn5gNhu1p-ljmMQbwY0w",
            "dp": "LrWLlI1LxpG4wtJse6UAY2caefKdv7Z831bZnvc-Xesp9vJnOhh1GMvHwIWMRtWpHQuB0C5DbOw1akC_Yr9mI9TKBDtbpoldXH7hNW0VxDPsJ3ZITmXZVtNf7asJ7Ih0jAFys5jwUIZqoJrnccavCLO0sVzZecU9tGQX4OC080s",
            "dq": "NE5Xen4r31ltaOIE1iyMT-_YRWWHLqEPKT7_6oznIC_3NKC2R7qndeOGJc8aQT3WeHBk1lx9e5YJ1cYuRs4gqBFFRFhmsbLF80ZiGGdmorMX42Z3ccPB_kJibFChlsOEX4mQECFE06xEYRXZ7kNAh7mf66OCuEQA5H8dxqXavyU",
            "n": "grvEfHfqjwf-sJX-rEsJQV2LK1ok8InBvRDpR2BJGmDt_NCozqqMYhbRZaAJuqzYBav1m86VaKz3ZkGqYVI16tq4cB_csn9NYqD3yHhx3HdrJqt2AZZihCJCghHwTff6kclvpUIjvmYV92VJAGw_rlmbfBt7h4U5pkeAZ2RgsPVNTi8RaO5j9ogBuubFJS9i8nZ4qPG3e7nRenjP4VjRWgsvcGkHu6r5Tf-EWMSm8huYCm3Gxi-6krLAKC0e0YUkkAcB5oToZmmBl5hpsp2RD7P71Dv8u76NuDXWO6yDDty6hMoJjYzi2SCPHKgVO6hXu7MmSB0XvoGMgwZYR28cEw"
        },
		{
  		  "kty": "EC",
		  "d": "CMO2iZHDcDwkZvDd6IDTuxumYy4Fy6fOjkgL9IAtfrv3uuOHhAt5Qc0Mk8Ps53ss",
		  "crv": "P-384",
		  "x": "TYgJflJcwSRp1Qzx8zlz1rrt3t1LdWxfZ4Ticpa5Oa0IJCLXQZYcPqeBoT7lZBgO",
		  "y": "96EaX1zHA8aQi6cSledZfRJyIgVDekgw4J3mz_MrAON2MQTYWc3BpqqJ8gWrNMmr"
		}
    ]
}`
)

type FetcherSuite struct {
	suite.Suite
}

func (suite *FetcherSuite) newFetcher(options ...FetcherOption) Fetcher {
	f, err := NewFetcher(options...)
	suite.Require().NoError(err)
	suite.Require().NotNil(f)
	return f
}

// newFetcherWithMocks is a convenience for setting up a Fetcher with a mocked
// parser and loader.  Extra options can also be supplied.
func (suite *FetcherSuite) newFetcherWithMocks(extra ...FetcherOption) (f Fetcher, l *mockLoader, p *mockParser) {
	l = new(mockLoader)
	p = new(mockParser)
	f = suite.newFetcher(
		append(extra,
			WithParser(p),
			WithLoader(l),
		)...,
	)

	return
}

func (suite *FetcherSuite) TestLoaderError() {
	var (
		expectedError = errors.New("expected")
		f, l, p       = suite.newFetcherWithMocks()
	)

	l.ExpectLoadContent(context.Background(), "http://getkeys.com", ContentMeta{}).
		Return([]byte{}, ContentMeta{}, expectedError).
		Once()

	keys, meta, err := f.Fetch(context.Background(), "http://getkeys.com", ContentMeta{})
	suite.Empty(keys)
	suite.Equal(ContentMeta{}, meta)
	suite.ErrorIs(err, expectedError)

	l.AssertExpectations(suite.T())
	p.AssertExpectations(suite.T())
}

func (suite *FetcherSuite) TestParserError() {
	var (
		expectedError = errors.New("expected")
		f, l, p       = suite.newFetcherWithMocks()
	)

	l.ExpectLoadContent(context.Background(), "http://getkeys.com", ContentMeta{}).
		Return([]byte("keys"), ContentMeta{Format: MediaTypeJWK}, error(nil)).
		Once()

	p.ExpectParse(MediaTypeJWK, []byte("keys")).
		Return([]Key{}, expectedError).
		Once()

	keys, meta, err := f.Fetch(context.Background(), "http://getkeys.com", ContentMeta{})
	suite.Empty(keys)
	suite.Equal(ContentMeta{Format: MediaTypeJWK}, meta)
	suite.ErrorIs(err, expectedError)

	l.AssertExpectations(suite.T())
	p.AssertExpectations(suite.T())
}

func (suite *FetcherSuite) testFetch(extra ...FetcherOption) {
	var (
		f, l, p = suite.newFetcherWithMocks(extra...)

		realParser, _ = NewParser()
	)

	parsedKeys, err := realParser.Parse(MediaTypeJWKSet, []byte(jwkFetchSet))
	suite.Require().Len(parsedKeys, 2)
	suite.Require().NoError(err)

	l.ExpectLoadContent(context.Background(), "http://getkeys.com", ContentMeta{}).
		Return([]byte(jwkFetchSet), ContentMeta{Format: MediaTypeJWKSet}, error(nil)).
		Once()

	p.ExpectParse(MediaTypeJWKSet, []byte(jwkFetchSet)).
		Return(parsedKeys, error(nil)).
		Once()

	keys, meta, err := f.Fetch(context.Background(), "http://getkeys.com", ContentMeta{})
	suite.Require().NoError(err)
	suite.Equal(ContentMeta{Format: MediaTypeJWKSet}, meta)
	suite.Require().Len(keys, 2)

	// the fetcher should have ensured that each returned key has a key ID
	for _, k := range keys {
		suite.NotEmpty(k.KeyID())
	}

	l.AssertExpectations(suite.T())
	p.AssertExpectations(suite.T())
}

func (suite *FetcherSuite) TestFetch() {
	suite.Run("DefaultKeyIDHash", func() {
		suite.testFetch()
	})

	suite.Run("SHA512", func() {
		suite.testFetch(WithKeyIDHash(crypto.SHA512))
	})
}

// TestDefault just verifies the default setup.  We'll be verifying behavior with
// mocks elsewhere.
func (suite *FetcherSuite) TestDefault() {
	f := suite.newFetcher()
	suite.Require().IsType((*fetcher)(nil), f)

	suite.NotNil(f.(*fetcher).loader)
	suite.NotNil(f.(*fetcher).parser)
	suite.Equal(crypto.SHA256, f.(*fetcher).keyIDHash)
}

func TestFetcher(t *testing.T) {
	suite.Run(t, new(FetcherSuite))
}
