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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/stretchr/testify/suite"
)

const (
	// singlePEM is a single 2048-bit RSA key in PEM format
	singlePEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA20Ni+ma3vPIJuRkieFIHOQfl+OySVruUGJE59x+FHzmyOfP5
SzbXQXfrvt3nm3cRTBVVsVwUnELL6SjUWboFsWetqQ+PZauuXNxnxzucJAgZBmwE
7d/FdAFePUGuHya+4aM5pSYTn5/hlcgtyK7ult+dbtiijOvJfBh4WRkiLcOvaM6w
R/6uBybg6Q/Dmgg2yIGVZASepKgEKqC0DNBBRun+TwQasORlHiHsF1S5vV/mfNP1
IGzJiaAiusdiTU56EYzeIzyGRud/TehputfnOIfoWZlQAexzH50/qSOUaNARHrGs
bZVuKg1IUoCuv363/x1EbXVg6kMEeR7DvEqz6QIDAQABAoIBAFiURKw8SwY+EceB
a/eHy/syQanqiMQZS58RLIW1aiZPPL1E3vWP1i5QsCCPrT2VQJuoEtJwDLOEGLS9
FeyZxisBY5rk+l1smihRsms+nbnAu7tocCVZPX+7/cJpglp7YKnvMx6Q32ShRpUo
JbbpVOIGvKdHRYQAzYkgqZ31FWW+5Gk98aMJv9nLn3AJQzy1PrbbCesEzOl9FpAT
RIcSKHvsfwpkyDF2PcW0+BqqSz0UEPJAWseQcObwzN6oa1kqh1ovNOh+VCwjYa0v
wgIjcHi/znNICQvbrM24zICqKl1k9FqWcKxnZdUcdE071GGvhWUmQ5bkfH7alMsC
dNza37ECgYEA/3urqHicuV0CSowaev4c354pZwniuxGOZC96/g7Je5v4lHfAS7BR
hm3AqwK+mhpTDJqdxe1bM7pzFXIf608oMWUi6ZRyj8pVbzxQwv2UyksObAQR5GxT
xOCYzU/T0Szp///tVXVheI3T6CZ4YskkGXfB/h7WoIbh94hgnfHXYHsCgYEA27T0
qw3jzbjEiqW9mLBpx5jdc/MwFXvf9SyYznOxdLx+IPJDR+ImgXC7AUSFqurNSTYC
2cOIeOyD2AgNR96SQ4XKOt/mp4Ygwvsbgeahzn1jI2zxZAsgn02y7wcjBfSMDLcq
BwlMHFIPIJJKujbn88PtYy/y6uZslF7I5qOBeesCgYARqcg1bplPS3nkE4mlJTpz
z2iHYiyVyGHy1UGInRca/66Q/TKDSR5pz965NAhfeSByx6HO1Fkw21wniGtihmd9
+sMOKSA+hrufZCklQgjub4AAwctG4qJsAyctUq6PUK6g713GQcZKYmvbKgW6trNT
O29jFVi7Ynfu+DPN17GPTwKBgQC9emonu2rjWJ3oFNhWfo47nRIflXO6k4KqJzQB
mLVKP+Vm9Ighzl/28gnVJgtBRA6XPQVoWMGxyAhMn2UUvlbV9ORbsg1yHLLUdUtb
1FNniaueOa5U4WPY/2F502XZFPZTYQPV3abOJdb1+DSKNCAGksp/6DJPcznhG32X
qxtW0QKBgQCX/xoBloclDX13TbDpFDjQMJ9g/cyHQUya/ZWLYaCZia6Vwl9mbDcx
zIr7kWpN8UTJ77wg6nfY2uhJBM3C7VnO3CtKNfR3AezCBVwR7wJ0p6PNcaYFnK+x
Tb//37rP+cKKAyjm6yPpP29p2R3D6zRqRtxc0RLBfzAqVM6D8M8+7Q==
-----END RSA PRIVATE KEY-----`

	// listPEM is a list of (2) keys:  the same key as singleRSAPEM
	// and a EC key on P-256.
	listPEM = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA20Ni+ma3vPIJuRkieFIHOQfl+OySVruUGJE59x+FHzmyOfP5
SzbXQXfrvt3nm3cRTBVVsVwUnELL6SjUWboFsWetqQ+PZauuXNxnxzucJAgZBmwE
7d/FdAFePUGuHya+4aM5pSYTn5/hlcgtyK7ult+dbtiijOvJfBh4WRkiLcOvaM6w
R/6uBybg6Q/Dmgg2yIGVZASepKgEKqC0DNBBRun+TwQasORlHiHsF1S5vV/mfNP1
IGzJiaAiusdiTU56EYzeIzyGRud/TehputfnOIfoWZlQAexzH50/qSOUaNARHrGs
bZVuKg1IUoCuv363/x1EbXVg6kMEeR7DvEqz6QIDAQABAoIBAFiURKw8SwY+EceB
a/eHy/syQanqiMQZS58RLIW1aiZPPL1E3vWP1i5QsCCPrT2VQJuoEtJwDLOEGLS9
FeyZxisBY5rk+l1smihRsms+nbnAu7tocCVZPX+7/cJpglp7YKnvMx6Q32ShRpUo
JbbpVOIGvKdHRYQAzYkgqZ31FWW+5Gk98aMJv9nLn3AJQzy1PrbbCesEzOl9FpAT
RIcSKHvsfwpkyDF2PcW0+BqqSz0UEPJAWseQcObwzN6oa1kqh1ovNOh+VCwjYa0v
wgIjcHi/znNICQvbrM24zICqKl1k9FqWcKxnZdUcdE071GGvhWUmQ5bkfH7alMsC
dNza37ECgYEA/3urqHicuV0CSowaev4c354pZwniuxGOZC96/g7Je5v4lHfAS7BR
hm3AqwK+mhpTDJqdxe1bM7pzFXIf608oMWUi6ZRyj8pVbzxQwv2UyksObAQR5GxT
xOCYzU/T0Szp///tVXVheI3T6CZ4YskkGXfB/h7WoIbh94hgnfHXYHsCgYEA27T0
qw3jzbjEiqW9mLBpx5jdc/MwFXvf9SyYznOxdLx+IPJDR+ImgXC7AUSFqurNSTYC
2cOIeOyD2AgNR96SQ4XKOt/mp4Ygwvsbgeahzn1jI2zxZAsgn02y7wcjBfSMDLcq
BwlMHFIPIJJKujbn88PtYy/y6uZslF7I5qOBeesCgYARqcg1bplPS3nkE4mlJTpz
z2iHYiyVyGHy1UGInRca/66Q/TKDSR5pz965NAhfeSByx6HO1Fkw21wniGtihmd9
+sMOKSA+hrufZCklQgjub4AAwctG4qJsAyctUq6PUK6g713GQcZKYmvbKgW6trNT
O29jFVi7Ynfu+DPN17GPTwKBgQC9emonu2rjWJ3oFNhWfo47nRIflXO6k4KqJzQB
mLVKP+Vm9Ighzl/28gnVJgtBRA6XPQVoWMGxyAhMn2UUvlbV9ORbsg1yHLLUdUtb
1FNniaueOa5U4WPY/2F502XZFPZTYQPV3abOJdb1+DSKNCAGksp/6DJPcznhG32X
qxtW0QKBgQCX/xoBloclDX13TbDpFDjQMJ9g/cyHQUya/ZWLYaCZia6Vwl9mbDcx
zIr7kWpN8UTJ77wg6nfY2uhJBM3C7VnO3CtKNfR3AezCBVwR7wJ0p6PNcaYFnK+x
Tb//37rP+cKKAyjm6yPpP29p2R3D6zRqRtxc0RLBfzAqVM6D8M8+7Q==
-----END RSA PRIVATE KEY-----
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEbf/hZ+g/zI4ujx5/56qxm8YRTlvE5iMXzVmX9FBls5oAoGCCqGSM49
AwEHoUQDQgAEjPlgD6lSXpMpCQ1SBRyXXIvNMb4Dv6KRMMAsDEFa57mlT3Sd9GGu
aAdfGgjK2jZ7kXV5rnnxtfINVtb6aILglQ==
-----END EC PRIVATE KEY-----`

	// singleJWK is a 2048-bit RSA key in JWK (*not* JWK set) format.
	singleJWK = `{
    "p": "2ywWG0C5tMTXHj8AiGT0zvX4zDREvU4u_f8_btnPAoChVUqMAWMgVjw9Jpsv7-fzlf81kdg4ElJ8f5vhfc5Fhps03Gl_xNpVCyquwOYfgz9oAV1FiLfe8m5tXpOdFtz04f7XBHKEeLpHkyd_7hOgdVr0kGMHNvHlO6gsOiZqDRc",
    "kty": "RSA",
    "q": "mLNmPjbVMlyg__tpnHZOh-kDPctA4IRwd057SnavbEo1N1FrvC6QK7uUIwvTh5_XYikugE5Rfb4I6l4Umy9mE3n_8zOLepgkptyVpbkgfXWobP_5tTS3WQJ1pdUHsMe8byOWDoscwmA5ca901NnLpUwdezuFBU-ZX4Fmacxy3mU",
    "d": "Yneu7NkdcJHjAXpYkckKtZMRiZuiCxKXPCKKsloRda7gUfWPz-mhRxhMq7C440PgiZUVrz8QRgFRblGzVQ4o0jXfiYRWJJPB47G-L96YVCgWKtAmV9e_aCqt0W5Vg0RuFHSWhPCmH3igvvAo5gqihF21wOqqRk7QNy_PxRBTy7Q_ZyNxbHoxegE3p8U2rbb--YTT6QQk57uVBZY_ROdYKOjKZBzYcXnXfK_hQZVycy863XPV-hGcHuSq7rA-0Wwe45eCjNj3qpRL0DeXAXUNj1d069Q-m6WFFleI9tvyC2ubOp0ukQQ8GlXsPcdtDMROdUVK4cDbsPMQegGuJ6zcsQ",
    "e": "AQAB",
    "qi": "QVpIcBXZCkIDXQKPgkUWG5DKu6-v1uh7S4H0-y69A3aRLVtukZMUjIQ9DTPKQwZquL6On7P1v8JIqeYHXjEkA-xwaARMViYd7xOHfkzzuZ-M8sAgRumz-axzf18YhP0kRghuajddcYTZCKfZDOkj8RjEn5gNhu1p-ljmMQbwY0w",
    "dp": "LrWLlI1LxpG4wtJse6UAY2caefKdv7Z831bZnvc-Xesp9vJnOhh1GMvHwIWMRtWpHQuB0C5DbOw1akC_Yr9mI9TKBDtbpoldXH7hNW0VxDPsJ3ZITmXZVtNf7asJ7Ih0jAFys5jwUIZqoJrnccavCLO0sVzZecU9tGQX4OC080s",
    "dq": "NE5Xen4r31ltaOIE1iyMT-_YRWWHLqEPKT7_6oznIC_3NKC2R7qndeOGJc8aQT3WeHBk1lx9e5YJ1cYuRs4gqBFFRFhmsbLF80ZiGGdmorMX42Z3ccPB_kJibFChlsOEX4mQECFE06xEYRXZ7kNAh7mf66OCuEQA5H8dxqXavyU",
    "n": "grvEfHfqjwf-sJX-rEsJQV2LK1ok8InBvRDpR2BJGmDt_NCozqqMYhbRZaAJuqzYBav1m86VaKz3ZkGqYVI16tq4cB_csn9NYqD3yHhx3HdrJqt2AZZihCJCghHwTff6kclvpUIjvmYV92VJAGw_rlmbfBt7h4U5pkeAZ2RgsPVNTi8RaO5j9ogBuubFJS9i8nZ4qPG3e7nRenjP4VjRWgsvcGkHu6r5Tf-EWMSm8huYCm3Gxi-6krLAKC0e0YUkkAcB5oToZmmBl5hpsp2RD7P71Dv8u76NuDXWO6yDDty6hMoJjYzi2SCPHKgVO6hXu7MmSB0XvoGMgwZYR28cEw"
}`

	// jwkSet is a JWK set containing the singleJWK key followed by a key of each type, both private and public
	jwkSet = `{
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
            "kty": "RSA",
            "e": "AQAB",
            "n": "ieUrPhya0uxSMGBJ4ycGoLg9N-Wp3PK5uk30eoBsDmpOJMOr_5yLfplzv681dP9EHEhB_AMl5WgvhnNb7zLwDOZ13egYLrn6u6XOhIkGapabaaqftQ9MaNBDdlIJK-YNKDkNfU4bpk50qIpg2KQ1YJpC4YhWAcXs_rtOoNxqDTn9k4Vqp_EP89xhkLaxJqHG5UKpY7wLSftisuaLi0NdSFgF-n2DMPeOjiRmU_bGjknLCHuAlNeIP5a3XlxXl49VotuTnf9Vfb12YnOBecWbE30vi8J8JYXEXEV1fEHe7dBoGhzBjtmvDeYt00eNrBSHmKGFzlxyk_R7SsDdbQ1UHQ"
        },
		{
  		  "kty": "EC",
		  "d": "CMO2iZHDcDwkZvDd6IDTuxumYy4Fy6fOjkgL9IAtfrv3uuOHhAt5Qc0Mk8Ps53ss",
		  "crv": "P-384",
		  "x": "TYgJflJcwSRp1Qzx8zlz1rrt3t1LdWxfZ4Ticpa5Oa0IJCLXQZYcPqeBoT7lZBgO",
		  "y": "96EaX1zHA8aQi6cSledZfRJyIgVDekgw4J3mz_MrAON2MQTYWc3BpqqJ8gWrNMmr"
		},
        {
            "kty": "EC",
            "crv": "P-384",
            "x": "D5phDK1IM8GKR6RPVZKIQD5KE_FYxweV5zSKzUYxS8zf-cLbX8IBFWKOrMI_KsGY",
            "y": "JkxVyHR4b8A84WRIHLVHNkT8B0CJVtvlJRVBrTLSi4SsncyY98TADDaf-dMbsYoo"
        },
        {
            "kty": "oct",
            "k": "CJbqlYu3h-UlCIeGYu66Fv8AJvedOrqBFC2Qt4fASV4tlDUXPVv8LoH9A_AHZwEO0ag4DVBs7hOO6_l-OWTk8PWCQHSX4LeXTEPDzdxNucps-qY25gEBapnw4SqC6HgHM9e-zXgEep1Hx5VjNcE3RMs0-FBCTX20OypYPoIMX8HTTwlcGZrwXlFsHPlz1zIzuxOh9qrs9FyILOHbPCLck7AI4Gead5W97RTPFp0uvw39gbZYh-cn21brQgzX278sOYOavqFsZdwFznI050Rc1iCF0_b_Nyd-9VUpWd7GhbGUku-Z7bmmzM7i_Xlhms44sQ0ncCvJY1_2qJ-m_yAkEQ"
        },
        {
            "kty": "OKP",
            "d": "kK65SnMX5iL1j8DkVn8EqRrvrlcQdSFFVOed5MCf2Fk",
            "crv": "Ed25519",
            "x": "US0-0BVHsGkVvODXrAhLLk9AfzwlYvt4Xk6j-U0dsJc"
        },
        {
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "phvHkcNnoiXAWLoMDrkJxM1-B4Ov26uvU29lRTpe1QI"
        }
    ]
}`
)

type ParserSuite struct {
	suite.Suite
}

func (suite *ParserSuite) newParser(options ...ParserOption) Parser {
	p, err := NewParser(options...)
	suite.Require().NoError(err)
	suite.Require().NotNil(p)
	return p
}

// assertRSAKey runs standard assertions against an RSA private key.
func (suite *ParserSuite) assertRSAKey(k Key) {
	suite.Equal(string(jwa.RSA), k.KeyType())
	suite.IsType((*rsa.PrivateKey)(nil), k.Raw())
	suite.IsType((*rsa.PublicKey)(nil), k.Public())
}

// assertECKey runs standard assertions against an EC private key.
func (suite *ParserSuite) assertECKey(k Key) {
	suite.Equal(string(jwa.EC), k.KeyType())
	suite.IsType((*ecdsa.PrivateKey)(nil), k.Raw())
	suite.IsType((*ecdsa.PublicKey)(nil), k.Public())
}

func (suite *ParserSuite) testSinglePEM(format string) {
	p := suite.newParser()
	keys, err := p.Parse(format, []byte(singlePEM))
	suite.Require().NoError(err)
	suite.Require().Len(keys, 1)

	k := keys[0]
	suite.Require().NotNil(k)
	suite.Empty(k.KeyID())
	suite.Empty(k.KeyUsage())
	suite.assertRSAKey(k)
}

func (suite *ParserSuite) TestSinglePEM() {
	suite.Run(SuffixPEM, func() { suite.testSinglePEM(SuffixPEM) })
	suite.Run(MediaTypePEM, func() { suite.testSinglePEM(MediaTypePEM) })
}

func (suite *ParserSuite) testListPEM(format string) {
	p := suite.newParser()
	keys, err := p.Parse(format, []byte(listPEM))
	suite.Require().NoError(err)
	suite.Require().Len(keys, 2)

	k := keys[0]
	suite.Require().NotNil(k)
	suite.Empty(k.KeyID())
	suite.Empty(k.KeyUsage())
	suite.assertRSAKey(k)

	k = keys[1]
	suite.Require().NotNil(k)
	suite.Empty(k.KeyID())
	suite.Empty(k.KeyUsage())
	suite.assertECKey(k)
}

func (suite *ParserSuite) TestListPEM() {
	suite.Run(SuffixPEM, func() { suite.testListPEM(SuffixPEM) })
	suite.Run(MediaTypePEM, func() { suite.testListPEM(MediaTypePEM) })
	suite.Run(MediaTypePEM+";charset=us-ascii", func() { suite.testListPEM(MediaTypePEM + ";charset=us-ascii") })
}

func (suite *ParserSuite) testJWK(format string) {
	p := suite.newParser()
	keys, err := p.Parse(format, []byte(singleJWK))
	suite.Require().NoError(err)
	suite.Require().Len(keys, 1)

	k := keys[0]
	suite.Require().NotNil(k)
	suite.Empty(k.KeyID())
	suite.Empty(k.KeyUsage())
	suite.assertRSAKey(k)
}

func (suite *ParserSuite) testJWKRejectSet(format string) {
	p := suite.newParser()
	keys, err := p.Parse(format, []byte(jwkSet))
	suite.Empty(keys)
	suite.Error(err)
}

func (suite *ParserSuite) TestJWK() {
	suite.Run(SuffixJWK, func() { suite.testJWK(SuffixJWK) })
	suite.Run(MediaTypeJWK, func() { suite.testJWK(MediaTypeJWK) })

	suite.Run("RejectSet", func() {
		suite.Run(SuffixJWK, func() { suite.testJWKRejectSet(SuffixJWK) })
		suite.Run(MediaTypeJWK, func() { suite.testJWKRejectSet(MediaTypeJWK) })
		suite.Run(MediaTypeJWK+";charset=utf-8", func() { suite.testJWKRejectSet(MediaTypeJWK + ";charset=utf-8") })
	})
}

func (suite *ParserSuite) testJWKSet(format string) {
	p := suite.newParser()
	keys, err := p.Parse(format, []byte(jwkSet))
	suite.Require().NoError(err)
	suite.Require().Len(keys, 7)

	k := keys[0]
	suite.Require().NotNil(k)
	suite.Equal("first", k.KeyID())
	suite.Empty(k.KeyUsage())
	suite.Equal(string(jwa.RSA), k.KeyType())
	suite.IsType((*rsa.PrivateKey)(nil), k.Raw())
	suite.IsType((*rsa.PublicKey)(nil), k.Public())

	k = keys[1]
	suite.Require().NotNil(k)
	suite.Empty(k.KeyUsage())
	suite.Equal(string(jwa.RSA), k.KeyType())
	suite.IsType((*rsa.PublicKey)(nil), k.Raw())
	suite.IsType((*rsa.PublicKey)(nil), k.Public())

	k = keys[2]
	suite.Require().NotNil(k)
	suite.Empty(k.KeyUsage())
	suite.Equal(string(jwa.EC), k.KeyType())
	suite.IsType((*ecdsa.PrivateKey)(nil), k.Raw())
	suite.IsType((*ecdsa.PublicKey)(nil), k.Public())

	k = keys[3]
	suite.Require().NotNil(k)
	suite.Empty(k.KeyUsage())
	suite.Equal(string(jwa.EC), k.KeyType())
	suite.IsType((*ecdsa.PublicKey)(nil), k.Raw())
	suite.IsType((*ecdsa.PublicKey)(nil), k.Public())

	k = keys[4]
	suite.Require().NotNil(k)
	suite.Empty(k.KeyUsage())
	suite.Equal(string(jwa.OctetSeq), k.KeyType())
	suite.IsType(([]byte)(nil), k.Raw())
	suite.IsType(([]byte)(nil), k.Public())
	suite.Equal(k.Raw(), k.Public())

	k = keys[5]
	suite.Require().NotNil(k)
	suite.Empty(k.KeyUsage())
	suite.Equal(string(jwa.OKP), k.KeyType())
	suite.IsType((ed25519.PrivateKey)(nil), k.Raw())
	suite.IsType((ed25519.PublicKey)(nil), k.Public())

	k = keys[6]
	suite.Require().NotNil(k)
	suite.Empty(k.KeyUsage())
	suite.Equal(string(jwa.OKP), k.KeyType())
	suite.IsType((ed25519.PublicKey)(nil), k.Raw())
	suite.IsType((ed25519.PublicKey)(nil), k.Public())
}

func (suite *ParserSuite) testJWKSetInvalid(format string) {
	p := suite.newParser()
	keys, err := p.Parse(format, []byte("this is in no way a valid JWK set"))
	suite.Empty(keys)
	suite.Error(err)
}

func (suite *ParserSuite) TestJWKSet() {
	suite.Run(SuffixJWKSet, func() { suite.testJWKSet(SuffixJWKSet) })
	suite.Run(MediaTypeJWKSet, func() { suite.testJWKSet(MediaTypeJWKSet) })

	suite.Run("Invalid", func() {
		suite.Run(SuffixJWKSet, func() { suite.testJWKSetInvalid(SuffixJWKSet) })
		suite.Run(MediaTypeJWKSet, func() { suite.testJWKSetInvalid(MediaTypeJWKSet) })
		suite.Run(MediaTypeJWKSet+";charset=utf-8", func() { suite.testJWKSetInvalid(MediaTypeJWKSet + ";charset=utf-8") })
	})
}

func (suite *ParserSuite) TestUnsupportedFormat() {
	const unsupportedFormat = "this is not a supported format"
	p := suite.newParser()
	keys, err := p.Parse(unsupportedFormat, []byte("does not matter"))
	suite.Empty(keys)

	var ufe *UnsupportedFormatError
	suite.Require().ErrorAs(err, &ufe)
	suite.Equal(unsupportedFormat, ufe.Format)
	suite.Contains(ufe.Error(), unsupportedFormat)
}

func (suite *ParserSuite) TestCustomParser() {
	var (
		expectedError = errors.New("expected")
		custom        = new(mockParser)

		p = suite.newParser(
			WithFormats(custom, "custom"),
		)
	)

	custom.ExpectParse("custom", []byte("content")).
		Return([]Key{}, expectedError).
		Once()

	keys, err := p.Parse("custom", []byte("content"))
	suite.Empty(keys)
	suite.ErrorIs(err, expectedError)
}

func (suite *ParserSuite) TestMIMEParameters() {
	p, err := NewParser(
		WithFormats(nil, "application/json;charset=utf-8"),
	)

	suite.Nil(p)
	suite.Error(err)
}

func TestParser(t *testing.T) {
	suite.Run(t, new(ParserSuite))
}
