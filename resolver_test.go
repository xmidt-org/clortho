package clortho

import (
	"context"
	"testing"

	"github.com/stretchr/testify/suite"
)

const (

	// resolverTestKey is a known, good key for testing the Resolver code
	resolverTestKey = `
{
    "kid": "testKey",
    "p": "5I2R0qjqeBsdkOIOiIKwzJUhcqJrH2Q_V0EuNCCjrKBl6TNuX6t8ToLV2o57yu1nT4B4R2UVQOsRfi3y7ZpnvwK8b997vCC2M3jnTJ56SBYF9mO46fsRP3OeuRw8A0owTCXw8TbSYIuQw-agBME2N50u3Lgk1lTqZBCZ9U5tsHc",
    "kty": "RSA",
    "q": "qjf1QXyLlX8wxiEqyP0D1cLQCjnoKnlWQjKCFX54wexU92a6zjc6k5dAOCRNXWlttbZgGZnNBjIc0aYfYeYNfIP1BBQr094AjG7p6j6cSXKi2qwZG63PLgSsoUvp_W22jpqdnmA7oXYE-epl2gF2q1QGOrW2yMx4n2sJKI6AW7s",
    "d": "E5DzvlXUCubwPHNWo-H5L3r572hxsrGcKHSJhTrRh5IRv_h7rEMlZ-umMIpem_7yn3yjpMlxkcf2E20usXGsM0lRRo5iqM--tFlDesY-PcJA4QWiVkCm0HQlhKq8LFFJ3BD-FPlbqLU5a9vQppmJ26aW4UYCXfTMzx7p31SxDv84IZkiWlnuuJzl2TkfPxMxf8g7zFd2Ea3kPjBX8ZH_lLt4fNCGL1BGc7_cRKopnmL3r_o8sPI5NU4dC2WKkeXsnOdAMhbyxttP3i5a1S9rpdOs_H6xO2M-F0pEklQ35MZSSlBjnl9MDvEF6pyrqOwnRRJU2Uf-orgWx-3ArjyuqQ",
    "e": "AQAB",
    "qi": "vRxU0W7YQz3EIaFE3-2RJv5tjXz_6nrBagHtqF30MrfgkdDmlXAqwQVm3-5KZwa7vt2AAaafx2F_lxlpUoIHaOj04sr80HLm7DvrW6t5JZLXWXE-7BurTywO4EKugcjawh387jEQzo9cPwkEj-Sm-IwkpFMzE93lQw5slf4zKRI",
    "dp": "ugnKozE_-hgITwDTV6caBs11dnxiuiC9tmamF2RiFohRrCtjMpjCDJ5POSI1_g6Uw5ANWAAd9sPhb1YzodjHjiHKBT5i19XAudE2ZZWyb68Nl2vA_ySQ-5c_oeorp3niKnnP0GkRgejZI708j-I-IbLejGeQBK8GRAGHcLgwbS0",
    "dq": "RKDREjkbsgeY65j9vhE81Zd491aHg3BuVbw1dGMMXuthCmpx0Ki1xkHKE5iXVJ0oLYY9UrUO03uq4OAAcSEmuNgfFijnzsEIKZaiWt4pdvdwL4gJi35VNLGPxGxuB86PNwmhmPQltqB1uylFLVM_vC3hYRRYgLbnvyaRh7eEivc",
    "n": "l_f4Niwf0T9Cya4tuj0yGnXhIGnbFOmyRgsactAWZuXEO8ZYXp8l5TZe5-2HM5ARbYBOrornCbG4n82UjvfbvmR_57fzmOuogV1Btx4Q_WfmXzgbi1iuyS0kvBvv88mTyrCjSH46rXG22vacQhV-bZkLtOhiqUQakxMkxzj9BHGp-ubjOW7N6FOC8nIRARWN3S8QJLEMX28RDOsHHa7xdD9-29hTcLbv0NuE-ISKG6DW8hhLAWZBwpF4WKukfpeH8difnq31vvGwmW2cqss7WTBVxP6sOQ_NHUnU_og_PyjIcl0bO6QTysPSb5eQ5fv0ovtDWSGzuMzSF3ljhVoz7Q"
}`

	// resolverTestKeySet is JWK set that contains the resolveTestKey and
	// a couple of other keys.
	resolverTestKeySet = `
{
    "keys": [
        {
            "kty": "oct",
            "k": "1bzFnOuMfzKvFYUpggi5U6YfOfI9opANo0NBhgxoyCV_LNMaxhhZeseOV0AxM4lS3zlYpe6GCwA6dsknsJk6ANtWnwoCbRiKN3icLfJ238fEsdHjZSmP16twfnRo3G25Xg8JelJLXnbY1sGdb8a3J8GreGA8n6KxVlZ6NPjE9X0"
        },
        {
		    "kid": "testKey",
            "p": "5I2R0qjqeBsdkOIOiIKwzJUhcqJrH2Q_V0EuNCCjrKBl6TNuX6t8ToLV2o57yu1nT4B4R2UVQOsRfi3y7ZpnvwK8b997vCC2M3jnTJ56SBYF9mO46fsRP3OeuRw8A0owTCXw8TbSYIuQw-agBME2N50u3Lgk1lTqZBCZ9U5tsHc",
            "kty": "RSA",
            "q": "qjf1QXyLlX8wxiEqyP0D1cLQCjnoKnlWQjKCFX54wexU92a6zjc6k5dAOCRNXWlttbZgGZnNBjIc0aYfYeYNfIP1BBQr094AjG7p6j6cSXKi2qwZG63PLgSsoUvp_W22jpqdnmA7oXYE-epl2gF2q1QGOrW2yMx4n2sJKI6AW7s",
            "d": "E5DzvlXUCubwPHNWo-H5L3r572hxsrGcKHSJhTrRh5IRv_h7rEMlZ-umMIpem_7yn3yjpMlxkcf2E20usXGsM0lRRo5iqM--tFlDesY-PcJA4QWiVkCm0HQlhKq8LFFJ3BD-FPlbqLU5a9vQppmJ26aW4UYCXfTMzx7p31SxDv84IZkiWlnuuJzl2TkfPxMxf8g7zFd2Ea3kPjBX8ZH_lLt4fNCGL1BGc7_cRKopnmL3r_o8sPI5NU4dC2WKkeXsnOdAMhbyxttP3i5a1S9rpdOs_H6xO2M-F0pEklQ35MZSSlBjnl9MDvEF6pyrqOwnRRJU2Uf-orgWx-3ArjyuqQ",
            "e": "AQAB",
            "qi": "vRxU0W7YQz3EIaFE3-2RJv5tjXz_6nrBagHtqF30MrfgkdDmlXAqwQVm3-5KZwa7vt2AAaafx2F_lxlpUoIHaOj04sr80HLm7DvrW6t5JZLXWXE-7BurTywO4EKugcjawh387jEQzo9cPwkEj-Sm-IwkpFMzE93lQw5slf4zKRI",
            "dp": "ugnKozE_-hgITwDTV6caBs11dnxiuiC9tmamF2RiFohRrCtjMpjCDJ5POSI1_g6Uw5ANWAAd9sPhb1YzodjHjiHKBT5i19XAudE2ZZWyb68Nl2vA_ySQ-5c_oeorp3niKnnP0GkRgejZI708j-I-IbLejGeQBK8GRAGHcLgwbS0",
            "dq": "RKDREjkbsgeY65j9vhE81Zd491aHg3BuVbw1dGMMXuthCmpx0Ki1xkHKE5iXVJ0oLYY9UrUO03uq4OAAcSEmuNgfFijnzsEIKZaiWt4pdvdwL4gJi35VNLGPxGxuB86PNwmhmPQltqB1uylFLVM_vC3hYRRYgLbnvyaRh7eEivc",
            "n": "l_f4Niwf0T9Cya4tuj0yGnXhIGnbFOmyRgsactAWZuXEO8ZYXp8l5TZe5-2HM5ARbYBOrornCbG4n82UjvfbvmR_57fzmOuogV1Btx4Q_WfmXzgbi1iuyS0kvBvv88mTyrCjSH46rXG22vacQhV-bZkLtOhiqUQakxMkxzj9BHGp-ubjOW7N6FOC8nIRARWN3S8QJLEMX28RDOsHHa7xdD9-29hTcLbv0NuE-ISKG6DW8hhLAWZBwpF4WKukfpeH8difnq31vvGwmW2cqss7WTBVxP6sOQ_NHUnU_og_PyjIcl0bO6QTysPSb5eQ5fv0ovtDWSGzuMzSF3ljhVoz7Q"
        },
        {
		    "kid": "anotherKey",
            "kty": "OKP",
            "d": "AmXEBENjL8hKtEqC2WPS00hgdDaNEzKRkZX1vhZaaII",
            "crv": "Ed25519",
            "x": "RMK6ix73LXxbfjIxcxPTcsl9--B3osUQfk600q2HXs8"
        }]
}`
)

type ResolverSuite struct {
	suite.Suite

	testKey    Key
	testKeySet []Key
}

func (suite *ResolverSuite) SetupTest() {
	p, err := NewParser()
	suite.Require().NoError(err)
	suite.Require().NotNil(p)

	keys, err := p.Parse(MediaTypeJWK, []byte(resolverTestKey))
	suite.Require().NoError(err)
	suite.Len(keys, 1)
	suite.testKey = keys[0]

	keys, err = p.Parse(MediaTypeJWKSet, []byte(resolverTestKeySet))
	suite.Require().NoError(err)
	suite.Require().Len(keys, 3)
	suite.testKeySet = keys
}

func (suite *ResolverSuite) newResolver(options ...ResolverOption) Resolver {
	r, err := NewResolver(options...)
	suite.Require().NoError(err)
	suite.Require().NotNil(r)
	return r
}

func (suite *ResolverSuite) TestNoKeyIDTemplate() {
	r, err := NewResolver()
	suite.Error(err)
	suite.Nil(r)
}

func (suite *ResolverSuite) TestDefault() {
	r := suite.newResolver(
		WithKeyIDTemplate("http://getkeys.com/{keyID}"),
	)

	suite.Require().IsType((*resolver)(nil), r)
	suite.NotNil(r.(*resolver).fetcher)
}

func (suite *ResolverSuite) TestSimple() {
	var (
		f = new(mockFetcher)
		r = suite.newResolver(
			WithFetcher(f),
			WithKeyIDTemplate("http://getkeys.com/{keyID}"),
		)
	)

	f.ExpectFetch(context.Background(), "http://getkeys.com/testKey", ContentMeta{}).
		Return([]Key{suite.testKey}, ContentMeta{}, error(nil)).
		Once()

	key, err := r.Resolve(context.Background(), "testKey")
	suite.NoError(err)
	suite.Require().NotNil(key)
	suite.Equal(suite.testKey, key)

	f.AssertExpectations(suite.T())
}

func TestResolver(t *testing.T) {
	suite.Run(t, new(ResolverSuite))
}
