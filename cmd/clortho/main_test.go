package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
)

// testKeys are some keys used to test appending.  All of these
// must be writable as PEM, which means only RSA and EC keys.
var testKeys []jwk.Key

func TestMain(m *testing.M) {
	var jwks = []string{
		`
{
    "p": "27VqGv1kaPMdw6smApE3dm-KtxQtyjBuNcsQGxUob1eCPh-duAiVN8uoj2vtkbtdh3nIo1eTVyer_IhYdphOYw",
    "kty": "RSA",
    "q": "1M-d1VjHrkWdiVGzqXGA-vnoUPt5Bo9G-bcdbm3zrR5WZaboqhFDRuunwombrJbBMOi98pARE0fLXnRs0wLKYQ",
    "d": "gR7j-Z_Hcr7suF7PPjxWhQfsMbCSKo53OeSdx4SqaceiskCk5j3TsufBSU02YrzFIZYxgBRTfMinjLKvLA5COQg1oE4rIhrICln3A1QNgntLpKDL5AkdGonta1DfntofhIKHrJwQLSEzkQn6wLl5QiQ_pgHD9392AlnCnQCz3QE",
    "e": "AQAB",
    "qi": "ENcoMXh1nABn5peN2jgjQ-wk_tRkFue9K3VNxjuEOgN_68XC-5qTkKpHgIUhD1k1yA6xuVqZmu0vfCHIUBfpfw",
    "dp": "fr-55rgoJSOcGDW0R-beyESxEc1iXTJzYjUzpWwfV5x0VsKGipTpALdNFvB8rYYZ_v4S8aikJ7OLVLST1FcpYQ",
    "dq": "CsfZvw0YUIPGT0aMS3Esj4pJcpDKuMJZXh0gqI95YLPAvLWP482sEtOtU_WUpVGdx9SCit8xfkCM1OQg_y-NAQ",
    "n": "tqRrBIHfnQVpcRFkQe0QNTYiC4TfX6LUnfUf06JNCWeGf0cvDDFimSMkaCIfbYeXUaOAM06trbeqAtdggnjiiqSZf-0KWA-WHbqpg2IQakwM3ciRGpZ--JE35u-dUgxRPSVbVB-O4QL5dBEL2e_OPTTTTJ8cI9OwvdXaqVNV0YM"
}`,
		`{
    "kty": "EC",
    "d": "mz-BEdTGNC9N5YjGwNoxo39MYHqjXV0FtNs221hT4R-ckZB6c87ORdFPuz8MHUUN",
    "crv": "P-384",
    "x": "-razbaki-k98Vds0RNFm7XodG2nDenmSDbrprXqzAejpkhQsPy4oPr-xRlqMXJuY",
    "y": "_ZctwhhyON95LOs0kPc38-cjE71RIZXm_WX-sc_MyggAIcK1JyqLO40eswLcXPtY"
}`,
	}

	testKeys = make([]jwk.Key, 0, len(jwks))
	for _, k := range jwks {
		key, err := jwk.ParseKey([]byte(k))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot parse test key: %s\n", err)
			os.Exit(1)
		}

		testKeys = append(testKeys, key)
	}

	os.Exit(m.Run())
}
