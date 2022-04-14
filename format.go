package clortho

import "fmt"

const (
	// MediaTypeJSON is the media type for JSON data.  By default, content with this media type
	// may contain either a single JWK or a JWK set.
	MediaTypeJSON = "application/json"

	// SuffixJSON is the file suffix for JSON data.  By default, files with this suffix may
	// contain either a single JWK or a JWK Set.
	SuffixJSON = ".json"

	// MediaTypeJWK is the media type for a single JWK.
	MediaTypeJWK = "application/jwk+json"

	// SuffixJWK is the file suffix for a single JWK.
	SuffixJWK = ".jwk"

	// MediaTypeJWKSet is the media type for a JWK set.
	MediaTypeJWKSet = "application/jwk-set+json"

	// SuffixJWKSet is the file suffix for a JWK set.
	SuffixJWKSet = ".jwk-set"

	// MediaTypePEM is the media type for a PEM-encoded key.
	MediaTypePEM = "application/x-pem-file"

	// SuffixPEM is the file suffix for a PEM-encoded key.
	SuffixPEM = ".pem"

	// DefaultHTTPFormat is the format assumed when an HTTP response does not specify a Content-Type.
	DefaultHTTPFormat = "application/json"

	// DefaultFileFormat is the format assumed when no format can be deduced from a file.
	DefaultFileFormat = ".pem"
)

// UnsupportedFormatError indicates that a format (media type or file suffix) was passed
// to Parse which had no associated Parser.
type UnsupportedFormatError struct {
	Format string
}

// Error fulfills the error interface.
func (ufe *UnsupportedFormatError) Error() string {
	return fmt.Sprintf("Unsupported key format: %s", ufe.Format)
}
