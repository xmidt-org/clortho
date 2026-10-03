// SPDX-FileCopyrightText: 2026 Comcast Cable Communications Management, LLC
// SPDX-License-Identifier: Apache-2.0

package clorthometrics

import (
	"errors"
	"io/fs"
	"net"
	"strconv"

	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/xmidt-org/clortho"
)

// The values of ReasonLabel.  The set is fixed so that the label cannot grow
// without bound, whatever a source serves.
const (
	reasonTooLarge       = "too_large"
	reasonSymmetricKey   = "symmetric_key"
	reasonMissingKeyID   = "missing_key_id"
	reasonDuplicateKeyID = "duplicate_key_id"
	reasonHTTPPrefix     = "http_"
	reasonHTTPOther      = "http_other"
	reasonUnreachable    = "unreachable"
	reasonUnreadableFile = "unreadable_file"
	reasonUnparseable    = "unparseable"
	reasonOther          = "other"
)

// reason classifies the error from a failed refresh as one ReasonLabel value.
//
// A key set can be rejected for several faults at once.  The first one in the
// order below is the one reported, so the same set always gets the same
// reason.
func reason(err error) string {
	var (
		httpErr *clortho.HTTPError
		netErr  net.Error
		pathErr *fs.PathError
	)

	switch {
	case errors.Is(err, clortho.ErrResponseTooLarge):
		return reasonTooLarge

	case errors.Is(err, clortho.ErrSymmetricKey):
		return reasonSymmetricKey

	case errors.Is(err, clortho.ErrMissingKeyID):
		return reasonMissingKeyID

	case errors.Is(err, clortho.ErrDuplicateKeyID):
		return reasonDuplicateKeyID

	case errors.As(err, &httpErr):
		return httpReason(httpErr.StatusCode)

	case errors.As(err, &pathErr):
		// this comes before the net.Error case.  a path error wraps a syscall
		// error number, which also satisfies net.Error.
		return reasonUnreadableFile

	case errors.As(err, &netErr):
		// the client's own errors, a timeout included, all satisfy net.Error
		return reasonUnreachable

	case errors.Is(err, jwk.ParseError()):
		return reasonUnparseable

	default:
		return reasonOther
	}
}

// httpReason names an HTTP status.  A status outside the range HTTP defines
// is folded into one value, so that a misbehaving server cannot mint labels.
func httpReason(statusCode int) string {
	if statusCode < 100 || statusCode > 599 {
		return reasonHTTPOther
	}

	return reasonHTTPPrefix + strconv.Itoa(statusCode)
}
