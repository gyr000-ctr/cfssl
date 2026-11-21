package est

import (
	"fmt"
	"net/http"
)

// ESTError is an error returned by an EST handler. It carries the HTTP
// status code that RFC 7030 (Section 4.2.3) requires the server to use
// when rejecting an enrollment request, and is written to the client as a
// plain-text, human-readable message as described in that section.
type ESTError struct {
	// Status is the HTTP status code to return.
	Status int
	// Description is a human-readable explanation. It is written to
	// the response body.
	Description string
}

// Error implements the error interface.
func (e *ESTError) Error() string {
	if e.Description == "" {
		return http.StatusText(e.Status)
	}
	return e.Description
}

// Write writes the error to w as plain text, together with its status code.
func (e *ESTError) Write(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(e.Status)
	fmt.Fprintf(w, "%d %s\n", e.Status, e.Error())
}

// The standard EST errors used by this package.
var (
	// errAuthRequired is used when no client credentials were supplied.
	// RFC 7030 Section 3.2.3 requires that the server reject the request
	// with a WWW-Authenticate header so that the client can retry with
	// HTTP Basic authentication.
	errAuthRequired = &ESTError{
		Status:      http.StatusUnauthorized,
		Description: "authorization required",
	}
	// errAuthFailed is used when credentials were supplied but are wrong.
	errAuthFailed = &ESTError{
		Status:      http.StatusUnauthorized,
		Description: "authentication failed",
	}
	// errInvalidClientCert is used when a client certificate is supplied
	// but is not acceptable for the requested operation.
	errInvalidClientCert = &ESTError{
		Status:      http.StatusForbidden,
		Description: "invalid client certificate",
	}
	// errClientCertExpired is like errInvalidClientCert but is returned
	// when the certificate is simply no longer valid, since a node whose
	// certificate has expired still needs to be able to re-enroll.
	errClientCertExpired = &ESTError{
		Status:      http.StatusForbidden,
		Description: "client certificate has expired",
	}
	// errRevokedClientCert is used when the authenticated client's
	// certificate has been revoked.
	errRevokedClientCert = &ESTError{
		Status:      http.StatusUnauthorized,
		Description: "client certificate has been revoked",
	}
	// errAlreadyEnrolled is used when a simpleenroll request is made by a
	// client that already holds a valid certificate. RFC 7030 Section
	// 4.2.2 defines /simplereenroll for the renewal or rekey of an
	// existing certificate, and /simpleenroll is not permitted to
	// duplicate a successful enrollment.
	errAlreadyEnrolled = &ESTError{
		Status:      http.StatusConflict,
		Description: "client already has a valid certificate; use /simplereenroll to renew or rekey",
	}
	// errNoClientCert is used for a simplereenroll request that was not
	// authenticated with a client certificate.
	errNoClientCert = &ESTError{
		Status:      http.StatusForbidden,
		Description: "client certificate must be provided for /simplereenroll",
	}
	// errSubjectChanged is used when a simplereenroll request asks for a
	// Subject or SubjectAltName different from the certificate being
	// renewed. RFC 7030 Section 4.2.2 requires these to be identical.
	errSubjectChanged = &ESTError{
		Status:      http.StatusForbidden,
		Description: "Subject and SubjectAltName fields in the CSR must be identical to the certificate being renewed",
	}
	// errUnsupportedMediaType is used when the request body is not one of
	// the media types defined for the operation.
	errUnsupportedMediaType = &ESTError{
		Status:      http.StatusUnsupportedMediaType,
		Description: "unsupported content type",
	}
	// errBadRequest is used for malformed enrollment requests.
	errBadRequest = &ESTError{
		Status:      http.StatusBadRequest,
		Description: "malformed enrollment request",
	}
	// errInternal is used for unexpected server-side failures.
	errInternal = &ESTError{
		Status:      http.StatusInternalServerError,
		Description: "internal server error",
	}
)
