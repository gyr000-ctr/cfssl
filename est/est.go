package est

import (
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	cfsslErrors "github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/info"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// Operation paths defined by RFC 7030, Section 3.2.2. A server may serve
// multiple CAs by inserting an additional path segment (the CA label)
// between "est" and the operation path, so requests are matched on the
// operation path suffix and the label segment is ignored.
const (
	// PathCACerts is the path of the /cacerts operation.
	PathCACerts = "/.well-known/est/cacerts"
	// PathSimpleEnroll is the path of the /simpleenroll operation.
	PathSimpleEnroll = "/.well-known/est/simpleenroll"
	// PathSimpleReenroll is the path of the /simplereenroll operation.
	PathSimpleReenroll = "/.well-known/est/simplereenroll"
)

// BasicAuthFunc authenticates an HTTP Basic username and password. It
// returns nil if the credentials are valid.
type BasicAuthFunc func(r *http.Request, username, password string) error

// StaticBasicAuth returns a BasicAuthFunc that accepts the given
// username/password pairs. Credentials are compared in constant time.
func StaticBasicAuth(users map[string]string) BasicAuthFunc {
	return func(_ *http.Request, username, password string) error {
		want, ok := users[username]
		if !ok {
			// Compare anyway so that unknown users take the same time
			// as known ones.
			subtle.ConstantTimeCompare([]byte(password), []byte(password))
			return errors.New("est: unknown user")
		}
		if subtle.ConstantTimeCompare([]byte(want), []byte(password)) != 1 {
			return errors.New("est: invalid password")
		}
		return nil
	}
}

// Config configures an EST handler.
type Config struct {
	// Signer signs certificates for enrollment requests. It is required,
	// and enrollment goes through the normal signer.Sign flow.
	Signer signer.Signer

	// Profile is the signing profile used for enrollment and re-enrollment.
	// If empty, the signer's default profile is used.
	Profile string

	// Label is recorded as the label of issued certificates.
	Label string

	// CACerts is the certificate chain returned by /cacerts. The CA
	// certificate must come first. If empty, the signer's CA certificate
	// is used.
	CACerts []*x509.Certificate

	// Accessor, if set, is used to check whether a client certificate has
	// been revoked and whether a client has already enrolled. If nil, the
	// signer's certdb accessor is used when one is configured.
	Accessor certdb.Accessor

	// ClientCAs, if set, enables client-certificate authentication. A
	// certificate presented by the client must chain to one of these
	// roots and be valid for client authentication.
	ClientCAs *x509.CertPool

	// BasicAuth, if set, enables HTTP Basic authentication.
	BasicAuth BasicAuthFunc
}

// Handler serves the EST /cacerts, /simpleenroll and /simplereenroll
// operations. It implements http.Handler.
type Handler struct {
	signer    signer.Signer
	profile   string
	label     string
	caCerts   []*x509.Certificate
	db        certdb.Accessor
	clientCAs *x509.CertPool
	basicAuth BasicAuthFunc
	issued    issuedIndex
	now       func() time.Time
}

// NewHandler creates an EST handler from cfg.
func NewHandler(cfg Config) (*Handler, error) {
	if cfg.Signer == nil {
		return nil, errors.New("est: a signer is required")
	}
	if cfg.BasicAuth == nil && cfg.ClientCAs == nil {
		return nil, errors.New("est: at least one of BasicAuth and ClientCAs must be configured")
	}

	caCerts := cfg.CACerts
	if len(caCerts) == 0 {
		caCert, err := caCertificate(cfg.Signer, cfg.Profile)
		if err != nil {
			return nil, err
		}
		caCerts = []*x509.Certificate{caCert}
	}
	for i, cert := range caCerts {
		if cert == nil {
			return nil, fmt.Errorf("est: CA certificate %d is nil", i)
		}
	}

	db := cfg.Accessor
	if db == nil {
		db = cfg.Signer.GetDBAccessor()
	}

	return &Handler{
		signer:    cfg.Signer,
		profile:   cfg.Profile,
		label:     cfg.Label,
		caCerts:   caCerts,
		db:        db,
		clientCAs: cfg.ClientCAs,
		basicAuth: cfg.BasicAuth,
		now:       time.Now,
	}, nil
}

// caCertificate gets the signer's CA certificate through the regular Info
// call so that remote signers work too.
func caCertificate(s signer.Signer, profile string) (*x509.Certificate, error) {
	resp, err := s.Info(info.Req{Profile: profile})
	if err != nil {
		return nil, fmt.Errorf("est: getting CA certificate: %w", err)
	}
	if resp == nil || resp.Certificate == "" {
		return nil, errors.New("est: signer did not return a CA certificate")
	}
	cert, err := helpers.ParseCertificatePEM([]byte(resp.Certificate))
	if err != nil {
		return nil, fmt.Errorf("est: parsing CA certificate: %w", err)
	}
	return cert, nil
}

// CACerts returns the certificate chain served by /cacerts.
func (h *Handler) CACerts() []*x509.Certificate {
	out := make([]*x509.Certificate, len(h.caCerts))
	copy(out, h.caCerts)
	return out
}

type operation int

const (
	opUnknown operation = iota
	opCACerts
	opSimpleEnroll
	opSimpleReenroll
)

// operationForPath returns the EST operation for a request path. The path
// is /.well-known/est/<operation>, optionally with a single CA label
// segment before the operation (RFC 7030, Section 3.2.2). A handler
// mounted with http.StripPrefix receives "/<operation>" and is accepted
// too.
func operationForPath(path string) operation {
	const prefix = "/.well-known/est/"
	var rest string
	switch {
	case strings.HasPrefix(path, prefix):
		rest = strings.TrimPrefix(path, prefix)
	case strings.HasPrefix(path, "/"):
		// Mounted under a stripped prefix.
		rest = strings.TrimPrefix(path, "/")
	default:
		return opUnknown
	}
	rest = strings.TrimSuffix(rest, "/")

	// Strip at most one additional path segment, the CA label.
	if i := strings.LastIndex(rest, "/"); i >= 0 {
		label := rest[:i]
		if label == "" || strings.Contains(label, "/") {
			return opUnknown
		}
		rest = rest[i+1:]
	}

	switch rest {
	case "cacerts":
		return opCACerts
	case "simpleenroll":
		return opSimpleEnroll
	case "simplereenroll":
		return opSimpleReenroll
	}
	return opUnknown
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	op := operationForPath(r.URL.Path)
	if op == opUnknown {
		http.NotFound(w, r)
		return
	}

	var err *ESTError
	switch op {
	case opCACerts:
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			methodNotAllowed(w, http.MethodGet)
			return
		}
		err = h.serveCACerts(w, r)
	default:
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		reenroll := op == opSimpleReenroll
		err = h.serveEnroll(w, r, reenroll)
	}
	if err != nil {
		writeESTError(w, err, h.basicAuth != nil)
	}
}

func methodNotAllowed(w http.ResponseWriter, allowed string) {
	w.Header().Set("Allow", allowed)
	writeESTError(w, &ESTError{
		Status:      http.StatusMethodNotAllowed,
		Description: "method not allowed",
	}, false)
}

// writeESTError writes err to w. If challenge is true and the error is an
// authentication failure, a WWW-Authenticate header is included so that
// the client can retry with HTTP Basic credentials (RFC 7030,
// Section 3.2.3).
func writeESTError(w http.ResponseWriter, err *ESTError, challenge bool) {
	if err.Status == http.StatusUnauthorized && challenge {
		w.Header().Set("WWW-Authenticate", `Basic realm="EST"`)
	}
	log.Infof("EST request failed: %d %s", err.Status, err.Error())
	err.Write(w)
}

// clientIdentity is the result of authenticating a request.
type clientIdentity struct {
	// cert is the verified client certificate, or nil if the request was
	// authenticated with HTTP Basic credentials only.
	cert *x509.Certificate
}

// authenticate authenticates r using a client certificate or HTTP Basic
// credentials. If no credentials were supplied it returns errAuthRequired.
func (h *Handler) authenticate(r *http.Request) (*clientIdentity, *ESTError) {
	presentedCert, certErr := h.verifyClientCertificate(r)
	if certErr == nil && presentedCert != nil {
		id := &clientIdentity{cert: presentedCert}
		if err := h.checkCertificateNotRevoked(presentedCert); err != nil {
			return nil, err
		}
		return id, nil
	}

	// A client certificate was supplied but is not acceptable. Report that
	// rather than asking for credentials that the client may not have.
	if certErr != nil {
		return nil, certErr
	}

	if h.basicAuth != nil {
		username, password, ok := r.BasicAuth()
		if ok {
			if err := h.basicAuth(r, username, password); err != nil {
				log.Warningf("EST: Basic authentication failed: %v", err)
				return nil, errAuthFailed
			}
			return &clientIdentity{}, nil
		}
	}

	return nil, errAuthRequired
}

// verifyClientCertificate verifies a client certificate presented in the
// TLS handshake. It returns (nil, nil) if there is no client certificate to
// verify.
func (h *Handler) verifyClientCertificate(r *http.Request) (*x509.Certificate, *ESTError) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, nil
	}
	if h.clientCAs == nil {
		// Client certificate authentication is not configured, so a
		// certificate presented by the client cannot be trusted.
		return nil, nil
	}

	leaf := r.TLS.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, cert := range r.TLS.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         h.clientCAs,
		Intermediates: intermediates,
		CurrentTime:   h.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		log.Warningf("EST: rejecting client certificate: %v", err)
		var invalid x509.CertificateInvalidError
		if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
			return nil, errClientCertExpired
		}
		return nil, errInvalidClientCert
	}
	return leaf, nil
}

// checkCertificateNotRevoked looks the certificate up in the certificate
// database and reports whether it has been revoked.
//
// Some cfssl configurations keep issued certificates only in the signer's
// CRL database and some do not use a database at all, so an unknown
// certificate is not by itself a reason to reject it: the certificate has
// already been verified against the configured client CA. If the lookup
// itself fails, though, revocation cannot be determined and the request is
// refused.
func (h *Handler) checkCertificateNotRevoked(cert *x509.Certificate) *ESTError {
	if h.db == nil {
		return nil
	}
	records, err := h.db.GetCertificate(cert.SerialNumber.String(), certAKI(cert))
	if err != nil {
		log.Errorf("EST: looking up certificate %s: %v", cert.SerialNumber, err)
		return errInternal
	}
	for _, record := range records {
		if record.Status == "revoked" || !record.RevokedAt.IsZero() {
			log.Warningf("EST: client certificate %s has been revoked", cert.SerialNumber)
			return errRevokedClientCert
		}
	}
	return nil
}

// certAKI returns the hex-encoded authority key identifier as stored by
// certdb.
func certAKI(cert *x509.Certificate) string {
	return fmt.Sprintf("%x", cert.AuthorityKeyId)
}

// classifySignError converts a signer error into a client-facing EST
// error. Signer errors caused by the request (a bad CSR or a policy
// rejection) are reported as bad requests; everything else is an internal
// error.
func classifySignError(err error) *ESTError {
	var httpErr *cfsslErrors.HTTPError
	var cfErr *cfsslErrors.Error
	switch {
	case errors.As(err, &httpErr):
		return &ESTError{Status: httpErr.StatusCode, Description: httpErr.Error()}
	case errors.As(err, &cfErr):
		// 4xxx and 9xxx codes are request problems (bad CSR, bad
		// policy); 5xxx is a policy rejection. Report them all as
		// bad requests.
		return &ESTError{Status: http.StatusBadRequest, Description: cfErr.Message}
	default:
		log.Errorf("EST: signing failed: %v", err)
		return errInternal
	}
}
