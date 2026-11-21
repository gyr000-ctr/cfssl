package est

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/signer"
)

// maxRequestSize bounds the size of an enrollment request body.
const maxRequestSize = 1 << 20

// oidSubjectAltName is the SubjectAltName extension OID used to compare
// the SAN of a re-enrollment CSR with the certificate being renewed.
var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// identity describes the end entity a certificate is issued to. It is
// used to detect repeat enrollment for the same identity.
type identity struct {
	spki     []byte
	subject  string
	dnsNames []string
	ips      []string
	emails   []string
	uris     []string
}

func identityFromCertificate(cert *x509.Certificate) identity {
	id := identity{
		spki:     cert.RawSubjectPublicKeyInfo,
		subject:  subjectString(cert.Subject),
		dnsNames: append([]string(nil), cert.DNSNames...),
		emails:   append([]string(nil), cert.EmailAddresses...),
	}
	for _, ip := range cert.IPAddresses {
		id.ips = append(id.ips, ip.String())
	}
	for _, uri := range cert.URIs {
		id.uris = append(id.uris, uri.String())
	}
	id.sort()
	return id
}

func identityFromCSR(csr *x509.CertificateRequest) identity {
	id := identity{
		spki:     csr.RawSubjectPublicKeyInfo,
		subject:  subjectString(csr.Subject),
		dnsNames: append([]string(nil), csr.DNSNames...),
		emails:   append([]string(nil), csr.EmailAddresses...),
	}
	for _, ip := range csr.IPAddresses {
		id.ips = append(id.ips, ip.String())
	}
	for _, uri := range csr.URIs {
		id.uris = append(id.uris, uri.String())
	}
	id.sort()
	return id
}

func (id *identity) sort() {
	sort.Strings(id.dnsNames)
	sort.Strings(id.ips)
	sort.Strings(id.emails)
	sort.Strings(id.uris)
}

// subjectString renders a distinguished name in a stable, order-independent
// form. The signer re-encodes the CSR subject when it issues a certificate,
// so the subject must be compared after decoding rather than as DER, and
// the encoding may regroup attributes into different RDNs.
func subjectString(name pkix.Name) string {
	attrs := name.Names
	if len(attrs) == 0 {
		for _, rdn := range name.ToRDNSequence() {
			attrs = append(attrs, rdn...)
		}
	}
	parts := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		parts = append(parts, fmt.Sprintf("%s=%v", attr.Type.String(), attr.Value))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\x00")
}

// equal reports whether two identities are the same end entity.
func (id identity) equal(other identity) bool {
	return bytes.Equal(id.spki, other.spki) &&
		id.subject == other.subject &&
		equalStrings(id.dnsNames, other.dnsNames) &&
		equalStrings(id.ips, other.ips) &&
		equalStrings(id.emails, other.emails) &&
		equalStrings(id.uris, other.uris)
}

// sameSubject reports whether two identities name the same end entity,
// ignoring the public key. This is used for rekey requests.
func (id identity) sameSubject(other identity) bool {
	return id.subject == other.subject &&
		equalStrings(id.dnsNames, other.dnsNames) &&
		equalStrings(id.ips, other.ips) &&
		equalStrings(id.emails, other.emails) &&
		equalStrings(id.uris, other.uris)
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// issuedIndex records certificates issued by this handler. It lets repeat
// enrollment be detected even when no certificate database is configured.
type issuedIndex struct {
	mu    sync.Mutex
	certs []*x509.Certificate
}

func (x *issuedIndex) add(cert *x509.Certificate) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.certs = append(x.certs, cert)
	x.pruneLocked()
}

func (x *issuedIndex) pruneLocked() {
	now := time.Now()
	kept := x.certs[:0]
	for _, cert := range x.certs {
		if now.Before(cert.NotAfter) {
			kept = append(kept, cert)
		}
	}
	x.certs = kept
}

// find returns a currently valid certificate for id, if any.
func (x *issuedIndex) find(id identity) *x509.Certificate {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.pruneLocked()
	for _, cert := range x.certs {
		if identityFromCertificate(cert).equal(id) {
			return cert
		}
	}
	return nil
}

// findSubject returns a currently valid certificate for the end entity
// named by id, regardless of its public key.
func (x *issuedIndex) findSubject(id identity) *x509.Certificate {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.pruneLocked()
	for _, cert := range x.certs {
		if identityFromCertificate(cert).sameSubject(id) {
			return cert
		}
	}
	return nil
}

// serveCACerts serves the /cacerts operation. Client authentication is
// not required: RFC 7030 Section 4.1.2 says the server should not require
// it for this operation.
func (h *Handler) serveCACerts(w http.ResponseWriter, r *http.Request) *ESTError {
	return h.writeCertificates(w, h.caCerts)
}

// writeCertificates writes certs as a base64-encoded, certs-only PKCS #7
// response (RFC 7030 Sections 4.1.3 and 4.2.3).
func (h *Handler) writeCertificates(w http.ResponseWriter, certs []*x509.Certificate) *ESTError {
	der, err := EncodePKCS7(certs)
	if err != nil {
		log.Errorf("EST: encoding PKCS #7 response: %v", err)
		return errInternal
	}

	w.Header().Set("Content-Type", ContentTypePKCS7)
	w.Header().Set("Content-Transfer-Encoding", "base64")
	w.WriteHeader(http.StatusOK)

	encoded := base64.StdEncoding.EncodeToString(der)
	for len(encoded) > 64 {
		if _, err := io.WriteString(w, encoded[:64]+"\n"); err != nil {
			return nil
		}
		encoded = encoded[64:]
	}
	if len(encoded) > 0 {
		io.WriteString(w, encoded+"\n")
	}
	return nil
}

// serveEnroll serves /simpleenroll (reenroll == false) and
// /simplereenroll (reenroll == true).
func (h *Handler) serveEnroll(w http.ResponseWriter, r *http.Request, reenroll bool) *ESTError {
	who, authErr := h.authenticate(r)
	if authErr != nil {
		return authErr
	}

	if err := h.checkRequestContentType(r); err != nil {
		return err
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestSize)
	csr, csrPEM, err := readCSR(r)
	if err != nil {
		return err
	}

	id := identityFromCSR(csr)

	if reenroll {
		if err := h.checkReenrollment(who, csr, id); err != nil {
			return err
		}
	} else {
		existing, err := h.findIssued(id)
		if err != nil {
			return err
		}
		if existing != nil {
			log.Infof("EST: client already holds certificate %s", existing.SerialNumber)
			return errAlreadyEnrolled
		}
	}

	// Sign through the normal signer so that the CFSSL signing and CSR
	// handling flow, including policy checks, is unchanged. The signer
	// expects a PEM-encoded request.
	metadata := map[string]interface{}{
		"est_spki": sha256Hex(csr.RawSubjectPublicKeyInfo),
	}
	if who.cert != nil {
		metadata["est_authenticated_by"] = "certificate"
		metadata["est_client_serial"] = who.cert.SerialNumber.String()
	} else {
		metadata["est_authenticated_by"] = "basic"
	}

	certPEM, signErr := h.signer.Sign(signer.SignRequest{
		Request:  string(csrPEM),
		Profile:  h.profile,
		Label:    h.label,
		Metadata: metadata,
	})
	if signErr != nil {
		log.Warningf("EST: signing request failed: %v", signErr)
		return classifySignError(signErr)
	}

	cert, parseErr := helpers.ParseCertificatePEM(certPEM)
	if parseErr != nil {
		log.Errorf("EST: parsing issued certificate: %v", parseErr)
		return errInternal
	}

	if err := h.recordIssued(cert, metadata); err != nil {
		return err
	}
	h.issued.add(cert)

	return h.writeCertificates(w, []*x509.Certificate{cert})
}

// checkRequestContentType rejects requests that declare a media type other
// than application/pkcs10. A missing Content-Type is tolerated.
func (h *Handler) checkRequestContentType(r *http.Request) *ESTError {
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != MIMEPKCS10 {
		return errUnsupportedMediaType
	}
	return nil
}

// readCSR reads and parses a PKCS #10 request from r. The body may be
// base64-encoded DER (as EST requires) or PEM-encoded. It returns the
// parsed request and its PEM encoding.
func readCSR(r *http.Request) (*x509.CertificateRequest, []byte, *ESTError) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return nil, nil, &ESTError{
				Status:      http.StatusRequestEntityTooLarge,
				Description: "request body too large",
			}
		}
		return nil, nil, errBadRequest
	}
	r.Body.Close()

	der := bytes.TrimSpace(body)
	if block, _ := pem.Decode(der); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, nil, errBadRequest
		}
		der = block.Bytes
	} else {
		// EST sends the PKCS #10 structure base64-encoded. Accept both
		// standard and raw (unpadded) encodings.
		compact := compactWhitespace(body)
		decoded, decodeErr := base64.StdEncoding.DecodeString(compact)
		if decodeErr != nil {
			decoded, decodeErr = base64.RawStdEncoding.DecodeString(compact)
		}
		if decodeErr != nil {
			return nil, nil, &ESTError{
				Status:      http.StatusBadRequest,
				Description: "unable to decode base64 request body",
			}
		}
		der = decoded
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, &ESTError{
			Status:      http.StatusBadRequest,
			Description: "malformed PKCS10 certificate signing request",
		}
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, &ESTError{
			Status:      http.StatusBadRequest,
			Description: "invalid PKCS10 certificate signing request signature",
		}
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr.Raw})
	return csr, csrPEM, nil
}

func compactWhitespace(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
		default:
			sb.WriteByte(c)
		}
	}
	return sb.String()
}

// checkReenrollment enforces the RFC 7030 Section 4.2.2 requirement that a
// re-enrollment request has the same Subject and SubjectAltName as the
// certificate being renewed.
func (h *Handler) checkReenrollment(who *clientIdentity, csr *x509.CertificateRequest, id identity) *ESTError {
	subjectAltNameChanged := func(cert *x509.Certificate) bool {
		return !bytes.Equal(subjectAltName(csr.Extensions), subjectAltName(cert.Extensions))
	}

	if who.cert != nil {
		if identityFromCSR(csr).subject != identityFromCertificate(who.cert).subject || subjectAltNameChanged(who.cert) {
			return errSubjectChanged
		}
		return nil
	}

	// The client authenticated with HTTP Basic credentials, so there is no
	// client certificate to compare against. Require that a currently
	// valid certificate for the same end entity exists; this still allows
	// renewals and rekeys.
	existing, err := h.findIssuedSubject(id)
	if err != nil {
		return err
	}
	if existing == nil {
		return &ESTError{
			Status:      http.StatusForbidden,
			Description: "no existing certificate found for re-enrollment",
		}
	}
	if subjectAltNameChanged(existing) {
		return errSubjectChanged
	}
	return nil
}

// subjectAltName returns the raw value of the SubjectAltName extension, or
// nil if the extensions contain no SubjectAltName.
func subjectAltName(extensions []pkix.Extension) []byte {
	for _, ext := range extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			return ext.Value
		}
	}
	return nil
}

// findIssued looks for a valid certificate for id. The certificate
// database, when configured, is the source of truth; otherwise an
// in-memory index of certificates issued by this handler is used.
func (h *Handler) findIssued(id identity) (*x509.Certificate, *ESTError) {
	if h.db != nil {
		return h.findIssuedInDB(func(cert *x509.Certificate) bool {
			return identityFromCertificate(cert).equal(id)
		})
	}
	return h.issued.find(id), nil
}

// findIssuedSubject is like findIssued but ignores the public key.
func (h *Handler) findIssuedSubject(id identity) (*x509.Certificate, *ESTError) {
	if h.db != nil {
		return h.findIssuedInDB(func(cert *x509.Certificate) bool {
			return identityFromCertificate(cert).sameSubject(id)
		})
	}
	return h.issued.findSubject(id), nil
}

// findIssuedInDB returns the first unexpired, unrevoked certificate issued
// by this CA that matches. It returns nil if no certificate database is
// configured.
func (h *Handler) findIssuedInDB(match func(*x509.Certificate) bool) (*x509.Certificate, *ESTError) {
	if h.db == nil {
		return nil, nil
	}

	records, err := h.db.GetUnexpiredCertificates()
	if err != nil {
		log.Errorf("EST: listing certificates: %v", err)
		return nil, errInternal
	}

	for _, record := range records {
		if record.Status == "revoked" || !record.RevokedAt.IsZero() {
			continue
		}
		cert, err := helpers.ParseCertificatePEM([]byte(record.PEM))
		if err != nil {
			log.Warningf("EST: skipping unparseable certificate record %s: %v", record.Serial, err)
			continue
		}
		if !h.issuedByCA(cert) {
			continue
		}
		if match(cert) {
			return cert, nil
		}
	}
	return nil, nil
}

// issuedByCA reports whether cert was issued by one of the CA certificates
// this handler serves.
func (h *Handler) issuedByCA(cert *x509.Certificate) bool {
	for _, ca := range h.caCerts {
		if err := cert.CheckSignatureFrom(ca); err == nil {
			return true
		}
	}
	return false
}

// recordIssued stores the issued certificate in the certificate database
// when the signer does not do so itself, so that revocation and repeat
// enrollment checks keep working.
func (h *Handler) recordIssued(cert *x509.Certificate, metadata map[string]interface{}) *ESTError {
	if h.db == nil || h.signer.GetDBAccessor() != nil {
		// The signer records certificates when it has a database.
		return nil
	}

	now := time.Now()
	record := certdb.CertificateRecord{
		Serial:       cert.SerialNumber.String(),
		AKI:          hex.EncodeToString(cert.AuthorityKeyId),
		CALabel:      h.label,
		Status:       "good",
		Expiry:       cert.NotAfter,
		PEM:          string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		IssuedAt:     &now,
		NotBefore:    &cert.NotBefore,
		CommonName:   sql.NullString{String: cert.Subject.CommonName, Valid: true},
		MetadataJSON: nil,
	}
	if err := record.SetMetadata(metadata); err != nil {
		log.Errorf("EST: encoding certificate metadata: %v", err)
		return errInternal
	}
	if err := record.SetSANs(cert.DNSNames); err != nil {
		log.Errorf("EST: encoding certificate SANs: %v", err)
		return errInternal
	}
	if err := h.db.InsertCertificate(record); err != nil {
		log.Errorf("EST: recording issued certificate: %v", err)
		return errInternal
	}
	return nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
