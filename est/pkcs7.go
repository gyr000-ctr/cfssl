// Package est implements the subset of Enrollment over Secure Transport
// (RFC 7030) needed to enroll devices against a CFSSL CA: the /cacerts,
// /simpleenroll and /simplereenroll operations.
//
// The package only adds an HTTP handler. It uses the existing signer and
// CSR handling code, so the ordinary CFSSL signing and CSR flows are
// unaffected.
package est

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// Content types used by EST (RFC 7030, Section 3.2.4).
const (
	// MIMEPKCS10 is the media type of a certificate signing request.
	MIMEPKCS10 = "application/pkcs10"
	// MIMEPKCS7 is the media type of a certs-only PKCS #7 response.
	MIMEPKCS7 = "application/pkcs7-mime"
	// ContentTypePKCS7 is the full Content-Type of an EST PKCS #7
	// certificate response.
	ContentTypePKCS7 = MIMEPKCS7 + `; smime-type=certs-only`
)

var (
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
)

// EncodePKCS7 encodes certs as a degenerate PKCS #7 SignedData structure
// ("certs-only"), as required by RFC 7030 Sections 4.1.3 and 4.2.3.
//
// The result is the DER encoding of a SignedData ContentInfo with no
// signers. The certificates are stored in the certificates field, and an
// empty CRLs field is emitted so that parsers which expect the field to be
// present (including cfssl's crypto/pkcs7) can decode the structure.
func EncodePKCS7(certs []*x509.Certificate) ([]byte, error) {
	if len(certs) == 0 {
		return nil, errors.New("est: no certificates to encode")
	}

	// The signedData certificates field is [0] IMPLICIT and holds the
	// concatenated DER encodings of the certificates.
	var rawCerts []byte
	for _, cert := range certs {
		if cert == nil || len(cert.Raw) == 0 {
			return nil, errors.New("est: certificate is not DER encoded")
		}
		rawCerts = append(rawCerts, cert.Raw...)
	}

	emptySet := asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSet,
		IsCompound: true,
	}

	// Encapsulated content: a data ContentInfo. The Simple PKI Response
	// does not carry any content, so the data is empty.
	contentInfo, err := asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
	}{oidData})
	if err != nil {
		return nil, fmt.Errorf("est: encoding content info: %w", err)
	}

	signedData, err := asn1.Marshal(struct {
		Version          int
		DigestAlgorithms asn1.RawValue
		ContentInfo      asn1.RawValue
		Certificates     asn1.RawValue
		CRLs             asn1.RawValue
		SignerInfos      asn1.RawValue
	}{
		// RFC 2315 Section 9.1: version is 1 when the certificates are
		// X.509 certificates and no attribute certificates are present.
		Version:          1,
		DigestAlgorithms: emptySet,
		ContentInfo:      asn1.RawValue{FullBytes: contentInfo},
		Certificates: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      rawCerts,
		},
		// [1] IMPLICIT SET OF CertificateRevocationList, empty.
		CRLs: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        1,
			IsCompound: true,
		},
		SignerInfos: emptySet,
	})
	if err != nil {
		return nil, fmt.Errorf("est: encoding signed data: %w", err)
	}

	contentInfo, err = asn1.Marshal(struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue
	}{
		ContentType: oidSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      signedData,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("est: encoding PKCS #7: %w", err)
	}

	return contentInfo, nil
}
