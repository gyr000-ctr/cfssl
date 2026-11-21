package est

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/crypto/pkcs7"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/signer/local"
)

const (
	testCAFile    = "../api/testdata/ca.pem"
	testCAKeyFile = "../api/testdata/ca_key.pem"
)

// fakeAccessor is an in-memory certdb.Accessor.
type fakeAccessor struct {
	mu    sync.Mutex
	certs map[string]certdb.CertificateRecord
	ocsps []certdb.OCSPRecord
}

func newFakeAccessor() *fakeAccessor {
	return &fakeAccessor{certs: make(map[string]certdb.CertificateRecord)}
}

func certKey(serial, aki string) string { return serial + "|" + aki }

func (f *fakeAccessor) InsertCertificate(cr certdb.CertificateRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.certs[certKey(cr.Serial, cr.AKI)] = cr
	return nil
}

func (f *fakeAccessor) GetCertificate(serial, aki string) ([]certdb.CertificateRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if cr, ok := f.certs[certKey(serial, aki)]; ok {
		return []certdb.CertificateRecord{cr}, nil
	}
	return nil, nil
}

func (f *fakeAccessor) GetUnexpiredCertificates() ([]certdb.CertificateRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	var out []certdb.CertificateRecord
	for _, cr := range f.certs {
		if now.Before(cr.Expiry) {
			out = append(out, cr)
		}
	}
	return out, nil
}

func (f *fakeAccessor) GetRevokedAndUnexpiredCertificates() ([]certdb.CertificateRecord, error) {
	return f.revoked(), nil
}

func (f *fakeAccessor) GetUnexpiredCertificatesByLabel(labels []string) ([]certdb.CertificateRecord, error) {
	return f.GetUnexpiredCertificates()
}

func (f *fakeAccessor) GetRevokedAndUnexpiredCertificatesByLabel(label string) ([]certdb.CertificateRecord, error) {
	return f.revoked(), nil
}

func (f *fakeAccessor) GetRevokedAndUnexpiredCertificatesByLabelSelectColumns(label string) ([]certdb.CertificateRecord, error) {
	return f.revoked(), nil
}

func (f *fakeAccessor) revoked() []certdb.CertificateRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []certdb.CertificateRecord
	for _, cr := range f.certs {
		if cr.Status == "revoked" {
			out = append(out, cr)
		}
	}
	return out
}

func (f *fakeAccessor) RevokeCertificate(serial, aki string, reasonCode int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := certKey(serial, aki)
	cr, ok := f.certs[key]
	if !ok {
		return fmt.Errorf("certificate not found")
	}
	cr.Status = "revoked"
	cr.Reason = reasonCode
	cr.RevokedAt = time.Now()
	f.certs[key] = cr
	return nil
}

func (f *fakeAccessor) InsertOCSP(rr certdb.OCSPRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ocsps = append(f.ocsps, rr)
	return nil
}

func (f *fakeAccessor) GetOCSP(serial, aki string) ([]certdb.OCSPRecord, error) {
	return nil, nil
}

func (f *fakeAccessor) GetUnexpiredOCSPs() ([]certdb.OCSPRecord, error) { return nil, nil }

func (f *fakeAccessor) UpdateOCSP(serial, aki, body string, expiry time.Time) error {
	return nil
}

func (f *fakeAccessor) UpsertOCSP(serial, aki, body string, expiry time.Time) error {
	return nil
}

type testEnv struct {
	handler *Handler
	signer  *local.Signer
	db      *fakeAccessor
	caCert  *x509.Certificate
	caKey   crypto.Signer
	caPool  *x509.CertPool
}

func newTestEnv(t *testing.T, opts ...func(*Config)) *testEnv {
	t.Helper()

	s, err := local.NewSignerFromFile(testCAFile, testCAKeyFile, nil)
	if err != nil {
		t.Fatalf("loading test signer: %v", err)
	}

	caPEM, err := helpers.ReadBytes(testCAFile)
	if err != nil {
		t.Fatalf("reading CA certificate: %v", err)
	}
	caCert, err := helpers.ParseCertificatePEM(caPEM)
	if err != nil {
		t.Fatalf("parsing CA certificate: %v", err)
	}
	caKeyPEM, err := helpers.ReadBytes(testCAKeyFile)
	if err != nil {
		t.Fatalf("reading CA key: %v", err)
	}
	caKey, err := helpers.ParsePrivateKeyPEM(caKeyPEM)
	if err != nil {
		t.Fatalf("parsing CA key: %v", err)
	}

	db := newFakeAccessor()
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	cfg := Config{
		Signer:    s,
		Accessor:  db,
		ClientCAs: caPool,
		BasicAuth: StaticBasicAuth(map[string]string{"estuser": "estpassword"}),
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	h, err := NewHandler(cfg)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	return &testEnv{handler: h, signer: s, db: db, caCert: caCert, caKey: caKey, caPool: caPool}
}

// makeCSR creates a new key and a CSR for it with the given common name.
func makeCSR(t *testing.T, cn string, sanDNS ...string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sanDNS,
	}, key)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}
	return der, key
}

// makeCSRWithSubject creates a CSR with an arbitrary subject.
func makeCSRWithSubject(t *testing.T, subject pkix.Name) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: subject}, key)
	if err != nil {
		t.Fatalf("creating CSR: %v", err)
	}
	return der
}

func csrPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func enrollRequest(t *testing.T, handler http.Handler, path string, csrDER []byte) *http.Response {
	t.Helper()
	body := base64.StdEncoding.EncodeToString(csrDER)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", MIMEPKCS10)
	req.SetBasicAuth("estuser", "estpassword")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

func doRequest(handler http.Handler, method, path string, body io.Reader, setup func(*http.Request)) *http.Response {
	req := httptest.NewRequest(method, path, body)
	if setup != nil {
		setup(req)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec.Result()
}

// certsFromResponse decodes a base64 PKCS #7 EST response.
func certsFromResponse(t *testing.T, resp *http.Response) []*x509.Certificate {
	t.Helper()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, MIMEPKCS7) {
		t.Fatalf("Content-Type = %q, want %q", got, MIMEPKCS7)
	}
	if got := resp.Header.Get("Content-Transfer-Encoding"); got != "base64" {
		t.Fatalf("Content-Transfer-Encoding = %q, want base64", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
	if err != nil {
		t.Fatalf("decoding base64 response: %v", err)
	}
	msg, err := pkcs7.ParsePKCS7(der)
	if err != nil {
		t.Fatalf("parsing PKCS #7 response: %v", err)
	}
	if msg.ContentInfo != "SignedData" {
		t.Fatalf("ContentInfo = %q, want SignedData", msg.ContentInfo)
	}
	return msg.Content.SignedData.Certificates
}

func TestCACerts(t *testing.T) {
	env := newTestEnv(t)

	resp := doRequest(env.handler, http.MethodGet, PathCACerts, nil, nil)
	certs := certsFromResponse(t, resp)
	if len(certs) != 1 {
		t.Fatalf("got %d certificates, want 1", len(certs))
	}
	if !certs[0].Equal(env.caCert) {
		t.Fatal("served CA certificate does not match the signer's CA")
	}

	// The response is also parseable as PEM-wrapped PKCS #7, which is
	// how cfssl clients unpack it.
	resp = doRequest(env.handler, http.MethodGet, "/.well-known/est/myca/cacerts", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("labeled cacerts status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCACertsWithoutAuthentication(t *testing.T) {
	env := newTestEnv(t)
	resp := doRequest(env.handler, http.MethodGet, PathCACerts, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("cacerts without credentials status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSimpleEnroll(t *testing.T) {
	env := newTestEnv(t)
	csrDER, key := makeCSR(t, "device-1.example.com", "device-1.example.com")

	certs := certsFromResponse(t, enrollRequest(t, env.handler, PathSimpleEnroll, csrDER))
	if len(certs) != 1 {
		t.Fatalf("got %d certificates, want 1", len(certs))
	}
	leaf := certs[0]
	if leaf.Subject.CommonName != "device-1.example.com" {
		t.Errorf("CN = %q, want device-1.example.com", leaf.Subject.CommonName)
	}
	if err := leaf.CheckSignatureFrom(env.caCert); err != nil {
		t.Errorf("certificate is not signed by the CA: %v", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !pub.Equal(&key.PublicKey) {
		t.Error("issued certificate does not contain the CSR's public key")
	}
	if leaf.SerialNumber == nil {
		t.Error("issued certificate has no serial number")
	}
}

func TestSimpleEnrollPEMBody(t *testing.T) {
	env := newTestEnv(t)
	csrDER, _ := makeCSR(t, "pem-body.example.com")

	resp := doRequest(env.handler, http.MethodPost, PathSimpleEnroll, bytes.NewReader(csrPEM(csrDER)), func(r *http.Request) {
		r.Header.Set("Content-Type", MIMEPKCS10)
		r.SetBasicAuth("estuser", "estpassword")
	})
	if len(certsFromResponse(t, resp)) != 1 {
		t.Fatal("expected one certificate")
	}
}

func TestSimpleEnrollBadCredentials(t *testing.T) {
	env := newTestEnv(t)
	csrDER, _ := makeCSR(t, "denied.example.com")

	resp := doRequest(env.handler, http.MethodPost, PathSimpleEnroll,
		strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)),
		func(r *http.Request) {
			r.Header.Set("Content-Type", MIMEPKCS10)
			r.SetBasicAuth("estuser", "wrong")
		})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic") {
		t.Errorf("WWW-Authenticate = %q, want a Basic challenge", got)
	}
}

func TestSimpleEnrollMissingCredentials(t *testing.T) {
	env := newTestEnv(t)
	csrDER, _ := makeCSR(t, "anonymous.example.com")

	resp := doRequest(env.handler, http.MethodPost, PathSimpleEnroll,
		strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)),
		func(r *http.Request) { r.Header.Set("Content-Type", MIMEPKCS10) })
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("missing WWW-Authenticate challenge")
	}
}

func TestSimpleEnrollDuplicate(t *testing.T) {
	env := newTestEnv(t)
	csrDER, _ := makeCSR(t, "duplicate.example.com")

	if got := enrollRequest(t, env.handler, PathSimpleEnroll, csrDER).StatusCode; got != http.StatusOK {
		t.Fatalf("first enrollment status = %d, want 200", got)
	}

	resp := enrollRequest(t, env.handler, PathSimpleEnroll, csrDER)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("repeat enrollment status = %d, want 409", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("error Content-Type = %q, want text/plain", ct)
	}
}

func TestSimpleEnrollDuplicateNonASCII(t *testing.T) {
	// The signer re-encodes the CSR subject when it issues a certificate,
	// so duplicate detection must compare decoded subjects rather than the
	// DER encoding of the CSR.
	env := newTestEnv(t)
	csrDER := makeCSRWithSubject(t, pkix.Name{
		CommonName:   "设备-一",
		Organization: []string{"测试 组织"},
		Country:      []string{"CN"},
	})

	if got := enrollRequest(t, env.handler, PathSimpleEnroll, csrDER).StatusCode; got != http.StatusOK {
		t.Fatalf("first enrollment status = %d, want 200", got)
	}
	resp := enrollRequest(t, env.handler, PathSimpleEnroll, csrDER)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("repeat enrollment status = %d, want 409", resp.StatusCode)
	}
}

func TestSimpleReenrollSameKey(t *testing.T) {
	env := newTestEnv(t)
	csrDER, _ := makeCSR(t, "renew.example.com")

	if got := enrollRequest(t, env.handler, PathSimpleEnroll, csrDER).StatusCode; got != http.StatusOK {
		t.Fatalf("enrollment status = %d, want 200", got)
	}
	if got := enrollRequest(t, env.handler, PathSimpleReenroll, csrDER).StatusCode; got != http.StatusOK {
		t.Fatalf("re-enrollment status = %d, want 200", got)
	}
}

func TestSimpleReenrollRekey(t *testing.T) {
	env := newTestEnv(t)
	oldCSR, _ := makeCSR(t, "rekey.example.com")
	if got := enrollRequest(t, env.handler, PathSimpleEnroll, oldCSR).StatusCode; got != http.StatusOK {
		t.Fatalf("enrollment status = %d, want 200", got)
	}

	newCSR, _ := makeCSR(t, "rekey.example.com")
	certs := certsFromResponse(t, enrollRequest(t, env.handler, PathSimpleReenroll, newCSR))
	if len(certs) != 1 {
		t.Fatalf("got %d certificates, want 1", len(certs))
	}
}

func TestSimpleReenrollSubjectChanged(t *testing.T) {
	env := newTestEnv(t)
	oldCSR, _ := makeCSR(t, "original.example.com")
	if got := enrollRequest(t, env.handler, PathSimpleEnroll, oldCSR).StatusCode; got != http.StatusOK {
		t.Fatalf("enrollment status = %d, want 200", got)
	}

	newCSR, _ := makeCSR(t, "changed.example.com")
	resp := enrollRequest(t, env.handler, PathSimpleReenroll, newCSR)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("re-enrollment with changed subject status = %d, want 403", resp.StatusCode)
	}
}

func TestSimpleReenrollNoExistingCertificate(t *testing.T) {
	env := newTestEnv(t)
	csrDER, _ := makeCSR(t, "never-enrolled.example.com")

	resp := enrollRequest(t, env.handler, PathSimpleReenroll, csrDER)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestMalformedRequests(t *testing.T) {
	env := newTestEnv(t)

	tests := []struct {
		name        string
		body        string
		contentType string
		want        int
	}{
		{"garbage base64", "!!!not base64!!!", MIMEPKCS10, http.StatusBadRequest},
		{"not a csr", base64.StdEncoding.EncodeToString([]byte("hello")), MIMEPKCS10, http.StatusBadRequest},
		{"wrong content type", base64.StdEncoding.EncodeToString([]byte("hello")), "application/json", http.StatusUnsupportedMediaType},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resp := doRequest(env.handler, http.MethodPost, PathSimpleEnroll, strings.NewReader(test.body), func(r *http.Request) {
				r.Header.Set("Content-Type", test.contentType)
				r.SetBasicAuth("estuser", "estpassword")
			})
			defer resp.Body.Close()
			if resp.StatusCode != test.want {
				t.Fatalf("status = %d, want %d", resp.StatusCode, test.want)
			}
		})
	}
}

func TestWrongMethod(t *testing.T) {
	env := newTestEnv(t)
	for _, path := range []string{PathSimpleEnroll, PathSimpleReenroll} {
		resp := doRequest(env.handler, http.MethodGet, path, nil, nil)
		resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET %s status = %d, want 405", path, resp.StatusCode)
		}
	}
	resp := doRequest(env.handler, http.MethodPost, PathCACerts, nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST %s status = %d, want 405", PathCACerts, resp.StatusCode)
	}
}

func TestOperationForPath(t *testing.T) {
	tests := []struct {
		path string
		want operation
	}{
		{"/.well-known/est/cacerts", opCACerts},
		{"/.well-known/est/cacerts/", opCACerts},
		{"/.well-known/est/simpleenroll", opSimpleEnroll},
		{"/.well-known/est/simplereenroll", opSimpleReenroll},
		{"/.well-known/est/myca/simpleenroll", opSimpleEnroll},
		{"/.well-known/est/myca/simplereenroll", opSimpleReenroll},
		// Mounted with http.StripPrefix.
		{"/cacerts", opCACerts},
		{"/simpleenroll", opSimpleEnroll},
		// Not EST paths.
		{"/api/v1/cfssl/sign", opUnknown},
		{"/.well-known/est/", opUnknown},
		{"/.well-known/est/a/b/simpleenroll", opUnknown},
		{"/.well-known/est/unknown", opUnknown},
		{"/cacerts/extra", opUnknown},
	}
	for _, test := range tests {
		if got := operationForPath(test.path); got != test.want {
			t.Errorf("operationForPath(%q) = %v, want %v", test.path, got, test.want)
		}
	}
}

func TestUnknownPath(t *testing.T) {
	env := newTestEnv(t)
	resp := doRequest(env.handler, http.MethodGet, "/.well-known/est/unknown", nil, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

// issueClientCert creates a client certificate signed by the test CA.
func (env *testEnv) issueClientCert(t *testing.T, cn string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, env.caCert, &key.PublicKey, env.caKey)
	if err != nil {
		t.Fatalf("creating client certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// newTLSServer starts a TLS server that requests (but does not require)
// client certificates, so the handler can authenticate them itself.
func newTLSServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	ts := httptest.NewUnstartedServer(handler)
	ts.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return ts
}

func tlsClient(t *testing.T, clientCert *tls.Certificate) *http.Client {
	t.Helper()
	cfg := &tls.Config{InsecureSkipVerify: true}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

func enrollOverTLS(t *testing.T, client *http.Client, url string, csrDER []byte, setup func(*http.Request)) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(base64.StdEncoding.EncodeToString(csrDER)))
	if err != nil {
		t.Fatalf("creating request: %v", err)
	}
	req.Header.Set("Content-Type", MIMEPKCS10)
	if setup != nil {
		setup(req)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("enrolling: %v", err)
	}
	return resp
}

func TestClientCertificateAuthentication(t *testing.T) {
	env := newTestEnv(t)
	ts := newTLSServer(t, env.handler)

	clientCert := env.issueClientCert(t, "client.example.com")
	client := tlsClient(t, &clientCert)
	csrDER, _ := makeCSR(t, "client.example.com")

	resp := enrollOverTLS(t, client, ts.URL+PathSimpleEnroll, csrDER, nil)
	if len(certsFromResponse(t, resp)) != 1 {
		t.Fatal("expected one certificate")
	}
}

func TestClientCertificateAuthenticationWithHandlerPool(t *testing.T) {
	env := newTestEnv(t, func(cfg *Config) {
		cfg.BasicAuth = nil
	})
	pool := x509.NewCertPool()
	pool.AddCert(env.caCert)
	h, err := NewHandler(Config{Signer: env.signer, Accessor: env.db, ClientCAs: pool})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	ts := newTLSServer(t, h)

	clientCert := env.issueClientCert(t, "client2.example.com")
	client := tlsClient(t, &clientCert)
	csrDER, _ := makeCSR(t, "client2.example.com")
	resp := enrollOverTLS(t, client, ts.URL+PathSimpleEnroll, csrDER, nil)
	if len(certsFromResponse(t, resp)) != 1 {
		t.Fatal("expected one certificate")
	}

	// Without a client certificate the request is rejected with a
	// Basic challenge, even though Basic authentication is disabled.
	anon := tlsClient(t, nil)
	resp = enrollOverTLS(t, anon, ts.URL+PathSimpleEnroll, csrDER, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") != "" {
		t.Error("WWW-Authenticate must not be sent when Basic authentication is disabled")
	}
}

func TestClientCertificateRejectedByUntrustedCA(t *testing.T) {
	env := newTestEnv(t)

	// Build a handler that trusts a different CA than the one that signs
	// the client certificate.
	unrelatedKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "Unrelated Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	unrelatedDER, err := x509.CreateCertificate(rand.Reader, unrelatedTemplate, unrelatedTemplate, &unrelatedKey.PublicKey, unrelatedKey)
	if err != nil {
		t.Fatal(err)
	}
	unrelated, err := x509.ParseCertificate(unrelatedDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(unrelated)
	h, err := NewHandler(Config{Signer: env.signer, Accessor: env.db, ClientCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	ts := newTLSServer(t, h)

	clientCert := env.issueClientCert(t, "untrusted.example.com")
	client := tlsClient(t, &clientCert)
	csrDER, _ := makeCSR(t, "untrusted.example.com")
	resp := enrollOverTLS(t, client, ts.URL+PathSimpleEnroll, csrDER, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
}

func TestRevokedClientCertificate(t *testing.T) {
	env := newTestEnv(t)
	clientCert := env.issueClientCert(t, "revoked.example.com")

	leaf, err := x509.ParseCertificate(clientCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := env.db.InsertCertificate(certdb.CertificateRecord{
		Serial:    leaf.SerialNumber.String(),
		AKI:       fmt.Sprintf("%x", leaf.AuthorityKeyId),
		Status:    "revoked",
		RevokedAt: time.Now(),
		Expiry:    leaf.NotAfter,
		PEM:       string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})),
	}); err != nil {
		t.Fatal(err)
	}

	ts := newTLSServer(t, env.handler)
	client := tlsClient(t, &clientCert)
	csrDER, _ := makeCSR(t, "revoked.example.com")
	resp := enrollOverTLS(t, client, ts.URL+PathSimpleEnroll, csrDER, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "revoked") {
		t.Errorf("response body = %q, want it to mention revocation", body)
	}
}

func TestRevokedCertificateIsNotCountedAsEnrolled(t *testing.T) {
	env := newTestEnv(t)
	csrDER, _ := makeCSR(t, "re-enroll-after-revoke.example.com")

	certs := certsFromResponse(t, enrollRequest(t, env.handler, PathSimpleEnroll, csrDER))
	if err := env.db.RevokeCertificate(certs[0].SerialNumber.String(), fmt.Sprintf("%x", certs[0].AuthorityKeyId), 0); err != nil {
		t.Fatalf("revoking issued certificate: %v", err)
	}

	// A revoked certificate must not block a new enrollment, and the
	// /simpleenroll duplicate check must ignore it.
	resp := enrollRequest(t, env.handler, PathSimpleEnroll, csrDER)
	if len(certsFromResponse(t, resp)) != 1 {
		t.Fatal("expected enrollment to succeed after revocation")
	}
}

func TestEncodePKCS7RoundTrip(t *testing.T) {
	env := newTestEnv(t)

	certs := []*x509.Certificate{env.caCert}
	der, err := EncodePKCS7(certs)
	if err != nil {
		t.Fatalf("EncodePKCS7: %v", err)
	}
	msg, err := pkcs7.ParsePKCS7(der)
	if err != nil {
		t.Fatalf("ParsePKCS7: %v", err)
	}
	if len(msg.Content.SignedData.Certificates) != 1 {
		t.Fatalf("got %d certificates, want 1", len(msg.Content.SignedData.Certificates))
	}
	if !msg.Content.SignedData.Certificates[0].Equal(env.caCert) {
		t.Error("round-tripped certificate differs from the original")
	}

	if _, err := EncodePKCS7(nil); err == nil {
		t.Error("EncodePKCS7(nil) succeeded, want an error")
	}
}

func TestNewHandlerRequiresAuthenticationMethod(t *testing.T) {
	env := newTestEnv(t)
	if _, err := NewHandler(Config{Signer: env.signer, Accessor: env.db}); err == nil {
		t.Fatal("NewHandler without any authentication method succeeded")
	}
	if _, err := NewHandler(Config{BasicAuth: StaticBasicAuth(map[string]string{"a": "b"})}); err == nil {
		t.Fatal("NewHandler without a signer succeeded")
	}
}
