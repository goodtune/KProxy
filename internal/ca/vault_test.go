package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// testVaultPKI is a small in-memory CA used by the mock Vault server to sign
// incoming CSRs, mirroring what a real Vault PKI engine would do.
type testVaultPKI struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

func newTestVaultPKI(t *testing.T) *testVaultPKI {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate CA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Vault Root CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create CA cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	return &testVaultPKI{cert: cert, key: key, certPEM: certPEM}
}

// sign parses a PEM CSR and issues a leaf certificate PEM signed by the test CA.
func (p *testVaultPKI) sign(t *testing.T, csrPEM string) string {
	t.Helper()

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatalf("failed to decode CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse CSR: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature invalid: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      csr.Subject,
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, p.cert, csr.PublicKey, p.key)
	if err != nil {
		t.Fatalf("failed to sign leaf cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))
}

// mockVaultServer wires the three endpoints VaultCA calls.
// It delegates to mockVaultServerWithOpts with default (zero-value) options so
// all existing tests continue to work unchanged.
func mockVaultServer(t *testing.T, pki *testVaultPKI, signCount *int) *httptest.Server {
	t.Helper()
	return mockVaultServerWithOpts(t, pki, signCount, mockVaultSignOpts{})
}

func testVaultConfig(addr string) VaultCAConfig {
	return VaultCAConfig{
		Address:      addr,
		AppRoleMount: "approle",
		RoleID:       "test-role-id",
		SecretID:     "test-secret-id",
		PKIMount:     "pki",
		PKIRole:      "kproxy",
		TTL:          time.Hour,
		CacheSize:    100,
		CacheTTL:     time.Hour,
	}
}

func TestNewVaultCA(t *testing.T) {
	pki := newTestVaultPKI(t)
	srv := mockVaultServer(t, pki, nil)

	v, err := NewVaultCA(context.Background(), testVaultConfig(srv.URL), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA failed: %v", err)
	}
	defer v.Close()

	if v.client.Token() != "test-token" {
		t.Errorf("expected client token to be set to test-token, got %q", v.client.Token())
	}

	root, err := v.GetRootCertPEM()
	if err != nil {
		t.Fatalf("GetRootCertPEM failed: %v", err)
	}
	if string(root) != string(pki.certPEM) {
		t.Errorf("root cert PEM does not match mock CA PEM")
	}
}

func TestVaultCAGetCertificate(t *testing.T) {
	pki := newTestVaultPKI(t)
	srv := mockVaultServer(t, pki, nil)

	v, err := NewVaultCA(context.Background(), testVaultConfig(srv.URL), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA failed: %v", err)
	}
	defer v.Close()

	hostname := "example.com"
	cert, err := v.GetCertificate(&tls.ClientHelloInfo{ServerName: hostname})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if cert.Leaf == nil {
		t.Fatal("expected non-nil Leaf")
	}
	if cert.Leaf.Subject.CommonName != hostname {
		t.Errorf("expected CommonName %q, got %q", hostname, cert.Leaf.Subject.CommonName)
	}

	// Verify the leaf chains to the test CA.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pki.certPEM) {
		t.Fatal("failed to add test CA to pool")
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: hostname,
		Roots:   roots,
	}); err != nil {
		t.Errorf("certificate failed to verify against test CA: %v", err)
	}

	// The served chain should include the issuing CA.
	if len(cert.Certificate) < 2 {
		t.Errorf("expected served chain to include issuer, got %d certs", len(cert.Certificate))
	}
}

func TestVaultCACaching(t *testing.T) {
	pki := newTestVaultPKI(t)
	var signCount int
	srv := mockVaultServer(t, pki, &signCount)

	v, err := NewVaultCA(context.Background(), testVaultConfig(srv.URL), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA failed: %v", err)
	}
	defer v.Close()

	hello := &tls.ClientHelloInfo{ServerName: "cache.example.com"}
	if _, err := v.GetCertificate(hello); err != nil {
		t.Fatalf("first GetCertificate failed: %v", err)
	}
	if _, err := v.GetCertificate(hello); err != nil {
		t.Fatalf("second GetCertificate failed: %v", err)
	}

	if signCount != 1 {
		t.Errorf("expected Vault sign endpoint to be hit once, got %d", signCount)
	}
}

func TestVaultCAEmptyServerName(t *testing.T) {
	pki := newTestVaultPKI(t)
	srv := mockVaultServer(t, pki, nil)

	v, err := NewVaultCA(context.Background(), testVaultConfig(srv.URL), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA failed: %v", err)
	}
	defer v.Close()

	if _, err := v.GetCertificate(&tls.ClientHelloInfo{ServerName: ""}); err == nil {
		t.Error("expected error for empty ServerName, got nil")
	}
}

// mockVaultSignOpts configures the behaviour of the sign endpoint in
// mockVaultServerWithOpts.
type mockVaultSignOpts struct {
	// forceError makes the sign endpoint respond with an HTTP 500.
	forceError bool
	// useCaChain makes the sign endpoint return the issuer in the ca_chain
	// JSON array instead of the issuing_ca string field.
	useCaChain bool
}

// mockVaultServerWithOpts is like mockVaultServer but accepts additional
// options that control sign-endpoint behaviour. The existing mockVaultServer
// wrapper continues to call this with zero-value opts so all existing tests
// remain unchanged.
func mockVaultServerWithOpts(t *testing.T, pki *testVaultPKI, signCount *int, opts mockVaultSignOpts) *httptest.Server {
	t.Helper()
	var mu sync.Mutex

	mux := http.NewServeMux()

	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"auth": map[string]interface{}{
				"client_token":   "test-token",
				"lease_duration": 3600,
				"renewable":      true,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/v1/pki/sign/kproxy", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if signCount != nil {
			*signCount++
		}
		mu.Unlock()

		if opts.forceError {
			http.Error(w, `{"errors":["internal server error"]}`, http.StatusInternalServerError)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		csrPEM, _ := req["csr"].(string)
		leafPEM := pki.sign(t, csrPEM)

		var data map[string]interface{}
		if opts.useCaChain {
			data = map[string]interface{}{
				"certificate": leafPEM,
				"ca_chain":    []string{string(pki.certPEM)},
			}
		} else {
			data = map[string]interface{}{
				"certificate": leafPEM,
				"issuing_ca":  string(pki.certPEM),
			}
		}

		resp := map[string]interface{}{"data": data}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/v1/pki/ca/pem", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		_, _ = w.Write(pki.certPEM)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestVaultCASignFailureNoFallback verifies that when the Vault sign endpoint
// returns an error, GetCertificate propagates the error and does NOT cache
// anything (i.e. there is no silent fallback to local signing).
func TestVaultCASignFailureNoFallback(t *testing.T) {
	pki := newTestVaultPKI(t)
	srv := mockVaultServerWithOpts(t, pki, nil, mockVaultSignOpts{forceError: true})

	v, err := NewVaultCA(context.Background(), testVaultConfig(srv.URL), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA failed: %v", err)
	}
	defer v.Close()

	cert, err := v.GetCertificate(&tls.ClientHelloInfo{ServerName: "fail.example.com"})
	if err == nil {
		t.Fatal("expected GetCertificate to return an error when sign endpoint fails, got nil")
	}
	if cert != nil {
		t.Errorf("expected nil certificate on sign failure, got non-nil")
	}

	// Nothing should have been cached for the failed hostname.
	if size, _ := v.CacheStats(); size != 0 {
		t.Errorf("expected empty cache after sign failure, got %d entries", size)
	}
}

// TestVaultCACaChainBranch verifies that when the Vault sign response carries
// the issuer in the ca_chain array (the preferred field), the chain-assembly
// code picks it up and the resulting tls.Certificate has at least two DER
// entries (leaf + issuer), and that the issuer DER parses as a valid cert.
func TestVaultCACaChainBranch(t *testing.T) {
	pki := newTestVaultPKI(t)
	srv := mockVaultServerWithOpts(t, pki, nil, mockVaultSignOpts{useCaChain: true})

	v, err := NewVaultCA(context.Background(), testVaultConfig(srv.URL), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA failed: %v", err)
	}
	defer v.Close()

	cert, err := v.GetCertificate(&tls.ClientHelloInfo{ServerName: "chain.example.com"})
	if err != nil {
		t.Fatalf("GetCertificate failed: %v", err)
	}

	if len(cert.Certificate) < 2 {
		t.Fatalf("expected at least 2 DER entries (leaf + issuer), got %d", len(cert.Certificate))
	}

	// The second entry must parse as a valid x509 certificate.
	issuerDER := cert.Certificate[1]
	if _, err := x509.ParseCertificate(issuerDER); err != nil {
		t.Errorf("issuer DER (from ca_chain) does not parse as a valid certificate: %v", err)
	}
}

func TestVaultCASecretIDFile(t *testing.T) {
	pki := newTestVaultPKI(t)
	srv := mockVaultServer(t, pki, nil)

	dir := t.TempDir()
	secretIDPath := filepath.Join(dir, "secret-id")
	if err := os.WriteFile(secretIDPath, []byte("file-secret-id\n"), 0600); err != nil {
		t.Fatalf("failed to write secret id file: %v", err)
	}

	cfg := testVaultConfig(srv.URL)
	cfg.SecretID = ""
	cfg.SecretIDFile = secretIDPath

	v, err := NewVaultCA(context.Background(), cfg, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA with secret_id_file failed: %v", err)
	}
	defer v.Close()

	// Verify resolveSecretID trims whitespace and reads from file.
	got, err := v.resolveSecretID()
	if err != nil {
		t.Fatalf("resolveSecretID failed: %v", err)
	}
	if got != "file-secret-id" {
		t.Errorf("expected secret id %q, got %q", "file-secret-id", got)
	}
}
