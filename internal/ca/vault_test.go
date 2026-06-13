package ca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	vaultapi "github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
	tcvault "github.com/testcontainers/testcontainers-go/modules/vault"
)

// These tests run against a real HashiCorp Vault instance started in a
// container via testcontainers-go. A single Vault container is started once
// for the package (TestMain), its PKI secrets engine and AppRole auth method
// are configured exactly as documented in docs/vault-setup.md, and every test
// exercises VaultCA against it. Running these tests requires a working Docker
// daemon.

const (
	vaultImage     = "hashicorp/vault:1.21"
	vaultRootToken = "root-token"
	vaultRootCN    = "KProxy Root CA"
)

// Populated by TestMain after the container is configured.
var (
	vaultAddr     string
	vaultRoleID   string
	vaultSecretID string
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	container, err := tcvault.Run(ctx, vaultImage, tcvault.WithToken(vaultRootToken))
	if err != nil {
		log.Fatalf("failed to start Vault container (is Docker running?): %v", err)
	}

	addr, err := container.HttpHostAddress(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		log.Fatalf("failed to get Vault address: %v", err)
	}
	vaultAddr = addr

	if err := setupVaultPKI(ctx, addr, vaultRootToken); err != nil {
		_ = container.Terminate(ctx)
		log.Fatalf("failed to configure Vault PKI/AppRole: %v", err)
	}

	code := m.Run()

	// os.Exit skips deferred calls, so terminate explicitly.
	if err := container.Terminate(ctx); err != nil {
		log.Printf("failed to terminate Vault container: %v", err)
	}
	os.Exit(code)
}

// setupVaultPKI configures the running Vault exactly like the operator guide:
// it enables and seeds the PKI engine, creates the kproxy signing role and
// policy, enables AppRole, and mints the role_id/secret_id used by the tests.
func setupVaultPKI(ctx context.Context, addr, token string) error {
	cfg := vaultapi.DefaultConfig()
	cfg.Address = addr
	client, err := vaultapi.NewClient(cfg)
	if err != nil {
		return fmt.Errorf("new admin client: %w", err)
	}
	client.SetToken(token)

	// Enable and tune the PKI secrets engine.
	if err := client.Sys().MountWithContext(ctx, "pki", &vaultapi.MountInput{
		Type:   "pki",
		Config: vaultapi.MountConfigInput{MaxLeaseTTL: "8760h"},
	}); err != nil {
		return fmt.Errorf("mount pki: %w", err)
	}

	// Generate the root CA.
	if _, err := client.Logical().WriteWithContext(ctx, "pki/root/generate/internal", map[string]interface{}{
		"common_name": vaultRootCN,
		"ttl":         "87600h",
	}); err != nil {
		return fmt.Errorf("generate root CA: %w", err)
	}

	// Create the signing role. KProxy intercepts arbitrary hostnames and sends
	// a CSR, so any name is allowed, hostname enforcement is off, and the key
	// type is "any" (KProxy generates the key locally).
	if _, err := client.Logical().WriteWithContext(ctx, "pki/roles/kproxy", map[string]interface{}{
		"allow_any_name":    true,
		"enforce_hostnames": false,
		"key_type":          "any",
		"max_ttl":           "48h",
	}); err != nil {
		return fmt.Errorf("create pki role: %w", err)
	}

	// Policy granting only the two capabilities KProxy needs.
	policy := `path "pki/sign/kproxy" { capabilities = ["update"] }
path "pki/ca/pem"      { capabilities = ["read"] }`
	if err := client.Sys().PutPolicyWithContext(ctx, "kproxy", policy); err != nil {
		return fmt.Errorf("put policy: %w", err)
	}

	// Enable AppRole and create the kproxy role.
	if err := client.Sys().EnableAuthWithOptionsWithContext(ctx, "approle", &vaultapi.EnableAuthOptions{
		Type: "approle",
	}); err != nil {
		return fmt.Errorf("enable approle: %w", err)
	}
	if _, err := client.Logical().WriteWithContext(ctx, "auth/approle/role/kproxy", map[string]interface{}{
		"token_policies": "kproxy",
		"token_ttl":      "1h",
		"token_max_ttl":  "4h",
	}); err != nil {
		return fmt.Errorf("create approle role: %w", err)
	}

	// Fetch the role_id (non-secret) and mint a secret_id.
	ridSec, err := client.Logical().ReadWithContext(ctx, "auth/approle/role/kproxy/role-id")
	if err != nil {
		return fmt.Errorf("read role-id: %w", err)
	}
	vaultRoleID, _ = ridSec.Data["role_id"].(string)

	sidSec, err := client.Logical().WriteWithContext(ctx, "auth/approle/role/kproxy/secret-id", nil)
	if err != nil {
		return fmt.Errorf("generate secret-id: %w", err)
	}
	vaultSecretID, _ = sidSec.Data["secret_id"].(string)

	if vaultRoleID == "" || vaultSecretID == "" {
		return fmt.Errorf("vault returned empty role_id or secret_id")
	}
	return nil
}

// newVaultCAConfig returns a VaultCAConfig pointing at the test container with
// valid AppRole credentials.
func newVaultCAConfig() VaultCAConfig {
	return VaultCAConfig{
		Address:      vaultAddr,
		AppRoleMount: "approle",
		RoleID:       vaultRoleID,
		SecretID:     vaultSecretID,
		PKIMount:     "pki",
		PKIRole:      "kproxy",
		TTL:          time.Hour,
		CacheSize:    100,
		CacheTTL:     time.Hour,
	}
}

// rootPool builds a cert pool from the issuer's root cert for chain verification.
func rootPool(t *testing.T, v *VaultCA) *x509.CertPool {
	t.Helper()
	rootPEM, err := v.GetRootCertPEM()
	if err != nil {
		t.Fatalf("GetRootCertPEM failed: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(rootPEM) {
		t.Fatal("failed to add Vault root CA to pool")
	}
	return pool
}

func TestNewVaultCA(t *testing.T) {
	v, err := NewVaultCA(context.Background(), newVaultCAConfig(), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA failed: %v", err)
	}
	defer v.Close()

	// AppRole login must have set a token on the client.
	if v.client.Token() == "" {
		t.Error("expected client token to be set after AppRole login, got empty")
	}

	root, err := v.GetRootCertPEM()
	if err != nil {
		t.Fatalf("GetRootCertPEM failed: %v", err)
	}
	block, _ := pem.Decode(root)
	if block == nil {
		t.Fatal("root cert PEM did not decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("root cert did not parse: %v", err)
	}
	if cert.Subject.CommonName != vaultRootCN {
		t.Errorf("expected root CN %q, got %q", vaultRootCN, cert.Subject.CommonName)
	}
}

func TestVaultCAGetCertificate(t *testing.T) {
	v, err := NewVaultCA(context.Background(), newVaultCAConfig(), zerolog.Nop())
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

	// The leaf must chain to the Vault root CA.
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		DNSName: hostname,
		Roots:   rootPool(t, v),
	}); err != nil {
		t.Errorf("certificate failed to verify against Vault root CA: %v", err)
	}

	// Vault returns the issuer chain (ca_chain), so the served chain should
	// include the issuing CA alongside the leaf.
	if len(cert.Certificate) < 2 {
		t.Errorf("expected served chain to include issuer, got %d certs", len(cert.Certificate))
	}
}

func TestVaultCACaching(t *testing.T) {
	v, err := NewVaultCA(context.Background(), newVaultCAConfig(), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA failed: %v", err)
	}
	defer v.Close()

	hello := &tls.ClientHelloInfo{ServerName: "cache.example.com"}
	first, err := v.GetCertificate(hello)
	if err != nil {
		t.Fatalf("first GetCertificate failed: %v", err)
	}
	second, err := v.GetCertificate(hello)
	if err != nil {
		t.Fatalf("second GetCertificate failed: %v", err)
	}

	// A cache hit returns the identical cached certificate; a second Vault sign
	// would have produced a distinct *tls.Certificate (and a new serial).
	if first != second {
		t.Error("expected second GetCertificate to return the cached certificate, got a freshly signed one")
	}
}

func TestVaultCAEmptyServerName(t *testing.T) {
	v, err := NewVaultCA(context.Background(), newVaultCAConfig(), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA failed: %v", err)
	}
	defer v.Close()

	if _, err := v.GetCertificate(&tls.ClientHelloInfo{ServerName: ""}); err == nil {
		t.Error("expected error for empty ServerName, got nil")
	}
}

// TestVaultCASignFailureNoFallback verifies that when Vault refuses to sign
// (here, an unknown PKI role the AppRole token has no access to),
// GetCertificate propagates the error and caches nothing — there is no silent
// fallback to local signing.
func TestVaultCASignFailureNoFallback(t *testing.T) {
	cfg := newVaultCAConfig()
	cfg.PKIRole = "nonexistent-role"

	v, err := NewVaultCA(context.Background(), cfg, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA failed: %v", err)
	}
	defer v.Close()

	cert, err := v.GetCertificate(&tls.ClientHelloInfo{ServerName: "fail.example.com"})
	if err == nil {
		t.Fatal("expected GetCertificate to return an error when signing is refused, got nil")
	}
	if cert != nil {
		t.Error("expected nil certificate on sign failure, got non-nil")
	}
	if size, _ := v.CacheStats(); size != 0 {
		t.Errorf("expected empty cache after sign failure, got %d entries", size)
	}
}

// TestVaultCASecretIDFile verifies the secret_id is sourced from a file (with
// surrounding whitespace trimmed) and that AppRole login succeeds with it.
func TestVaultCASecretIDFile(t *testing.T) {
	dir := t.TempDir()
	secretIDPath := filepath.Join(dir, "secret-id")
	if err := os.WriteFile(secretIDPath, []byte(vaultSecretID+"\n"), 0600); err != nil {
		t.Fatalf("failed to write secret id file: %v", err)
	}

	cfg := newVaultCAConfig()
	cfg.SecretID = ""
	cfg.SecretIDFile = secretIDPath

	v, err := NewVaultCA(context.Background(), cfg, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewVaultCA with secret_id_file failed: %v", err)
	}
	defer v.Close()

	got, err := v.resolveSecretID()
	if err != nil {
		t.Fatalf("resolveSecretID failed: %v", err)
	}
	if got != vaultSecretID {
		t.Errorf("expected secret id %q, got %q", vaultSecretID, got)
	}
}
