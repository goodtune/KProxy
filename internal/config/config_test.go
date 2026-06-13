package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeConfig writes a minimal YAML config file to dir/config.yaml and returns its path.
func writeConfig(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writeConfig: %v", err)
	}
	return path
}

// minimalConfig is the smallest valid YAML config that satisfies validation.
const minimalConfig = `
server:
  dns_port: 53
  http_port: 80
  https_port: 443

dns:
  upstream_servers:
    - "8.8.8.8:53"

storage:
  type: redis
  redis:
    host: localhost
    port: 6379
`

func TestDefaultBackendIsLocal(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, minimalConfig)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.TLS.Backend != "local" {
		t.Errorf("TLS.Backend = %q; want %q", cfg.TLS.Backend, "local")
	}
}

func TestDefaultVaultMounts(t *testing.T) {
	dir := t.TempDir()
	path := writeConfig(t, dir, minimalConfig)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.TLS.Vault.AppRole.Mount != "approle" {
		t.Errorf("Vault.AppRole.Mount = %q; want %q", cfg.TLS.Vault.AppRole.Mount, "approle")
	}
	if cfg.TLS.Vault.PKI.Mount != "pki" {
		t.Errorf("Vault.PKI.Mount = %q; want %q", cfg.TLS.Vault.PKI.Mount, "pki")
	}
}

func TestVaultBackendMissingAddressFails(t *testing.T) {
	dir := t.TempDir()
	content := minimalConfig + `
tls:
  backend: vault
  vault:
    approle:
      role_id: "my-role-id"
    pki:
      role: kproxy
`
	path := writeConfig(t, dir, content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected error for missing vault address, got nil")
	}
}

func TestVaultBackendMissingRoleIDFails(t *testing.T) {
	dir := t.TempDir()
	content := minimalConfig + `
tls:
  backend: vault
  vault:
    address: "https://vault.example.com:8200"
    pki:
      role: kproxy
`
	path := writeConfig(t, dir, content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected error for missing vault approle.role_id, got nil")
	}
}

func TestVaultBackendMissingPKIRoleFails(t *testing.T) {
	dir := t.TempDir()
	content := minimalConfig + `
tls:
  backend: vault
  vault:
    address: "https://vault.example.com:8200"
    approle:
      role_id: "my-role-id"
`
	path := writeConfig(t, dir, content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected error for missing vault pki.role, got nil")
	}
}

func TestVaultBackendAllRequiredFieldsPass(t *testing.T) {
	dir := t.TempDir()
	content := minimalConfig + `
tls:
  backend: vault
  vault:
    address: "https://vault.example.com:8200"
    approle:
      role_id: "my-role-id"
      secret_id: "my-secret-id"
    pki:
      role: kproxy
`
	path := writeConfig(t, dir, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error for valid vault config: %v", err)
	}

	if cfg.TLS.Backend != "vault" {
		t.Errorf("TLS.Backend = %q; want %q", cfg.TLS.Backend, "vault")
	}
	if cfg.TLS.Vault.Address != "https://vault.example.com:8200" {
		t.Errorf("Vault.Address = %q; want %q", cfg.TLS.Vault.Address, "https://vault.example.com:8200")
	}
	if cfg.TLS.Vault.AppRole.RoleID != "my-role-id" {
		t.Errorf("Vault.AppRole.RoleID = %q; want %q", cfg.TLS.Vault.AppRole.RoleID, "my-role-id")
	}
	if cfg.TLS.Vault.PKI.Role != "kproxy" {
		t.Errorf("Vault.PKI.Role = %q; want %q", cfg.TLS.Vault.PKI.Role, "kproxy")
	}
}

func TestUnsupportedBackendFails(t *testing.T) {
	dir := t.TempDir()
	content := minimalConfig + `
tls:
  backend: hsm
`
	path := writeConfig(t, dir, content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load() expected error for unsupported backend, got nil")
	}
}

func TestLocalBackendExplicitPasses(t *testing.T) {
	dir := t.TempDir()
	content := minimalConfig + `
tls:
  backend: local
`
	path := writeConfig(t, dir, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error for explicit local backend: %v", err)
	}
	if cfg.TLS.Backend != "local" {
		t.Errorf("TLS.Backend = %q; want %q", cfg.TLS.Backend, "local")
	}
}

func TestVaultFullConfigRoundtrip(t *testing.T) {
	dir := t.TempDir()
	content := minimalConfig + `
tls:
  backend: vault
  vault:
    address: "https://vault.home.local:8200"
    ca_cert: "/etc/kproxy/vault-ca.crt"
    namespace: "my-ns"
    approle:
      mount: "approle"
      role_id: "abc123"
      secret_id_file: "/etc/kproxy/vault-secret-id"
    pki:
      mount: "pki"
      role: "kproxy"
      ttl: "12h"
`
	path := writeConfig(t, dir, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	v := cfg.TLS.Vault
	checks := []struct {
		got  string
		want string
		name string
	}{
		{v.Address, "https://vault.home.local:8200", "Vault.Address"},
		{v.CACert, "/etc/kproxy/vault-ca.crt", "Vault.CACert"},
		{v.Namespace, "my-ns", "Vault.Namespace"},
		{v.AppRole.Mount, "approle", "Vault.AppRole.Mount"},
		{v.AppRole.RoleID, "abc123", "Vault.AppRole.RoleID"},
		{v.AppRole.SecretIDFile, "/etc/kproxy/vault-secret-id", "Vault.AppRole.SecretIDFile"},
		{v.PKI.Mount, "pki", "Vault.PKI.Mount"},
		{v.PKI.Role, "kproxy", "Vault.PKI.Role"},
		{v.PKI.TTL, "12h", "Vault.PKI.TTL"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q; want %q", c.name, c.got, c.want)
		}
	}
}
