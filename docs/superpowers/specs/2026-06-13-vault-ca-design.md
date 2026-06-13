# Vault PKI Certificate Backend

**Date:** 2026-06-13
**Status:** Approved

## Overview

Add HashiCorp Vault as an optional certificate minting backend for KProxy's TLS interception. When enabled, KProxy generates leaf private keys locally, submits CSRs to Vault's PKI secrets engine for signing, and assembles the resulting `tls.Certificate` pairs. The full CA hierarchy (root and intermediate) lives inside Vault — private keys never leave it.

Auth method: AppRole. Leaf key generation: local (CSR flow, not `pki/issue`). Selection: config flag `tls.backend`.

---

## Architecture

### Interface

A new `CertificateIssuer` interface in `internal/ca/issuer.go`:

```go
type CertificateIssuer interface {
    GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
    GetRootCertPEM() ([]byte, error)
}
```

The existing `CA` struct satisfies this interface without modification. The proxy server's field changes from `*ca.CA` to `ca.CertificateIssuer`. `main.go` selects the implementation based on `tls.backend`.

### File structure

```
internal/ca/
  issuer.go     # CertificateIssuer interface (new)
  ca.go         # existing LocalCA — no logic changes
  vault.go      # VaultCA implementation (new)
```

---

## VaultCA

### Struct fields

- `*vault.Client` — authenticated Vault API client
- `pkiMount`, `pkiRole` strings
- LRU cert cache (same capacity/TTL as LocalCA)
- `rootCertPEM []byte` — fetched once at startup from `<mount>/ca/pem`, cached in memory
- `certValidity time.Duration`
- `zerolog.Logger`
- `context.Context` / cancel — for shutdown of renewal goroutine

### Certificate issuance (`GetCertificate`)

1. Check LRU cache — hit → return immediately (metrics: cache hit)
2. Generate ECDSA P-256 key pair locally
3. Build `x509.CertificateRequest` for the hostname
4. PEM-encode CSR, POST to `<mount>/sign/<role>` with `common_name` and `ttl`
5. Vault returns JSON; extract `data.certificate` (PEM string) and parse into `tls.Certificate` + local private key
6. Store in LRU cache (metrics: cache miss, cert generated)
7. Return

### Root cert (`GetRootCertPEM`)

Returns the in-memory `rootCertPEM` fetched at startup from `<mount>/ca/pem`. Used by the proxy's existing cert download endpoint — no changes needed there.

### Startup sequence (`NewVaultCA`)

1. Build `vault.Client` from config (address, optional CA cert for Vault's own TLS)
2. Read secret ID from `secret_id_file` if set, otherwise from `secret_id` config value
3. POST `auth/<approle_mount>/login` with `role_id` + `secret_id` → set token on client
4. Fetch `<pki_mount>/ca/pem` → cache as `rootCertPEM`
5. Create LRU cache
6. Start token renewal goroutine
7. Return `*VaultCA`

Returns an error (and KProxy fails to start) if any of steps 2–4 fail.

---

## AppRole Auth and Token Lifecycle

### Secret ID sourcing (checked in order)

1. `vault.approle.secret_id_file` — path to file containing the secret ID (preferred; supports external rotation without config reload)
2. `vault.approle.secret_id` — inline config value (simpler for home/dev use)

### Token renewal goroutine

- Calculates renewal interval as ⅔ of token lease duration
- Calls `auth/token/renew-self` before expiry
- On renewal failure: attempts full re-login with AppRole credentials
- On re-login failure: logs error, retries with exponential backoff (initial 5s, cap 5m)
- During auth outage: cached certs continue serving; new hostnames return an error (logged prominently)
- Goroutine stops cleanly when the context passed to `NewVaultCA` is cancelled (wired to main shutdown context)

---

## Configuration

New `tls.backend` key selects the implementation. Existing `tls.ca_cert` / `tls.ca_key` / `tls.intermediate_*` fields are only used when `backend: local` (default). Shared cache/TTL fields (`cert_cache_size`, `cert_cache_ttl`, `cert_validity`) apply to both backends.

```yaml
tls:
  backend: vault   # "local" (default) or "vault"

  # Shared (apply to both backends)
  cert_cache_size: 1000
  cert_cache_ttl: 24h
  cert_validity: 24h   # used by local backend; VaultCA uses vault.pki.ttl (defaults to this if unset)

  vault:
    address: https://vault.home.local:8200
    ca_cert: /etc/kproxy/vault-ca.crt   # Vault server's TLS CA cert, optional
    namespace: ""                        # Vault Enterprise only

    approle:
      mount: approle                     # auth mount path, default "approle"
      role_id: <role-id>
      secret_id: ""                      # inline value, or use secret_id_file
      secret_id_file: /etc/kproxy/vault-secret-id

    pki:
      mount: pki                         # PKI secrets engine mount, default "pki"
      role: kproxy                       # Vault PKI role name
      ttl: 24h                           # leaf cert TTL (must be ≤ role max_ttl); defaults to tls.cert_validity if unset
```

Go struct additions in `internal/config/config.go`:

```go
type TLSConfig struct {
    // ... existing fields ...
    Backend string      `mapstructure:"backend"`
    Vault   VaultConfig `mapstructure:"vault"`
}

type VaultConfig struct {
    Address   string            `mapstructure:"address"`
    CACert    string            `mapstructure:"ca_cert"`
    Namespace string            `mapstructure:"namespace"`
    AppRole   VaultAppRoleConfig `mapstructure:"approle"`
    PKI       VaultPKIConfig     `mapstructure:"pki"`
}

type VaultAppRoleConfig struct {
    Mount        string `mapstructure:"mount"`
    RoleID       string `mapstructure:"role_id"`
    SecretID     string `mapstructure:"secret_id"`
    SecretIDFile string `mapstructure:"secret_id_file"`
}

type VaultPKIConfig struct {
    Mount string `mapstructure:"mount"`
    Role  string `mapstructure:"role"`
    TTL   string `mapstructure:"ttl"`
}
```

---

## Error Handling

- **Vault unreachable + cache miss** → `GetCertificate` returns an error; proxy serves its existing error response. No silent fallback to local signing.
- **Startup failure** → KProxy exits with a clear error if `backend: vault` is set but Vault is unreachable, AppRole login fails, or the root cert cannot be fetched.
- **Token expiry during auth outage** → renewal goroutine retries with backoff; cached certs continue serving; new cert requests fail with a logged error until auth recovers.

---

## Testing

- The `CertificateIssuer` interface lets the proxy be unit-tested with a mock issuer (same pattern as the OPA engine mock in this codebase).
- `VaultCA` gets integration tests using an `httptest.Server` that mocks the three Vault endpoints it calls:
  - `POST auth/approle/login`
  - `POST pki/sign/<role>`
  - `GET pki/ca/pem`

---

## Vault PKI Prerequisites

These steps must be performed in Vault before enabling the backend (document in `configs/config.example.yaml`):

```bash
# Enable PKI secrets engine
vault secrets enable pki
vault secrets tune -max-lease-ttl=8760h pki

# Configure CA URLs
vault write pki/config/urls \
  issuing_certificates="https://vault.home.local:8200/v1/pki/ca" \
  crl_distribution_points="https://vault.home.local:8200/v1/pki/crl"

# Generate root CA (or import existing)
vault write pki/root/generate/internal \
  common_name="KProxy Root CA" \
  ttl=87600h

# Create role for leaf cert signing
vault write pki/roles/kproxy \
  allow_any_name=true \
  enforce_hostnames=false \
  key_type=any \
  max_ttl=48h

# Create policy
vault policy write kproxy - <<EOF
path "pki/sign/kproxy"  { capabilities = ["update"] }
path "pki/ca/pem"       { capabilities = ["read"] }
EOF

# Enable AppRole and create role
vault auth enable approle
vault write auth/approle/role/kproxy \
  token_policies="kproxy" \
  token_ttl=1h \
  token_max_ttl=4h

# Fetch credentials
vault read auth/approle/role/kproxy/role-id
vault write -f auth/approle/role/kproxy/secret-id
```

---

## New Dependency

`github.com/hashicorp/vault/api` — the official Vault Go client. Pure Go, no CGO.

---

## Out of Scope

- Vault as secrets store for local CA keys (Option C) — not implemented
- Vault agent / auto-auth sidecar — KProxy handles auth itself
- Certificate revocation via Vault CRL — leaf certs are short-lived; CRL not needed
- Multiple Vault PKI mounts — single mount/role per KProxy instance
