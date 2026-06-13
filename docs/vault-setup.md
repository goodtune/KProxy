# Configuring HashiCorp Vault as KProxy's Certificate Backend

## Overview

KProxy can use HashiCorp Vault's PKI secrets engine to sign the leaf TLS certificates it generates during HTTPS interception. With this backend, KProxy generates each leaf private key locally and submits a CSR to Vault's `pki/sign/<role>` endpoint for signing via AppRole authentication. The full CA hierarchy — root and intermediate — lives inside Vault, and the private keys never leave it. For full architecture detail, see `docs/superpowers/specs/2026-06-13-vault-ca-design.md`.

---

## Prerequisites

- A reachable Vault server (Vault OSS ≥ 1.9 is sufficient). Note the address you will use, e.g. `https://vault.home.local:8200`.
- The `vault` CLI installed and authenticated as an admin (`vault login` with a token that has `sys/mounts`, `sys/policies`, and `auth/` management capabilities).
- KProxy installed with a working `config.yaml` (the `backend: local` default).

> All commands below use `https://vault.home.local:8200` as the Vault address placeholder. Replace it with your actual address wherever it appears.

---

## Step 1: Enable and Configure the PKI Secrets Engine

```bash
# Enable the PKI secrets engine at the default "pki" mount
vault secrets enable pki

# Extend the maximum lease TTL to 1 year (8760 h).
# Vault refuses to issue certs with TTLs longer than the mount's max_lease_ttl,
# so set this generously — the role's max_ttl (Step 1d) is the real ceiling.
vault secrets tune -max-lease-ttl=8760h pki

# Configure the CA's issuing certificate and CRL distribution URLs.
# Clients use these URLs for OCSP/CRL checks.  Replace the address below.
vault write pki/config/urls \
  issuing_certificates="https://vault.home.local:8200/v1/pki/ca" \
  crl_distribution_points="https://vault.home.local:8200/v1/pki/crl"

# Generate the root CA inside Vault.
# "internal" means Vault generates the key — it never leaves Vault.
vault write pki/root/generate/internal \
  common_name="KProxy Root CA" \
  ttl=87600h
```

Now create the PKI **role** that KProxy uses when submitting CSRs:

```bash
vault write pki/roles/kproxy \
  allow_any_name=true \
  enforce_hostnames=false \
  key_type=any \
  max_ttl=48h
```

Why these settings matter:

| Setting | Why |
|---|---|
| `allow_any_name=true` | KProxy intercepts arbitrary hostnames (e.g. `accounts.google.com`, `api.example.com`). Vault's normal hostname allow-list would reject most of them. |
| `enforce_hostnames=false` | Turns off Vault's RFC-hostname validation. Required because internal names (e.g. `nas.home`) don't conform to public-DNS rules. |
| `key_type=any` | KProxy generates the leaf key locally and sends a CSR. Setting `key_type=any` tells Vault to accept whatever key type is in the CSR rather than generating its own. |
| `max_ttl=48h` | Hard ceiling on issued cert lifetime. KProxy's `tls.vault.pki.ttl` (default `24h`) must be ≤ this value. |

---

## Step 2: Create the Policy

KProxy needs exactly two capabilities: signing CSRs and reading the root CA cert.

```bash
vault policy write kproxy - <<'EOF'
path "pki/sign/kproxy" {
  capabilities = ["update"]
}
path "pki/ca/pem" {
  capabilities = ["read"]
}
EOF
```

`pki/sign/kproxy` is the endpoint KProxy POSTs CSRs to. `pki/ca/pem` is fetched once at startup so KProxy can serve its root CA download endpoint to clients.

---

## Step 3: Enable AppRole and Create the Role

```bash
# Enable the AppRole auth method (skip if already enabled)
vault auth enable approle

# Create the kproxy AppRole
vault write auth/approle/role/kproxy \
  token_policies="kproxy" \
  token_ttl=1h \
  token_max_ttl=4h
```

`token_ttl=1h` is the initial token lifetime. KProxy's renewal goroutine calls `auth/token/renew-self` at ⅔ of the remaining TTL (i.e. around the 40-minute mark), keeping the token alive indefinitely under normal operation. If renewal fails, KProxy attempts a full AppRole re-login. On re-login failure it retries with exponential backoff (starting at 5 s, capped at 5 min); cached certificates continue serving during the outage.

`token_max_ttl=4h` caps how long a single token can live even with renewals. After 4 h, KProxy performs a fresh AppRole login automatically.

---

## Step 4: Fetch the Credentials

```bash
# Get the role_id — this is non-secret (treat it like a username)
vault read auth/approle/role/kproxy/role-id

# Generate a secret_id — this IS sensitive (treat it like a password)
vault write -f auth/approle/role/kproxy/secret-id
```

Copy the `role_id` value; you will put it directly in `config.yaml`. The `secret_id` value is a one-time credential that should be stored securely — see Step 5.

---

## Step 5: Deliver the `secret_id` to KProxy

The recommended approach is `secret_id_file`. KProxy re-reads this file each time it performs an AppRole login, which means you can rotate the secret ID by updating the file without touching `config.yaml` or restarting the service (a `SIGHUP` policy reload is sufficient).

```bash
# Write the secret_id to the file (replace <secret-id> with the value from Step 4)
echo -n "<secret-id>" | sudo tee /etc/kproxy/vault-secret-id > /dev/null

# Lock down permissions — only the kproxy service user should be able to read it
sudo chown kproxy:kproxy /etc/kproxy/vault-secret-id
sudo chmod 600 /etc/kproxy/vault-secret-id
```

If you prefer to keep things simple for local development, you can put the secret ID directly in `config.yaml` using the `secret_id` field instead (see Step 6). This is convenient but means you must edit the config file whenever the secret ID rotates.

---

## Step 6: Configure KProxy

Edit `/etc/kproxy/config.yaml` (or your local `config.yaml`). Change `tls.backend` to `"vault"` and add the `vault:` block. See `configs/config.example.yaml` for the full annotated template.

```yaml
tls:
  backend: "vault"

  # cert_cache_size, cert_cache_ttl, cert_validity still apply
  cert_cache_size: 1000
  cert_cache_ttl: "24h"
  cert_validity: "24h"

  vault:
    address: "https://vault.home.local:8200"   # your Vault address
    # ca_cert: "/etc/kproxy/vault-ca.crt"      # uncomment if Vault uses a private TLS CA

    approle:
      mount: "approle"                          # default; omit if unchanged
      role_id: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"   # from Step 4
      secret_id_file: "/etc/kproxy/vault-secret-id"     # from Step 5

    pki:
      mount: "pki"                              # default; omit if unchanged
      role: "kproxy"                            # role name created in Step 1
      ttl: "24h"                                # must be <= role max_ttl (48h)
```

> The `tls.ca_cert`, `tls.ca_key`, `tls.intermediate_cert`, and `tls.intermediate_key` fields are ignored when `backend: vault`. You do not need to remove them, but they have no effect.

---

## Step 7: Verify

Start (or restart) KProxy:

```bash
sudo systemctl restart kproxy.service
```

On successful startup, KProxy logs:

```
{"level":"info","message":"Vault certificate backend initialized"}
```

**Root CA distribution.** KProxy fetches the root CA PEM from `pki/ca/pem` at startup and serves it via its existing CA-download endpoint (e.g. `http://local.kproxy/ca.crt`). Clients still need to trust this root CA — the same requirement as the local backend. Instructions for installing the root CA on client devices are in `docs/ca-installation.md`.

**Failure modes to be aware of:**

| When | What happens |
|---|---|
| Vault unreachable at startup | KProxy exits with a clear error — it will not start with a broken Vault backend. |
| AppRole login fails at startup | Same — KProxy exits. |
| Root cert fetch fails at startup | Same — KProxy exits. |
| Cache miss during a Vault auth outage | `GetCertificate` returns an error; the proxy serves its existing error response. **No silent fallback to local signing.** |
| Cache hit during a Vault auth outage | Already-cached certificates continue serving normally. |
| Token expiry during outage | Renewal goroutine retries with backoff; new cert requests fail with a logged error until auth recovers. |

---

## Notes

- **CRL not needed.** Leaf certificates are short-lived (default `24h`). KProxy does not configure or consult Vault's CRL.
- **Single mount/role per instance.** Each KProxy instance uses one PKI mount and one role. If you run multiple instances, you can point them at the same mount/role or create separate roles per instance.
- **`tls.vault.ca_cert` is for Vault's own TLS certificate.** If your Vault server's TLS cert is signed by a private CA (common in home labs), set `ca_cert` to the path of that CA's cert so KProxy can verify Vault's identity. This is unrelated to the KProxy interception CA.
