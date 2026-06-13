package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/kproxy/internal/metrics"
	lru "github.com/hashicorp/golang-lru/v2"
	vaultapi "github.com/hashicorp/vault/api"
	"github.com/rs/zerolog"
)

// VaultCAConfig holds the configuration for the Vault-backed certificate
// issuer. It is intentionally decoupled from the config package so the ca
// package stays independent (mirrors ca.Config).
type VaultCAConfig struct {
	Address      string        // Vault server address (https://...)
	CACert       string        // path to Vault server's own TLS CA cert (optional)
	Namespace    string        // Vault Enterprise namespace (optional)
	AppRoleMount string        // auth mount path, e.g. "approle"
	RoleID       string        // AppRole role id
	SecretID     string        // inline secret id
	SecretIDFile string        // path to file containing secret id (takes precedence if set)
	PKIMount     string        // PKI secrets engine mount, e.g. "pki"
	PKIRole      string        // Vault PKI role name
	TTL          time.Duration // leaf cert TTL
	CacheSize    int           // LRU cache capacity
	CacheTTL     time.Duration // LRU cache entry TTL
}

// VaultCA mints leaf certificates by submitting CSRs to a HashiCorp Vault PKI
// secrets engine. Leaf private keys are generated locally and never leave the
// process; the CA hierarchy lives inside Vault.
type VaultCA struct {
	client *vaultapi.Client

	pkiMount string
	pkiRole  string

	// AppRole credentials retained for token renewal / re-login.
	appRoleMount string
	roleID       string
	secretID     string
	secretIDFile string

	certCache     *lru.Cache[string, *tls.Certificate]
	cacheCapacity int
	cacheTTL      time.Duration

	rootCertPEM []byte
	certTTL     time.Duration

	logger zerolog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu sync.RWMutex
}

// Compile-time assertion: *VaultCA must satisfy CertificateIssuer.
var _ CertificateIssuer = (*VaultCA)(nil)

// NewVaultCA builds an authenticated Vault-backed certificate issuer. It logs
// in via AppRole, fetches the root CA certificate, and starts a token renewal
// goroutine. Any failure during authentication or root cert fetch returns an
// error so KProxy fails to start.
func NewVaultCA(ctx context.Context, cfg VaultCAConfig, logger zerolog.Logger) (*VaultCA, error) {
	log := logger.With().Str("component", "vault-ca").Logger()

	// 1. Build the Vault client.
	vcfg := vaultapi.DefaultConfig()
	vcfg.Address = cfg.Address
	if cfg.CACert != "" {
		if err := vcfg.ConfigureTLS(&vaultapi.TLSConfig{CACert: cfg.CACert}); err != nil {
			return nil, fmt.Errorf("failed to configure Vault TLS with CA cert %q: %w", cfg.CACert, err)
		}
	}

	client, err := vaultapi.NewClient(vcfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	v := &VaultCA{
		client:        client,
		pkiMount:      cfg.PKIMount,
		pkiRole:       cfg.PKIRole,
		appRoleMount:  cfg.AppRoleMount,
		roleID:        cfg.RoleID,
		secretID:      cfg.SecretID,
		secretIDFile:  cfg.SecretIDFile,
		cacheCapacity: cfg.CacheSize,
		cacheTTL:      cfg.CacheTTL,
		certTTL:       cfg.TTL,
		logger:        log,
	}

	// 2-3. Resolve the secret ID and perform the AppRole login.
	auth, err := v.login(ctx)
	if err != nil {
		return nil, fmt.Errorf("Vault AppRole login failed: %w", err)
	}

	// 4. Fetch the root CA certificate (PEM bytes).
	rootPEM, err := v.fetchRootCertPEM(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Vault root CA certificate: %w", err)
	}
	v.rootCertPEM = rootPEM

	// 5. Create the certificate cache.
	cache, err := lru.New[string, *tls.Certificate](cfg.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate cache: %w", err)
	}
	v.certCache = cache

	// 6. Derive a child context for the renewal goroutine and start it if the
	// token is renewable with a positive lease.
	v.ctx, v.cancel = context.WithCancel(ctx)
	if auth != nil && auth.Renewable && auth.LeaseDuration > 0 {
		go v.renewLoop(auth.LeaseDuration)
	} else {
		log.Info().Msg("Vault token is not renewable; skipping token renewal goroutine")
	}

	log.Info().
		Str("address", cfg.Address).
		Str("pki_mount", cfg.PKIMount).
		Str("pki_role", cfg.PKIRole).
		Int("cache_size", cfg.CacheSize).
		Msg("Vault certificate authority initialized")

	return v, nil
}

// resolveSecretID returns the secret ID, preferring the file source so that
// external rotation is picked up without a config reload.
func (v *VaultCA) resolveSecretID() (string, error) {
	if v.secretIDFile != "" {
		data, err := os.ReadFile(v.secretIDFile)
		if err != nil {
			return "", fmt.Errorf("failed to read secret_id_file %q: %w", v.secretIDFile, err)
		}
		secretID := strings.TrimSpace(string(data))
		if secretID == "" {
			return "", fmt.Errorf("secret_id_file %q is empty", v.secretIDFile)
		}
		return secretID, nil
	}
	if v.secretID == "" {
		return "", fmt.Errorf("no secret id configured: set secret_id or secret_id_file")
	}
	return v.secretID, nil
}

// login performs an AppRole login, sets the resulting token on the client, and
// returns the auth metadata for the renewal loop.
func (v *VaultCA) login(ctx context.Context) (*vaultapi.SecretAuth, error) {
	secretID, err := v.resolveSecretID()
	if err != nil {
		return nil, err
	}

	path := fmt.Sprintf("auth/%s/login", v.appRoleMount)
	secret, err := v.client.Logical().WriteWithContext(ctx, path, map[string]interface{}{
		"role_id":   v.roleID,
		"secret_id": secretID,
	})
	if err != nil {
		return nil, fmt.Errorf("AppRole login request failed: %w", err)
	}
	if secret == nil || secret.Auth == nil || secret.Auth.ClientToken == "" {
		return nil, fmt.Errorf("AppRole login returned no client token")
	}

	v.client.SetToken(secret.Auth.ClientToken)
	v.logger.Info().
		Int("lease_duration", secret.Auth.LeaseDuration).
		Bool("renewable", secret.Auth.Renewable).
		Msg("AppRole login successful")
	return secret.Auth, nil
}

// fetchRootCertPEM reads the PKI mount's CA certificate as raw PEM bytes. The
// <mount>/ca/pem endpoint is unauthenticated and returns raw PEM, not JSON.
func (v *VaultCA) fetchRootCertPEM(ctx context.Context) ([]byte, error) {
	path := fmt.Sprintf("%s/ca/pem", v.pkiMount)
	resp, err := v.client.Logical().ReadRawWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read root cert response body: %w", err)
	}
	if len(body) == 0 {
		return nil, fmt.Errorf("root cert response from %s is empty", path)
	}

	// Validate it parses as a certificate.
	block, _ := pem.Decode(body)
	if block == nil {
		return nil, fmt.Errorf("failed to decode root cert PEM from %s", path)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return nil, fmt.Errorf("failed to parse root cert from %s: %w", path, err)
	}

	return body, nil
}

// GetCertificate returns a certificate for the requested hostname, signing a
// locally generated key via Vault on a cache miss.
func (v *VaultCA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	hostname := hello.ServerName
	if hostname == "" {
		return nil, fmt.Errorf("no SNI hostname provided")
	}

	v.mu.RLock()
	if cert, ok := v.certCache.Get(hostname); ok {
		v.mu.RUnlock()
		v.logger.Debug().Str("hostname", hostname).Msg("Certificate cache hit")
		metrics.CertificateCacheHits.Inc()
		return cert, nil
	}
	v.mu.RUnlock()

	metrics.CertificateCacheMisses.Inc()

	v.logger.Info().Str("hostname", hostname).Msg("Signing new certificate via Vault")
	cert, err := v.signCertificate(hostname)
	if err != nil {
		v.logger.Error().Err(err).Str("hostname", hostname).Msg("Vault certificate signing failed")
		return nil, fmt.Errorf("failed to sign certificate for %s via Vault: %w", hostname, err)
	}

	metrics.CertificatesGenerated.Inc()

	v.mu.Lock()
	v.certCache.Add(hostname, cert)
	v.mu.Unlock()

	return cert, nil
}

// signCertificate generates a local ECDSA key, builds a CSR, and has Vault sign
// it, assembling the resulting tls.Certificate with the full issuer chain.
func (v *VaultCA) signCertificate(hostname string) (*tls.Certificate, error) {
	// Generate the leaf key locally; it never leaves the process.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Build and PEM-encode the CSR.
	csrTemplate := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: hostname},
		DNSNames: []string{hostname},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Submit the CSR to Vault for signing.
	data := map[string]interface{}{
		"csr":         string(csrPEM),
		"common_name": hostname,
	}
	if v.certTTL > 0 {
		data["ttl"] = fmt.Sprintf("%ds", int(v.certTTL.Seconds()))
	}

	path := fmt.Sprintf("%s/sign/%s", v.pkiMount, v.pkiRole)
	secret, err := v.client.Logical().WriteWithContext(v.ctx, path, data)
	if err != nil {
		return nil, fmt.Errorf("Vault sign request to %s failed: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("Vault sign response from %s was empty", path)
	}

	certPEM, ok := secret.Data["certificate"].(string)
	if !ok || certPEM == "" {
		return nil, fmt.Errorf("Vault sign response missing certificate field")
	}

	leafDER, err := pemToDER(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signed certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signed certificate: %w", err)
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  privKey,
		Leaf:        leaf,
	}

	// Append the issuer chain so the served chain is complete. Prefer ca_chain
	// (an array of PEM strings) and fall back to issuing_ca (a single PEM).
	for _, issuerDER := range v.issuerChainDER(secret.Data) {
		tlsCert.Certificate = append(tlsCert.Certificate, issuerDER)
	}

	return tlsCert, nil
}

// issuerChainDER extracts issuer certificate DER blocks from a Vault sign
// response, preferring ca_chain over issuing_ca.
func (v *VaultCA) issuerChainDER(data map[string]interface{}) [][]byte {
	var chain [][]byte

	if raw, ok := data["ca_chain"]; ok {
		if list, ok := raw.([]interface{}); ok {
			for _, item := range list {
				pemStr, ok := item.(string)
				if !ok || pemStr == "" {
					continue
				}
				der, err := pemToDER(pemStr)
				if err != nil {
					v.logger.Warn().Err(err).Msg("Skipping unparseable ca_chain entry")
					continue
				}
				chain = append(chain, der)
			}
		}
		if len(chain) > 0 {
			return chain
		}
	}

	if raw, ok := data["issuing_ca"].(string); ok && raw != "" {
		der, err := pemToDER(raw)
		if err != nil {
			v.logger.Warn().Err(err).Msg("Skipping unparseable issuing_ca")
		} else {
			chain = append(chain, der)
		}
	}

	return chain
}

// pemToDER decodes a single PEM block and returns its DER bytes.
func pemToDER(pemStr string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}
	return block.Bytes, nil
}

// GetRootCertPEM returns the root CA certificate fetched at startup.
func (v *VaultCA) GetRootCertPEM() ([]byte, error) {
	if len(v.rootCertPEM) == 0 {
		return nil, fmt.Errorf("root certificate not available")
	}
	return v.rootCertPEM, nil
}

// renewLoop keeps the Vault token alive. It renews at ⅔ of the lease duration,
// re-logs in on renewal failure, and backs off exponentially when auth is down.
// It exits cleanly when the context is cancelled.
func (v *VaultCA) renewLoop(leaseDuration int) {
	const (
		minBackoff = 5 * time.Second
		maxBackoff = 5 * time.Minute
	)

	lease := leaseDuration
	for {
		interval := renewalInterval(lease)
		timer := time.NewTimer(interval)

		select {
		case <-v.ctx.Done():
			timer.Stop()
			v.logger.Info().Msg("Stopping Vault token renewal goroutine")
			return
		case <-timer.C:
		}

		// Attempt a token self-renewal first.
		if secret, err := v.client.Auth().Token().RenewSelf(0); err == nil && secret != nil && secret.Auth != nil {
			lease = secret.Auth.LeaseDuration
			v.logger.Debug().Int("lease_duration", lease).Msg("Vault token renewed")
			continue
		} else if err != nil {
			v.logger.Warn().Err(err).Msg("Vault token renewal failed, attempting re-login")
		}

		// Renewal failed; attempt a full re-login with backoff.
		backoff := minBackoff
		for {
			auth, err := v.login(v.ctx)
			if err == nil && auth != nil {
				lease = auth.LeaseDuration
				v.logger.Info().Int("lease_duration", lease).Msg("Vault re-login successful")
				break
			}
			v.logger.Error().Err(err).Dur("retry_in", backoff).Msg("Vault re-login failed; cached certs continue serving")

			retry := time.NewTimer(backoff)
			select {
			case <-v.ctx.Done():
				retry.Stop()
				v.logger.Info().Msg("Stopping Vault token renewal goroutine")
				return
			case <-retry.C:
			}

			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}
}

// renewalInterval returns ⅔ of the lease duration as a renewal interval, with a
// sane floor for very short leases.
func renewalInterval(leaseDuration int) time.Duration {
	if leaseDuration <= 0 {
		return time.Second
	}
	d := time.Duration(leaseDuration) * time.Second * 2 / 3
	if d < time.Second {
		d = time.Second
	}
	return d
}

// Close stops the token renewal goroutine.
func (v *VaultCA) Close() {
	if v.cancel != nil {
		v.cancel()
	}
}

// ClearCache clears the certificate cache.
func (v *VaultCA) ClearCache() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.certCache.Purge()
	v.logger.Info().Msg("Certificate cache cleared")
}

// CacheStats returns certificate cache statistics.
func (v *VaultCA) CacheStats() (size, capacity int) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.certCache.Len(), v.cacheCapacity
}
