package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"

	"github.com/goodtune/kproxy/internal/metrics"
	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rs/zerolog"
)

// CA manages certificate generation for TLS interception
type CA struct {
	rootCert      *x509.Certificate
	rootKey       *ecdsa.PrivateKey
	intermCert    *x509.Certificate
	intermKey     *ecdsa.PrivateKey
	certCache     *lru.Cache[string, *tls.Certificate]
	cacheCapacity int
	cacheTTL      time.Duration
	certValidity  time.Duration
	logger        zerolog.Logger
	mu            sync.RWMutex
}

// Config holds CA configuration
type Config struct {
	RootCertPath   string
	RootKeyPath    string
	IntermCertPath string
	IntermKeyPath  string
	CertCacheSize  int
	CertCacheTTL   time.Duration
	CertValidity   time.Duration
}

// NewCA creates a new Certificate Authority
func NewCA(config Config, logger zerolog.Logger) (*CA, error) {
	ca := &CA{
		cacheTTL:     config.CertCacheTTL,
		certValidity: config.CertValidity,
		logger:       logger.With().Str("component", "ca").Logger(),
	}

	// Load root certificate and key
	rootCert, rootKey, err := loadCertificateAndKey(config.RootCertPath, config.RootKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load root certificate: %w", err)
	}
	ca.rootCert = rootCert
	ca.rootKey = rootKey

	// Load intermediate certificate and key (or use root if not provided)
	if config.IntermCertPath != "" && config.IntermKeyPath != "" {
		intermCert, intermKey, err := loadCertificateAndKey(config.IntermCertPath, config.IntermKeyPath)
		if err != nil {
			ca.logger.Warn().Err(err).Msg("Failed to load intermediate certificate, using root")
			ca.intermCert = rootCert
			ca.intermKey = rootKey
		} else {
			ca.intermCert = intermCert
			ca.intermKey = intermKey
		}
	} else {
		// Use root cert for signing
		ca.intermCert = rootCert
		ca.intermKey = rootKey
	}

	// Create certificate cache
	cache, err := lru.New[string, *tls.Certificate](config.CertCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate cache: %w", err)
	}
	ca.certCache = cache
	ca.cacheCapacity = config.CertCacheSize

	ca.logger.Info().
		Str("root_subject", rootCert.Subject.CommonName).
		Str("interm_subject", ca.intermCert.Subject.CommonName).
		Int("cache_size", config.CertCacheSize).
		Msg("Certificate Authority initialized")

	return ca, nil
}

// GetCertificate returns a certificate for the given hostname (implements tls.Config.GetCertificate)
func (ca *CA) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	hostname := hello.ServerName
	if hostname == "" {
		return nil, fmt.Errorf("no SNI hostname provided")
	}

	ca.mu.RLock()
	// Check cache
	if cert, ok := ca.certCache.Get(hostname); ok {
		ca.mu.RUnlock()
		ca.logger.Debug().Str("hostname", hostname).Msg("Certificate cache hit")
		metrics.CertificateCacheHits.Inc()
		return cert, nil
	}
	ca.mu.RUnlock()

	// Cache miss - generate new certificate
	metrics.CertificateCacheMisses.Inc()

	ca.logger.Info().Str("hostname", hostname).Msg("Generating new certificate")
	cert, err := ca.generateCertificate(hostname)
	if err != nil {
		return nil, fmt.Errorf("failed to generate certificate for %s: %w", hostname, err)
	}

	// Record certificate generation
	metrics.CertificatesGenerated.Inc()

	// Cache certificate
	ca.mu.Lock()
	ca.certCache.Add(hostname, cert)
	ca.mu.Unlock()

	return cert, nil
}

// generateCertificate generates a new certificate for the given hostname
func (ca *CA) generateCertificate(hostname string) (*tls.Certificate, error) {
	// Generate key pair
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"KProxy"},
		},
		NotBefore:             now.Add(-1 * time.Hour), // Start 1 hour in the past to handle clock skew
		NotAfter:              now.Add(ca.certValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	// Sign certificate with intermediate CA
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		ca.intermCert,
		&privKey.PublicKey,
		ca.intermKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Create tls.Certificate
	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privKey,
		Leaf:        cert,
	}

	// Include intermediate cert in chain if different from root
	if ca.intermCert != ca.rootCert {
		tlsCert.Certificate = append(tlsCert.Certificate, ca.intermCert.Raw)
	}

	return tlsCert, nil
}

// GetRootCertPEM returns the root CA certificate in PEM format
func (ca *CA) GetRootCertPEM() ([]byte, error) {
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca.rootCert.Raw,
	}), nil
}

// loadCertificateAndKey loads a certificate and private key from files
func loadCertificateAndKey(certPath, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate file: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read key file: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode key PEM")
	}

	// Try to parse as PKCS8 first, then PKCS1, then EC private key
	var key *ecdsa.PrivateKey

	if parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes); err == nil {
		if ecKey, ok := parsedKey.(*ecdsa.PrivateKey); ok {
			key = ecKey
		} else {
			return nil, nil, fmt.Errorf("PKCS8 key is not ECDSA")
		}
	} else if parsedKey, err := x509.ParseECPrivateKey(keyBlock.Bytes); err == nil {
		key = parsedKey
	} else {
		return nil, nil, fmt.Errorf("failed to parse private key")
	}

	return cert, key, nil
}

// ClearCache clears the certificate cache
func (ca *CA) ClearCache() {
	ca.mu.Lock()
	defer ca.mu.Unlock()
	ca.certCache.Purge()
	ca.logger.Info().Msg("Certificate cache cleared")
}

// CacheStats returns certificate cache statistics
func (ca *CA) CacheStats() (size, capacity int) {
	ca.mu.RLock()
	defer ca.mu.RUnlock()
	return ca.certCache.Len(), ca.cacheCapacity
}
