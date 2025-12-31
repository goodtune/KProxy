package acme

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"
	"github.com/rs/zerolog"
)

// Config holds ACME client configuration
type Config struct {
	Email        string            // Email for Let's Encrypt account
	DNSProvider  string            // DNS provider name (e.g., "cloudflare", "route53")
	Credentials  map[string]string // DNS provider credentials
	CertPath     string            // Path to store certificate
	KeyPath      string            // Path to store private key
	CADirURL     string            // ACME directory URL
	Domain       string            // Domain to obtain certificate for
}

// User implements the ACME user interface
type User struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// Client manages ACME certificate acquisition
type Client struct {
	config Config
	logger zerolog.Logger
}

// NewClient creates a new ACME client
func NewClient(config Config, logger zerolog.Logger) *Client {
	return &Client{
		config: config,
		logger: logger,
	}
}

// ObtainCertificate obtains a certificate from Let's Encrypt using DNS-01 challenge
func (c *Client) ObtainCertificate() error {
	c.logger.Info().
		Str("domain", c.config.Domain).
		Str("dns_provider", c.config.DNSProvider).
		Str("ca_url", c.config.CADirURL).
		Msg("Starting ACME certificate acquisition")

	// Create a new user
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	user := &User{
		Email: c.config.Email,
		key:   privateKey,
	}

	// Create lego config
	legoConfig := lego.NewConfig(user)
	legoConfig.CADirURL = c.config.CADirURL
	legoConfig.Certificate.KeyType = certcrypto.RSA2048

	// Create ACME client
	client, err := lego.NewClient(legoConfig)
	if err != nil {
		return fmt.Errorf("failed to create ACME client: %w", err)
	}

	c.logger.Info().Msg("ACME client created successfully")

	// Get DNS provider
	provider, err := c.getDNSProvider()
	if err != nil {
		return fmt.Errorf("failed to get DNS provider: %w", err)
	}

	// Set DNS challenge
	err = client.Challenge.SetDNS01Provider(provider)
	if err != nil {
		return fmt.Errorf("failed to set DNS provider: %w", err)
	}

	c.logger.Info().
		Str("provider", c.config.DNSProvider).
		Msg("DNS-01 challenge provider configured")

	// Register user
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fmt.Errorf("failed to register ACME account: %w", err)
	}
	user.Registration = reg

	c.logger.Info().
		Str("uri", reg.URI).
		Msg("ACME account registered successfully")

	// Request certificate
	c.logger.Info().
		Str("domain", c.config.Domain).
		Msg("Requesting certificate from Let's Encrypt")

	request := certificate.ObtainRequest{
		Domains: []string{c.config.Domain},
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return fmt.Errorf("failed to obtain certificate: %w", err)
	}

	c.logger.Info().
		Str("domain", certificates.Domain).
		Str("cert_url", certificates.CertURL).
		Msg("Certificate obtained successfully")

	// Save certificates
	if err := c.saveCertificates(certificates); err != nil {
		return fmt.Errorf("failed to save certificates: %w", err)
	}

	c.logger.Info().
		Str("cert_path", c.config.CertPath).
		Str("key_path", c.config.KeyPath).
		Msg("Certificates saved successfully")

	return nil
}

// getDNSProvider creates a DNS provider based on configuration
func (c *Client) getDNSProvider() (challenge.Provider, error) {
	// Set environment variables from credentials
	for key, value := range c.config.Credentials {
		os.Setenv(key, value)
	}

	// Create provider using environment variables
	// The lego library will automatically detect the provider from environment
	provider, err := dns.NewDNSChallengeProviderByName(c.config.DNSProvider)
	if err != nil {
		return nil, fmt.Errorf("unsupported DNS provider %q: %w", c.config.DNSProvider, err)
	}

	return provider, nil
}

// saveCertificates saves the obtained certificates to disk
func (c *Client) saveCertificates(certs *certificate.Resource) error {
	// Ensure directories exist
	certDir := filepath.Dir(c.config.CertPath)
	keyDir := filepath.Dir(c.config.KeyPath)

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	if certDir != keyDir {
		if err := os.MkdirAll(keyDir, 0755); err != nil {
			return fmt.Errorf("failed to create key directory: %w", err)
		}
	}

	// Save certificate (includes full chain)
	if err := os.WriteFile(c.config.CertPath, certs.Certificate, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Save private key
	if err := os.WriteFile(c.config.KeyPath, certs.PrivateKey, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}
