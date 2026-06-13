package ca

import "crypto/tls"

// CertificateIssuer mints leaf certificates for TLS interception and exposes
// the root certificate for client trust distribution. It is implemented by the
// local CA and by the Vault-backed CA.
type CertificateIssuer interface {
	GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error)
	GetRootCertPEM() ([]byte, error)
}

// Compile-time assertion: *CA must satisfy CertificateIssuer.
var _ CertificateIssuer = (*CA)(nil)
