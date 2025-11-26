package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cert-tools/ca"
)

// HostCert represents a host certificate with its private key
type HostCert struct {
	Hostname   string
	CertPEM    []byte
	KeyPEM     []byte
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
}

// Options holds customizable fields for certificate generation
type Options struct {
	Organization string
	Country      string
	Province     string
	Locality     string
	ValidDays    int
}

// DefaultOptions returns sensible defaults for certificate generation
func DefaultOptions() Options {
	return Options{
		ValidDays: 365,
	}
}

// Generate creates a new host certificate signed by the given CA
func Generate(authority *ca.CA, hostname string, opts Options) (*HostCert, error) {
	if hostname == "" {
		return nil, fmt.Errorf("hostname cannot be empty")
	}

	// Generate RSA 2048-bit private key for the host
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate random serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Build subject from options
	subject := pkix.Name{
		CommonName: hostname,
	}
	if opts.Organization != "" {
		subject.Organization = []string{opts.Organization}
	}
	if opts.Country != "" {
		subject.Country = []string{opts.Country}
	}
	if opts.Province != "" {
		subject.Province = []string{opts.Province}
	}
	if opts.Locality != "" {
		subject.Locality = []string{opts.Locality}
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(0, 0, opts.ValidDays),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
	}

	// Set SAN (Subject Alternative Name)
	// Check if hostname is an IP address
	if ip := net.ParseIP(hostname); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{hostname}
		// Also add wildcard if it's a domain
		if !strings.HasPrefix(hostname, "*.") && strings.Contains(hostname, ".") {
			// Don't add wildcard for simple hostnames like "localhost"
		}
	}

	// Sign the certificate with the CA
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		template,
		authority.Certificate,
		&privateKey.PublicKey,
		authority.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Parse the certificate back
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return &HostCert{
		Hostname:    hostname,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Certificate: cert,
		PrivateKey:  privateKey,
	}, nil
}

// Save writes the host certificate and private key to disk
func (hc *HostCert) Save(dir string) error {
	// Ensure directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Sanitize hostname for filename (replace special chars)
	filename := sanitizeFilename(hc.Hostname)

	// Write certificate
	certPath := filepath.Join(dir, filename+".crt")
	if err := os.WriteFile(certPath, hc.CertPEM, 0644); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key
	keyPath := filepath.Join(dir, filename+".key")
	if err := os.WriteFile(keyPath, hc.KeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	return nil
}

// sanitizeFilename converts a hostname to a safe filename
func sanitizeFilename(hostname string) string {
	// Replace characters that might cause issues in filenames
	replacer := strings.NewReplacer(
		"*", "wildcard",
		":", "_",
		"/", "_",
		"\\", "_",
	)
	return replacer.Replace(hostname)
}
