package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA represents a Certificate Authority with its certificate and private key
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CertPEM     []byte
}

// Options holds customizable fields for CA generation
type Options struct {
	CommonName   string
	Organization string
	Country      string
	Province     string
	Locality     string
	ValidYears   int
}

// DefaultOptions returns sensible defaults for CA generation
func DefaultOptions() Options {
	return Options{
		CommonName:   "Cert Tools CA",
		Organization: "Cert Tools",
		ValidYears:   10,
	}
}

// Generate creates a new CA certificate and private key
func Generate(opts Options) (*CA, error) {
	// Generate RSA 4096-bit private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
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
		CommonName: opts.CommonName,
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

	// Create CA certificate template
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(opts.ValidYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Self-sign the CA certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the certificate back to get x509.Certificate struct
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Encode certificate to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	return &CA{
		Certificate: cert,
		PrivateKey:  privateKey,
		CertPEM:     certPEM,
	}, nil
}

// Save writes the CA certificate and private key to disk
func (ca *CA) Save(dir string) error {
	// Ensure directory exists
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write certificate
	certPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certPath, ca.CertPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	// Encode and write private key
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(ca.PrivateKey),
	})
	keyPath := filepath.Join(dir, "ca.key")
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA private key: %w", err)
	}

	return nil
}

// Load reads an existing CA from disk
func Load(dir string) (*CA, error) {
	// Read certificate
	certPath := filepath.Join(dir, "ca.crt")
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Decode PEM block
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	// Parse certificate
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Read private key
	keyPath := filepath.Join(dir, "ca.key")
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key: %w", err)
	}

	// Decode PEM block
	block, _ = pem.Decode(keyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	// Parse private key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  privateKey,
		CertPEM:     certPEM,
	}, nil
}

// LoadOrCreate loads an existing CA or creates a new one if it doesn't exist
func LoadOrCreate(dir string, opts Options) (*CA, bool, error) {
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")

	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)

	certExists := certErr == nil
	keyExists := keyErr == nil

	// Check for inconsistent state (one file exists but not the other)
	if certExists && !keyExists {
		return nil, false, fmt.Errorf("CA certificate exists but private key is missing; remove %s and re-initialize the CA", certPath)
	}
	if !certExists && keyExists {
		return nil, false, fmt.Errorf("CA private key exists but certificate is missing; remove %s and re-initialize the CA", keyPath)
	}

	// Neither file exists, create new CA
	if !certExists && !keyExists {
		ca, err := Generate(opts)
		if err != nil {
			return nil, false, err
		}
		if err := ca.Save(dir); err != nil {
			return nil, false, err
		}
		return ca, true, nil // true = newly created
	}

	// Both files exist, load the CA
	ca, err := Load(dir)
	if err != nil {
		return nil, false, err
	}
	return ca, false, nil // false = loaded existing
}

// Exists checks if a CA exists in the given directory
func Exists(dir string) bool {
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	_, certErr := os.Stat(certPath)
	_, keyErr := os.Stat(keyPath)
	return certErr == nil && keyErr == nil
}
