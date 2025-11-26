package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"

	"cert-tools/ca"
	"cert-tools/cert"
)

const defaultOutputDir = "./certs"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "init-ca":
		handleInitCA(os.Args[2:])
	case "create":
		handleCreate(os.Args[2:])
	case "decode":
		handleDecode(os.Args[2:])
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`cert-tools - Generate CA and host certificates

Usage:
  cert-tools <command> [options] [arguments]

Commands:
  init-ca    Create a new Certificate Authority
  create     Create certificates for one or more hosts
  decode     Decode and display certificate information
  help       Show this help message

Examples:
  # Initialize a new CA
  cert-tools init-ca

  # Create certificates for hosts
  cert-tools create example.com localhost 192.168.1.1

  # Specify output directory
  cert-tools create --out ./my-certs example.com

  # Decode a certificate
  cert-tools decode ./certs/ca.crt
  cert-tools decode ./certs/example.com.crt

Options for 'init-ca':
  --out, -o    Output directory for CA files (default: ./certs)
  --cn         Common Name (default: Cert Tools CA)
  --org        Organization (default: Cert Tools)
  --country    Country (2-letter code)
  --province   State or Province
  --locality   City or Locality
  --years      Validity in years (default: 10)

Options for 'create':
  --out, -o    Output directory for certificate files (default: ./certs)
  --org        Organization
  --country    Country (2-letter code)
  --province   State or Province
  --locality   City or Locality
  --days       Validity in days (default: 365)`)
}

func handleInitCA(args []string) {
	fs := flag.NewFlagSet("init-ca", flag.ExitOnError)
	outDir := fs.String("out", defaultOutputDir, "Output directory")
	fs.StringVar(outDir, "o", defaultOutputDir, "Output directory (shorthand)")

	// CA subject fields
	opts := ca.DefaultOptions()
	fs.StringVar(&opts.CommonName, "cn", opts.CommonName, "Common Name")
	fs.StringVar(&opts.Organization, "org", opts.Organization, "Organization")
	fs.StringVar(&opts.Country, "country", "", "Country (2-letter code)")
	fs.StringVar(&opts.Province, "province", "", "State or Province")
	fs.StringVar(&opts.Locality, "locality", "", "City or Locality")
	fs.IntVar(&opts.ValidYears, "years", opts.ValidYears, "Validity in years")

	fs.Parse(args)

	if ca.Exists(*outDir) {
		fmt.Println("CA already exists in", *outDir)
		fmt.Println("To create a new CA, remove the existing ca.crt and ca.key files first.")
		os.Exit(1)
	}

	fmt.Println("Generating new Certificate Authority...")
	authority, err := ca.Generate(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating CA: %v\n", err)
		os.Exit(1)
	}

	if err := authority.Save(*outDir); err != nil {
		fmt.Fprintf(os.Stderr, "Error saving CA: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("CA certificate created successfully!\n")
	fmt.Printf("  Certificate: %s/ca.crt\n", *outDir)
	fmt.Printf("  Private key: %s/ca.key\n", *outDir)
}

func handleCreate(args []string) {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	outDir := fs.String("out", defaultOutputDir, "Output directory")
	fs.StringVar(outDir, "o", defaultOutputDir, "Output directory (shorthand)")

	// Certificate subject fields
	opts := cert.DefaultOptions()
	fs.StringVar(&opts.Organization, "org", "", "Organization")
	fs.StringVar(&opts.Country, "country", "", "Country (2-letter code)")
	fs.StringVar(&opts.Province, "province", "", "State or Province")
	fs.StringVar(&opts.Locality, "locality", "", "City or Locality")
	fs.IntVar(&opts.ValidDays, "days", opts.ValidDays, "Validity in days")

	fs.Parse(args)

	hosts := fs.Args()

	// Check if any "hostname" looks like a flag (user put flags after hostnames)
	for _, h := range hosts {
		if strings.HasPrefix(h, "-") {
			fmt.Fprintf(os.Stderr, "Error: flags must come before hostnames (found %q after hostname)\n", h)
			fmt.Fprintln(os.Stderr, "\nUsage: cert-tools create [options] HOST [HOST...]")
			os.Exit(1)
		}
	}
	if len(hosts) == 0 {
		fmt.Fprintln(os.Stderr, "Error: at least one hostname is required")
		fmt.Fprintln(os.Stderr, "\nUsage: cert-tools create [--out DIR] [options] HOST [HOST...]")
		os.Exit(1)
	}

	// Load or create CA
	authority, created, err := ca.LoadOrCreate(*outDir, ca.DefaultOptions())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading/creating CA: %v\n", err)
		os.Exit(1)
	}

	if created {
		fmt.Printf("Created new CA in %s\n", *outDir)
	} else {
		fmt.Printf("Using existing CA from %s\n", *outDir)
	}

	// Generate certificate for each host
	for _, hostname := range hosts {
		fmt.Printf("Generating certificate for %s...\n", hostname)

		hostCert, err := cert.Generate(authority, hostname, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error generating certificate for %s: %v\n", hostname, err)
			continue
		}

		if err := hostCert.Save(*outDir); err != nil {
			fmt.Fprintf(os.Stderr, "Error saving certificate for %s: %v\n", hostname, err)
			continue
		}

		fmt.Printf("  Created: %s.crt, %s.key\n", hostname, hostname)
	}

	fmt.Println("\nDone!")
}

func handleDecode(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: at least one certificate file is required")
		fmt.Fprintln(os.Stderr, "\nUsage: cert-tools decode CERT_FILE [CERT_FILE...]")
		os.Exit(1)
	}

	for _, certFile := range args {
		fmt.Printf("=== %s ===\n", certFile)

		// Read certificate file
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading %s: %v\n\n", certFile, err)
			continue
		}

		// Decode PEM block
		block, _ := pem.Decode(certPEM)
		if block == nil {
			fmt.Fprintf(os.Stderr, "Error: %s does not contain a valid PEM block\n\n", certFile)
			continue
		}

		if block.Type != "CERTIFICATE" {
			fmt.Fprintf(os.Stderr, "Error: %s is not a certificate (found: %s)\n\n", certFile, block.Type)
			continue
		}

		// Parse certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing certificate %s: %v\n\n", certFile, err)
			continue
		}

		// Display certificate information
		printCertInfo(cert)
		fmt.Println()
	}
}

func printCertInfo(cert *x509.Certificate) {
	fmt.Printf("Subject:      %s\n", cert.Subject.String())
	fmt.Printf("Issuer:       %s\n", cert.Issuer.String())
	fmt.Printf("Serial:       %s\n", cert.SerialNumber.String())
	fmt.Printf("Not Before:   %s\n", cert.NotBefore.Format("2006-01-02 15:04:05 MST"))
	fmt.Printf("Not After:    %s\n", cert.NotAfter.Format("2006-01-02 15:04:05 MST"))

	if cert.IsCA {
		fmt.Printf("Is CA:        Yes\n")
	} else {
		fmt.Printf("Is CA:        No\n")
	}

	// DNS Names
	if len(cert.DNSNames) > 0 {
		fmt.Printf("DNS Names:    %s\n", strings.Join(cert.DNSNames, ", "))
	}

	// IP Addresses
	if len(cert.IPAddresses) > 0 {
		ips := make([]string, len(cert.IPAddresses))
		for i, ip := range cert.IPAddresses {
			ips[i] = ip.String()
		}
		fmt.Printf("IP Addresses: %s\n", strings.Join(ips, ", "))
	}

	// Key Usage
	keyUsages := []string{}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature != 0 {
		keyUsages = append(keyUsages, "Digital Signature")
	}
	if cert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		keyUsages = append(keyUsages, "Key Encipherment")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign != 0 {
		keyUsages = append(keyUsages, "Certificate Sign")
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign != 0 {
		keyUsages = append(keyUsages, "CRL Sign")
	}
	if len(keyUsages) > 0 {
		fmt.Printf("Key Usage:    %s\n", strings.Join(keyUsages, ", "))
	}

	// Extended Key Usage
	extKeyUsages := []string{}
	for _, eku := range cert.ExtKeyUsage {
		switch eku {
		case x509.ExtKeyUsageServerAuth:
			extKeyUsages = append(extKeyUsages, "Server Auth")
		case x509.ExtKeyUsageClientAuth:
			extKeyUsages = append(extKeyUsages, "Client Auth")
		case x509.ExtKeyUsageCodeSigning:
			extKeyUsages = append(extKeyUsages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			extKeyUsages = append(extKeyUsages, "Email Protection")
		}
	}
	if len(extKeyUsages) > 0 {
		fmt.Printf("Ext Key Usage: %s\n", strings.Join(extKeyUsages, ", "))
	}

	// Signature Algorithm
	fmt.Printf("Signature:    %s\n", cert.SignatureAlgorithm.String())
}
