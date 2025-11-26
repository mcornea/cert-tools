# cert-tools

A simple CLI tool for generating X.509 certificates. Create a Certificate Authority and issue host certificates for development, testing, or internal services.

## Installation

```bash
go build -o cert-tools .
```

## Usage

```bash
cert-tools <command> [options] [arguments]
```

### Commands

| Command | Description |
|---------|-------------|
| `init-ca` | Create a new Certificate Authority |
| `create` | Create certificates for one or more hosts |
| `decode` | Decode and display certificate information |
| `help` | Show help message |

### init-ca

Create a new Certificate Authority.

```bash
cert-tools init-ca [options]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--out`, `-o` | Output directory | `./certs` |
| `--cn` | Common Name | `Cert Tools CA` |
| `--org` | Organization | `Cert Tools` |
| `--country` | Country (2-letter code) | - |
| `--province` | State or Province | - |
| `--locality` | City or Locality | - |
| `--years` | Validity in years | `10` |

**Examples:**

```bash
# Create CA with defaults
cert-tools init-ca

# Create CA with custom subject
cert-tools init-ca --cn "My Company CA" --org "My Company" --country US

# Create CA in custom directory with 5-year validity
cert-tools init-ca --out ./my-certs --years 5
```

### create

Create certificates for one or more hosts. If no CA exists, one will be created automatically.

```bash
cert-tools create [options] HOST [HOST...]
```

**Options:**

| Flag | Description | Default |
|------|-------------|---------|
| `--out`, `-o` | Output directory | `./certs` |
| `--org` | Organization | - |
| `--country` | Country (2-letter code) | - |
| `--province` | State or Province | - |
| `--locality` | City or Locality | - |
| `--days` | Validity in days | `365` |

**Examples:**

```bash
# Create certificate for a single host
cert-tools create example.com

# Create certificates for multiple hosts
cert-tools create example.com localhost 192.168.1.1

# Create certificate with custom options
cert-tools create --org "My Company" --days 90 api.example.com

# Create certificates in custom directory
cert-tools create --out ./my-certs example.com
```

### decode

Decode and display certificate information.

```bash
cert-tools decode CERT_FILE [CERT_FILE...]
```

**Examples:**

```bash
# Decode CA certificate
cert-tools decode ./certs/ca.crt

# Decode host certificate
cert-tools decode ./certs/example.com.crt

# Decode multiple certificates
cert-tools decode ./certs/ca.crt ./certs/example.com.crt
```

## Output Files

Certificates are saved to the output directory (default: `./certs`):

| File | Description |
|------|-------------|
| `ca.crt` | CA certificate |
| `ca.key` | CA private key |
| `<hostname>.crt` | Host certificate |
| `<hostname>.key` | Host private key |

## Technical Details

- **CA key size:** 4096-bit RSA
- **Host key size:** 2048-bit RSA
- **CA validity:** 10 years (configurable)
- **Host validity:** 365 days (configurable)
- **Key usage:** Digital Signature, Key Encipherment
- **Extended key usage:** Server Auth, Client Auth
- **SAN support:** DNS names and IP addresses

## License

MIT
