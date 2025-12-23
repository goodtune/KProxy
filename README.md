# KProxy

**Kids Proxy** - A transparent HTTP/HTTPS interception proxy with embedded DNS server for home network parental controls.

## Features

- **Embedded DNS Server** - Single IP configuration point for clients
- **Transparent Proxy** - Intercepts HTTP and HTTPS traffic with TLS termination
- **Dynamic TLS Certificates** - On-the-fly certificate generation for HTTPS interception
- **Intelligent DNS Routing** - Intercept or bypass domains at DNS level
- **Per-Device Policies** - Device identification and custom access rules
- **Domain/Path Filtering** - Fine-grained control with wildcard support
- **Time-Based Access** - Restrict access by time of day and day of week
- **Usage Tracking** - Monitor and limit daily usage per category
- **Request Logging** - Complete HTTP and DNS query logs
- **Prometheus Metrics** - Built-in observability and monitoring
- **Block Pages** - User-friendly block pages with detailed reasons

## Architecture

KProxy consists of several integrated components:

1. **DNS Server** - Resolves queries and decides whether to intercept or bypass
2. **HTTP/HTTPS Proxy** - Intercepts web traffic with TLS termination
3. **Policy Engine** - Evaluates requests against access rules
4. **Certificate Authority** - Generates certificates for HTTPS interception
5. **Storage** - Embedded KV store for configurations and logs
6. **Metrics Server** - Prometheus metrics endpoint

## Quick Start

### Prerequisites

- Go 1.22 or later
- OpenSSL (for CA generation)
- Embedded KV store (BoltDB)

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/goodtune/kproxy.git
   cd kproxy
   ```

2. **Build KProxy:**
   ```bash
   make build
   ```

3. **Generate CA certificates:**
   ```bash
   sudo make generate-ca
   ```

4. **Create configuration:**
   ```bash
   sudo mkdir -p /etc/kproxy
   sudo cp configs/config.example.yaml /etc/kproxy/config.yaml
   # Edit /etc/kproxy/config.yaml as needed
   ```

5. **Create storage directory:**
   ```bash
   sudo mkdir -p /var/lib/kproxy
   ```

6. **Run KProxy:**
   ```bash
   sudo ./bin/kproxy -config /etc/kproxy/config.yaml
   ```

### Client Setup

For KProxy to work, clients must:

1. **Configure DNS** to point to the KProxy server IP
2. **Install the root CA certificate** for HTTPS interception

#### DNS Configuration

**Option A: Router DHCP (Recommended)**
- Configure your router to assign KProxy IP as the DNS server
- All devices will automatically use KProxy

**Option B: Per-Device**
- Manually set DNS to KProxy IP in device network settings

#### Install Root CA Certificate

The root CA certificate is located at `/etc/kproxy/ca/root-ca.crt`

**Windows:**
```cmd
certutil -addstore -user Root C:\path\to\root-ca.crt
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root-ca.crt
```

**Linux:**
```bash
sudo cp root-ca.crt /usr/local/share/ca-certificates/kproxy-ca.crt
sudo update-ca-certificates
```

**iOS:**
1. Email the certificate to the device or host it on a web server
2. Open the certificate and follow the installation prompts
3. Go to Settings > General > About > Certificate Trust Settings
4. Enable full trust for the KProxy Root CA

**Android:**
1. Copy the certificate to the device
2. Go to Settings > Security > Install from storage
3. Select the certificate and follow the prompts

## Configuration

KProxy uses a YAML configuration file. See `configs/config.example.yaml` for a complete example.

### Key Configuration Sections

#### DNS Settings
```yaml
dns:
  upstream_servers:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
  intercept_ttl: 60
  bypass_ttl_cap: 300
  global_bypass:
    - "ocsp.*.com"    # Certificate validation
    - "*.apple.com"   # OS updates (optional)
```

#### TLS Settings
```yaml
tls:
  ca_cert: "/etc/kproxy/ca/root-ca.crt"
  ca_key: "/etc/kproxy/ca/root-ca.key"
  intermediate_cert: "/etc/kproxy/ca/intermediate-ca.crt"
  intermediate_key: "/etc/kproxy/ca/intermediate-ca.key"
  cert_cache_size: 1000
```

## Usage

### Managing Devices

Devices are stored in the embedded KV store. You can manage them via the admin API (future feature).

### Creating Access Profiles

Profiles and rules are stored alongside devices in the embedded KV store. The admin UI will provide CRUD tooling for these entities in a future release.

### DNS Bypass Rules

Configure domains that should bypass the proxy entirely:
Bypass rules are stored in the embedded KV store and will be exposed via the admin UI once available.

## Monitoring

### Prometheus Metrics

KProxy exposes Prometheus metrics on port 9090 by default:

```
http://kproxy-ip:9090/metrics
```

**Key metrics:**
- `kproxy_dns_queries_total` - DNS queries by device and action
- `kproxy_requests_total` - HTTP/HTTPS requests by device
- `kproxy_blocked_requests_total` - Blocked requests by reason
- `kproxy_certificates_generated_total` - TLS certificates generated
- `kproxy_request_duration_seconds` - Request latency

### Logs

Log data is recorded into the storage backend. Admin endpoints for querying and filtering logs will be introduced alongside the UI.

## Deployment

### Systemd Service

```bash
# Install
sudo make install

# Enable and start
sudo systemctl enable kproxy
sudo systemctl start kproxy

# Check status
sudo systemctl status kproxy

# View logs
sudo journalctl -u kproxy -f
```

### Docker

```bash
# Build image
make docker

# Run with Docker
docker run -d \
  --name kproxy \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 80:80 \
  -p 443:443 \
  -p 8443:8443 \
  -p 9090:9090 \
  -v /etc/kproxy:/etc/kproxy \
  -v /var/lib/kproxy:/var/lib/kproxy \
  --cap-add=NET_BIND_SERVICE \
  kproxy:latest
```

### Docker Compose

```yaml
version: '3.8'
services:
  kproxy:
    image: kproxy:latest
    container_name: kproxy
    ports:
      - "53:53/udp"
      - "53:53/tcp"
      - "80:80"
      - "443:443"
      - "8443:8443"
      - "9090:9090"
    volumes:
      - /etc/kproxy:/etc/kproxy
      - /var/lib/kproxy:/var/lib/kproxy
    cap_add:
      - NET_BIND_SERVICE
    restart: unless-stopped
```

## Security Considerations

1. **CA Private Keys** - Keep CA private keys secure with 600 permissions
2. **Storage Encryption** - Consider encrypting the storage file
3. **Log Retention** - Implement appropriate retention policies
4. **Network Security** - Restrict admin interface access
5. **Regular Updates** - Keep KProxy and dependencies updated

## Development

### Building from Source

```bash
# Install dependencies
go mod download

# Build
make build

# Run tests
make test

# Run linters
make lint
```

### Project Structure

```
kproxy/
├── cmd/kproxy/           # Main entry point
├── internal/             # Internal packages
│   ├── ca/              # Certificate authority
│   ├── config/          # Configuration
│   ├── storage/         # Storage layer
│   ├── dns/             # DNS server
│   ├── metrics/         # Prometheus metrics
│   ├── policy/          # Policy engine
│   └── proxy/           # HTTP/HTTPS proxy
├── configs/             # Configuration examples
├── deployments/         # Deployment files
├── scripts/             # Utility scripts
└── docs/                # Documentation
```

## Troubleshooting

### DNS Not Working

- Verify KProxy is listening on port 53: `sudo netstat -tulpn | grep :53`
- Check firewall rules allow DNS traffic
- Test DNS resolution: `dig @kproxy-ip example.com`

### HTTPS Interception Fails

- Verify root CA is installed on client devices
- Check CA certificate paths in configuration
- Verify certificate generation: `openssl x509 -in /etc/kproxy/ca/root-ca.crt -text`

### Devices Not Identified

- Add device identifiers (IP/MAC) to storage
- Enable MAC address identification in config
- Check logs for device identification errors

## Roadmap

- [ ] Admin web UI for configuration
- [ ] Usage limit enforcement with time overlays
- [ ] Response modification for time tracking
- [ ] SafeSearch enforcement
- [ ] Content categorization
- [ ] Mobile app for parents
- [ ] Multi-tenant support

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [miekg/dns](https://github.com/miekg/dns) - DNS library
- [smallstep/certificates](https://github.com/smallstep/certificates) - Certificate management
- [Prometheus](https://prometheus.io/) - Monitoring and metrics

## Support

- **Issues**: https://github.com/goodtune/kproxy/issues
- **Documentation**: https://github.com/goodtune/kproxy/docs

---

**Note**: KProxy is designed for home network parental controls. Always respect privacy and legal requirements in your jurisdiction.
