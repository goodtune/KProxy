<div align="center">

![KProxy](../assets/kproxy-text-logo.jpg)

</div>

**Kids Proxy** - A transparent HTTP/HTTPS interception proxy with embedded DNS server for home network parental controls, powered by Open Policy Agent (OPA).

## Features

- **Embedded DNS Server** - Single IP configuration point for clients
- **Transparent Proxy** - Intercepts HTTP and HTTPS traffic with TLS termination
- **Dynamic TLS Certificates** - On-the-fly certificate generation for HTTPS interception
- **Intelligent DNS Routing** - Intercept or bypass domains at DNS level
- **Policy-Based Control** - Declarative access rules using OPA and Rego
- **Per-Device Policies** - Device identification and custom access rules
- **Domain/Path Filtering** - Fine-grained control with wildcard support
- **Time-Based Access** - Restrict access by time of day and day of week
- **Usage Tracking** - Monitor and limit daily usage per category
- **Bypass Sensitive Domains** - Avoid MITM on banking and critical sites
- **Ad Blocking** - Block advertisement domains like Pi-hole
- **Prometheus Metrics** - Built-in observability and monitoring
- **Structured Logging** - Complete HTTP and DNS query logs via zerolog

## Quick Links

- **[Getting Started](#quick-start)** - Installation and setup
- **[Policy Tutorial](policy-tutorial.md)** - Learn to write OPA policies (from blocking everything to advanced use cases)
- **[CA Installation Guide](ca-installation.md)** - Trust the root CA on your devices
- **[Open Policy Agent & Rego](#open-policy-agent--rego)** - Understanding the policy engine

## Architecture

KProxy uses a **fact-based policy evaluation** approach powered by [Open Policy Agent (OPA)](https://www.openpolicyagent.org/):

```
┌─────────┐      DNS Query       ┌──────────┐
│ Device  │─────────────────────→│   DNS    │
└─────────┘                      │  Server  │
     │                           └────┬─────┘
     │                                │
     │ HTTP/HTTPS Request        ┌────▼─────┐      ┌──────────┐
     ↓                           │  Policy  │◄────→│   OPA    │
┌─────────┐   Facts (IP, MAC,    │  Engine  │      │  Engine  │
│  Proxy  │   domain, time, etc) └────┬─────┘      └──────────┘
│ Server  │◄──────────────────────────┘
└────┬────┘   Decision (Allow/Block)
     │
     ↓
  Internet
```

### How It Works

1. **DNS Stage**: When a device queries DNS, KProxy checks if the domain should be bypassed (banking), intercepted (filtered), or blocked (ads)

2. **Proxy Stage**: For intercepted domains, KProxy:
   - **Gathers facts** about the request (device, time, current usage, URL)
   - **Evaluates OPA policies** written in Rego
   - **Enforces the decision** (allow/block/track usage)

3. **Policy Evaluation**: OPA policies (`.rego` files) define:
   - Which devices exist and their profiles
   - Time restrictions (e.g., no social media during school hours)
   - Domain rules (allow/block by category)
   - Usage limits (e.g., 60 minutes of entertainment per day)
   - Bypass domains (banking, OCSP, etc.)

### Components

| Component | Purpose |
|-----------|---------|
| **DNS Server** | Resolves queries and routes to proxy or internet |
| **HTTP/HTTPS Proxy** | Intercepts web traffic with TLS termination |
| **Policy Engine** | Gathers facts and queries OPA for decisions |
| **OPA Engine** | Evaluates Rego policies against facts |
| **Certificate Authority** | Generates TLS certificates on-demand |
| **Redis Storage** | Stores operational data (usage, DHCP leases) |
| **Metrics Server** | Prometheus metrics endpoint |

### Data Flow: Facts → OPA → Decision

**Old approach (database-driven):**
```
Config (Database) → Go Code (hardcoded logic) → Decision
```

**KProxy approach (policy-driven):**
```
Facts (Go) + Policies (Rego) → OPA Engine → Decision
```

**Benefits:**
- **Configuration as Code**: Version control your policies
- **Declarative**: Describe *what* should happen, not *how*
- **Testable**: Use `opa test` to validate before deployment
- **Flexible**: Change rules without modifying application code
- **Auditable**: Clear separation of facts and policy

## Open Policy Agent & Rego

### What is OPA?

[Open Policy Agent](https://www.openpolicyagent.org/) is a general-purpose policy engine that decouples policy decision-making from policy enforcement. In KProxy:

- **You write policies** in Rego (`.rego` files)
- **KProxy gathers facts** (device identity, time, usage)
- **OPA evaluates** policies against facts
- **KProxy enforces** the decision

### What is Rego?

[Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) is OPA's declarative policy language. Example:

```rego
# Allow educational sites for child profile
allow {
    input.profile == "child"
    some domain in ["*.khanacademy.org", "*.wikipedia.org"]
    matches_domain(input.host, domain)
}

# Block social media for children
deny {
    input.profile == "child"
    some domain in ["*.tiktok.com", "*.snapchat.com"]
    matches_domain(input.host, domain)
}
```

### KProxy's Policy Files

| File | Purpose |
|------|---------|
| `policies/config.rego` | Central configuration: devices, profiles, rules, usage limits |
| `policies/device.rego` | Device identification logic (MAC → IP → CIDR) |
| `policies/dns.rego` | DNS-level decisions (BYPASS/INTERCEPT/BLOCK) |
| `policies/proxy.rego` | HTTP/HTTPS request decisions (ALLOW/BLOCK) |
| `policies/helpers.rego` | Utility functions (domain matching, time checks) |

**Learn more**: See the [Policy Tutorial](policy-tutorial.md) for step-by-step examples.

## Quick Start

### Prerequisites

- **Linux server** with network routing capability
- **Go 1.21+** for building from source
- **Redis** for operational data storage
- **Root access** for binding to privileged ports (DNS 53, HTTP 80, HTTPS 443)

### Installation

1. **Install Redis:**
   ```bash
   # Debian/Ubuntu
   sudo apt-get install redis-server
   sudo systemctl start redis

   # macOS
   brew install redis
   redis-server
   ```

2. **Clone and build KProxy:**
   ```bash
   git clone https://github.com/goodtune/kproxy.git
   cd kproxy
   make build
   ```

3. **Generate CA certificates:**
   ```bash
   sudo make generate-ca
   ```

4. **Configure KProxy:**
   ```bash
   sudo mkdir -p /etc/kproxy/policies
   sudo cp configs/config.example.yaml /etc/kproxy/config.yaml
   sudo cp policies/*.rego /etc/kproxy/policies/

   # Edit configuration
   sudo nano /etc/kproxy/config.yaml
   sudo nano /etc/kproxy/policies/config.rego
   ```

5. **Run KProxy:**
   ```bash
   sudo ./bin/kproxy -config /etc/kproxy/config.yaml
   ```

### Client Setup

For KProxy to work, clients must:

1. **Configure DNS** to point to the KProxy server IP
2. **Install the root CA certificate** for HTTPS interception

See the [CA Installation Guide](ca-installation.md) for detailed instructions per platform.

#### DNS Configuration

**Option A: Router DHCP (Recommended)**
- Configure your router to assign KProxy IP as the DNS server
- All devices will automatically use KProxy

**Option B: Per-Device**
- Manually set DNS to KProxy IP in device network settings

## Configuration

### YAML Configuration

Server settings in `/etc/kproxy/config.yaml`:

```yaml
dns:
  listen: ":53"
  upstream_servers:
    - "8.8.8.8:53"
    - "1.1.1.1:53"

proxy:
  http_listen: ":80"
  https_listen: ":443"

tls:
  ca_cert: "/etc/kproxy/ca/root-ca.crt"
  ca_key: "/etc/kproxy/ca/root-ca.key"
  intermediate_cert: "/etc/kproxy/ca/intermediate-ca.crt"
  intermediate_key: "/etc/kproxy/ca/intermediate-ca.key"

storage:
  redis:
    addr: "localhost:6379"

policy:
  opa_policy_source: filesystem
  opa_policy_dir: /etc/kproxy/policies
```

### Policy Configuration

All access control in `/etc/kproxy/policies/config.rego`:

```rego
package kproxy.config

devices := {
    "kids-ipad": {
        "name": "Kids iPad",
        "identifiers": ["aa:bb:cc:dd:ee:ff"],  # MAC address
        "profile": "child"
    },
    "parents-laptop": {
        "name": "Parents Laptop",
        "identifiers": ["192.168.1.100"],  # IP address
        "profile": "adult"
    }
}

profiles := {
    "child": {
        "time_restrictions": {
            "weekday": {
                "days": [1, 2, 3, 4, 5],  # Monday-Friday
                "start_hour": 15,          # 3 PM
                "end_hour": 20             # 8 PM
            }
        },
        "rules": [
            {
                "id": "allow-educational",
                "domains": ["*.khanacademy.org", "*.wikipedia.org"],
                "action": "allow",
                "priority": 10
            },
            {
                "id": "block-social",
                "domains": ["*.tiktok.com", "*.snapchat.com"],
                "action": "block",
                "priority": 20
            }
        ],
        "usage_limits": {
            "entertainment": {
                "daily_minutes": 60,
                "domains": ["*.youtube.com", "*.netflix.com"]
            }
        },
        "default_action": "block"
    },
    "adult": {
        "default_action": "allow"
    }
}

# Global bypass domains (avoid MITM on sensitive sites)
global_bypass_domains := [
    "*.bank.com",
    "*.paypal.com",
    "ocsp.*.com",
    "*.apple.com"
]
```

**See the [Policy Tutorial](policy-tutorial.md) for comprehensive examples.**

## Monitoring

### Prometheus Metrics

KProxy exposes metrics at `:9090/metrics`:

```
http://kproxy-ip:9090/metrics
```

**Key metrics:**
- `kproxy_dns_queries_total` - DNS queries by device, action, type
- `kproxy_requests_total` - HTTP/HTTPS requests by device, host
- `kproxy_blocked_requests_total` - Blocked requests by device, reason
- `kproxy_certificates_generated_total` - TLS certificates generated
- `kproxy_usage_minutes_consumed_total` - Usage by device, category
- `kproxy_request_duration_seconds` - Request latency
- `kproxy_active_connections` - Current active connections

### Structured Logs

All DNS queries and HTTP/HTTPS requests are logged via zerolog:

```json
{"level":"info","time":"2025-01-15T10:23:45Z","client_ip":"192.168.1.100","domain":"youtube.com","action":"INTERCEPT","latency_ms":12}
{"level":"info","time":"2025-01-15T10:23:46Z","client_ip":"192.168.1.100","method":"GET","host":"youtube.com","path":"/","action":"ALLOW","category":"entertainment"}
```

Route logs to:
- **Systemd journal**: `journalctl -u kproxy -f`
- **Log aggregation**: Vector, Fluentd, etc.
- **File**: Configure via systemd or Docker

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

# Run
docker run -d \
  --name kproxy \
  -p 53:53/udp \
  -p 53:53/tcp \
  -p 80:80 \
  -p 443:443 \
  -p 9090:9090 \
  -v /etc/kproxy:/etc/kproxy \
  --cap-add=NET_BIND_SERVICE \
  kproxy:latest
```

## Security Considerations

1. **CA Private Keys** - Keep CA keys secure with 600 permissions
2. **Policy Access** - Restrict write access to `/etc/kproxy/policies/`
3. **Bypass Domains** - Always bypass banking and OCSP domains
4. **Log Retention** - Implement appropriate retention policies
5. **Network Security** - Firewall the metrics endpoint (9090)
6. **Regular Updates** - Keep KProxy, Redis, and Go dependencies updated

## Troubleshooting

### DNS Not Working

- Verify KProxy is listening: `sudo netstat -tulpn | grep :53`
- Check firewall rules allow DNS traffic
- Test DNS resolution: `dig @kproxy-ip example.com`
- Check logs: `sudo journalctl -u kproxy -f`

### HTTPS Interception Fails

- Verify root CA is installed on client (see [CA Installation Guide](ca-installation.md))
- Check CA certificate paths in config
- Test certificate: `openssl x509 -in /etc/kproxy/ca/root-ca.crt -text -noout`

### Policy Errors

- Validate Rego syntax: `opa test /etc/kproxy/policies/ -v`
- Check logs for OPA compilation errors
- Test policy locally: `opa eval -d /etc/kproxy/policies/ -i input.json "data.kproxy.proxy.decision"`

### Devices Not Identified

- Add device MAC/IP to `policies/config.rego`
- Check DHCP leases in Redis: `redis-cli KEYS "kproxy:dhcp:*"`
- Enable debug logging in config

## Testing Policies

Test your policies before deploying:

```bash
# Run policy tests
opa test /etc/kproxy/policies/ -v

# Evaluate a specific query
echo '{"client_ip": "192.168.1.100", "host": "youtube.com"}' | \
  opa eval -d /etc/kproxy/policies/ -I -f pretty "data.kproxy.proxy.decision"
```

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

# Test OPA policies
opa test policies/
```

### Project Structure

```
kproxy/
├── cmd/kproxy/              # Main entry point
├── internal/
│   ├── ca/                  # Certificate authority
│   ├── config/              # Configuration loader
│   ├── dns/                 # DNS server
│   ├── metrics/             # Prometheus metrics
│   ├── policy/              # Policy engine & OPA integration
│   ├── proxy/               # HTTP/HTTPS proxy
│   ├── storage/             # Storage interface & Redis impl
│   └── usage/               # Usage tracking
├── policies/                # OPA Rego policies
│   ├── config.rego         # Central configuration
│   ├── device.rego         # Device identification
│   ├── dns.rego            # DNS decisions
│   ├── proxy.rego          # Proxy decisions
│   └── helpers.rego        # Utility functions
├── configs/                 # Configuration examples
└── docs/                    # Documentation
```

## Learning Resources

- **[Policy Tutorial](policy-tutorial.md)** - Step-by-step guide to writing KProxy policies
- **[CA Installation Guide](ca-installation.md)** - Install root CA on various platforms
- **[OPA Documentation](https://www.openpolicyagent.org/docs/latest/)** - Official OPA docs
- **[Rego Playground](https://play.openpolicyagent.org/)** - Test Rego policies online
- **[CLAUDE.md](../CLAUDE.md)** - Development guide for contributors

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests (Go tests + OPA policy tests)
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [Open Policy Agent](https://www.openpolicyagent.org/) - Policy engine
- [miekg/dns](https://github.com/miekg/dns) - DNS library
- [Redis](https://redis.io/) - Operational data storage
- [Prometheus](https://prometheus.io/) - Monitoring and metrics

## Support

- **Issues**: https://github.com/goodtune/kproxy/issues
- **Discussions**: https://github.com/goodtune/kproxy/discussions

---

**Note**: KProxy is designed for home network parental controls. Always respect privacy and legal requirements in your jurisdiction.
