# KProxy

A transparent HTTP/HTTPS interception proxy with embedded DNS server for home network parental controls, powered by [Open Policy Agent](https://www.openpolicyagent.org/).

## What is KProxy?

KProxy sits between your home devices and the internet, providing intelligent, policy-based access control:

- **Block inappropriate content** with time-based restrictions
- **Track and limit screen time** by category (entertainment, educational, etc.)
- **Bypass sensitive sites** (banking) to avoid MITM issues
- **Block advertisements** at the DNS level like Pi-hole
- **Configure with code** using declarative Rego policies

Unlike traditional parental controls, KProxy uses **policy-as-code** with OPA, giving you full control over access rules through version-controlled configuration files instead of databases or GUIs.

## Key Features

✨ **Policy-Based Control** - Define access rules in declarative Rego code
🕐 **Time-Based Restrictions** - Allow access only during specific hours
📊 **Usage Tracking & Limits** - Track and limit daily usage by category
🔒 **HTTPS Interception** - Transparent TLS termination with dynamic certificates
🌐 **Embedded DNS Server** - Single-point configuration for network clients
🚫 **Ad Blocking** - Block ad domains like Pi-hole
🏦 **Bypass Sensitive Sites** - Avoid MITM on banking and critical services
📈 **Prometheus Metrics** - Built-in observability and monitoring
🗃️ **Redis Storage** - Fast, scalable operational data storage

## Quick Start

```bash
# 1. Install dependencies
sudo apt-get install redis-server  # or: brew install redis
sudo systemctl start redis

# 2. Clone and build
git clone https://github.com/goodtune/kproxy.git
cd kproxy
make build

# 3. Generate CA certificates
sudo make generate-ca

# 4. Configure
sudo mkdir -p /etc/kproxy/policies
sudo cp configs/config.example.yaml /etc/kproxy/config.yaml
sudo cp policies/*.rego /etc/kproxy/policies/

# 5. Edit your policies
sudo nano /etc/kproxy/policies/config.rego

# 6. Run
sudo ./bin/kproxy -config /etc/kproxy/config.yaml
```

## Documentation

📚 **[Complete Documentation](docs/README.md)** - Architecture, setup, configuration

🎓 **[Policy Tutorial](docs/policy-tutorial.md)** - Step-by-step guide to writing policies:
- Start with "block everything"
- Allow specific services (Google, Gmail, etc.)
- Time-based restrictions by device/subnet
- Bypass banking sites
- Block advertisement domains

🔐 **[CA Installation Guide](docs/ca-installation.md)** - Install root CA on your devices:
- Windows, macOS, Linux
- iOS, Android, Chrome OS
- Firefox (all platforms)

⚙️ **[Development Guide](CLAUDE.md)** - For contributors

## How It Works

```
┌─────────┐                          ┌──────────┐
│ Device  │───── DNS Query ─────────→│   DNS    │
└─────────┘                          │  Server  │
     │                               └────┬─────┘
     │                                    │
     │                               ┌────▼─────┐      ┌──────────┐
     │                               │  Policy  │◄────→│   OPA    │
     │   HTTP/HTTPS Request          │  Engine  │      │  Engine  │
     ↓                               └────┬─────┘      └──────────┘
┌─────────┐   Facts: IP, MAC,             │
│  Proxy  │   domain, time, usage    Decision:
│ Server  │◄─────────────────────────Allow/Block
└────┬────┘
     │
     ↓
  Internet
```

### Fact-Based Policy Evaluation

1. **Go gathers facts**: Client IP/MAC, domain, time, current usage
2. **OPA evaluates policies**: Written in Rego (declarative policy language)
3. **Go enforces decisions**: Allow, block, or track usage

**Configuration lives in code** (`policies/*.rego`), not in a database. This means:
- ✅ Version control your policies with Git
- ✅ Test policies with `opa test`
- ✅ Change rules without modifying application code
- ✅ Declarative: describe *what*, not *how*

## Example Policy

```rego
# /etc/kproxy/policies/config.rego
package kproxy.config

devices := {
    "kids-ipad": {
        "name": "Kids iPad",
        "identifiers": ["aa:bb:cc:dd:ee:ff"],  # MAC address
        "profile": "child"
    }
}

profiles := {
    "child": {
        "time_restrictions": {
            "after-school": {
                "days": [1, 2, 3, 4, 5],  # Monday-Friday
                "start_hour": 15,          # 3 PM
                "end_hour": 18             # 6 PM
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
    }
}

# Bypass banking sites (no MITM)
global_bypass_domains := [
    ".wellsfargo.com",
    ".bankofamerica.com",
    "ocsp.*.com"  # Certificate validation
]
```

**This policy:**
- ✅ Allows educational sites for kids
- ❌ Blocks social media
- ⏰ Restricts access to 3-6 PM on weekdays
- 📊 Limits entertainment to 60 min/day
- 🏦 Bypasses banking sites (no interception)

**Learn more:** [Policy Tutorial](docs/policy-tutorial.md)

## Requirements

- **Linux server** (or Docker/VM) with network routing capability
- **Go 1.21+** for building from source
- **Redis** for operational data storage
- **Root/sudo access** for binding to privileged ports (DNS 53, HTTP 80, HTTPS 443)

## Client Setup

1. **Point DNS to KProxy server IP**
   - Option A: Configure router DHCP (recommended - applies to all devices)
   - Option B: Set DNS manually per device

2. **Install root CA certificate**
   - Required for HTTPS interception
   - See [CA Installation Guide](docs/ca-installation.md)

## Building & Testing

```bash
# Build
make build

# Run tests
make test

# Test OPA policies
opa test policies/ -v

# Run linter
make lint

# Generate CA certificates
sudo make generate-ca
```

## Monitoring

**Prometheus metrics** available at `:9090/metrics`:

```bash
curl http://kproxy-server:9090/metrics
```

**Key metrics:**
- `kproxy_dns_queries_total` - DNS queries by device/action
- `kproxy_requests_total` - HTTP/HTTPS requests
- `kproxy_blocked_requests_total` - Blocked requests
- `kproxy_usage_minutes_consumed_total` - Usage by category
- `kproxy_certificates_generated_total` - Certificate generation

**Structured logs** (zerolog):

```bash
sudo journalctl -u kproxy -f
```

## Deployment

### Systemd

```bash
sudo make install
sudo systemctl enable kproxy
sudo systemctl start kproxy
```

### Docker

```bash
docker run -d \
  --name kproxy \
  -p 53:53/udp -p 53:53/tcp \
  -p 80:80 -p 443:443 \
  -p 9090:9090 \
  -v /etc/kproxy:/etc/kproxy \
  --cap-add=NET_BIND_SERVICE \
  kproxy:latest
```

## Architecture

### Components

| Component | Purpose |
|-----------|---------|
| **DNS Server** | Routes domains to proxy or internet |
| **HTTP/HTTPS Proxy** | Intercepts web traffic with TLS termination |
| **Policy Engine** | Gathers facts and queries OPA |
| **OPA Engine** | Evaluates Rego policies |
| **Certificate Authority** | Generates TLS certificates on-demand |
| **Redis Storage** | Stores usage data and DHCP leases |
| **Metrics Server** | Prometheus endpoint |

### Storage

**Redis** stores operational data only:
- `usage_sessions` - Active usage tracking
- `daily_usage` - Time consumed per device/category
- `dhcp_leases` - DHCP IP assignments

**All configuration** (devices, profiles, rules) lives in **Rego policies**, not the database.

## Why OPA?

[Open Policy Agent](https://www.openpolicyagent.org/) decouples policy from code:

**Traditional approach:**
```
Config (DB) → Hardcoded logic (Go) → Decision
```

**KProxy approach:**
```
Facts (Go) + Policies (Rego) → OPA → Decision
```

**Benefits:**
- **Declarative** - Describe what should happen, not how
- **Testable** - `opa test` validates policies
- **Versionable** - Git for policy history
- **Flexible** - Change rules without code changes
- **Auditable** - Clear separation of concerns

## Use Cases

**Parental Controls:**
- Block social media during homework hours
- Limit YouTube to 1 hour per day
- Allow only educational sites for young children

**Network Security:**
- Block known malicious domains
- Prevent access to inappropriate content
- Log all HTTPS requests for audit

**Ad Blocking:**
- Block advertisement domains at DNS level
- Faster than browser-based ad blockers
- Works network-wide

**Development/Testing:**
- Intercept HTTPS for debugging
- Test certificate handling
- Inspect encrypted traffic

## Security Considerations

✅ **Keep the CA private key secure:**
```bash
sudo chmod 600 /etc/kproxy/ca/root-ca.key
sudo chown root:root /etc/kproxy/ca/root-ca.key
```

✅ **Bypass sensitive sites:**
```rego
global_bypass_domains := [
    ".wellsfargo.com",
    ".bankofamerica.com",
    "ocsp.*.com"  # Certificate validation
]
```

✅ **Restrict policy write access:**
```bash
sudo chmod 700 /etc/kproxy/policies
```

✅ **Firewall metrics endpoint:**
```bash
# Only allow from monitoring network
sudo ufw allow from 192.168.1.0/24 to any port 9090
```

⚠️ **Never share your CA private key**
⚠️ **Never use someone else's CA certificate**
⚠️ **Always bypass banking/healthcare sites**

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests (Go + OPA policy tests)
5. Submit a pull request

See [CLAUDE.md](CLAUDE.md) for development guidelines.

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Open Policy Agent](https://www.openpolicyagent.org/) - Policy engine
- [miekg/dns](https://github.com/miekg/dns) - DNS library
- [Redis](https://redis.io/) - Data storage
- [Prometheus](https://prometheus.io/) - Metrics
- [zerolog](https://github.com/rs/zerolog) - Structured logging

## Resources

- **GitHub**: [github.com/goodtune/kproxy](https://github.com/goodtune/kproxy)
- **Documentation**: [docs/README.md](docs/README.md)
- **Policy Tutorial**: [docs/policy-tutorial.md](docs/policy-tutorial.md)
- **CA Installation**: [docs/ca-installation.md](docs/ca-installation.md)
- **OPA Docs**: [openpolicyagent.org/docs](https://www.openpolicyagent.org/docs/latest/)
- **Rego Playground**: [play.openpolicyagent.org](https://play.openpolicyagent.org/)

## Support

- **Issues**: [github.com/goodtune/kproxy/issues](https://github.com/goodtune/kproxy/issues)
- **Discussions**: [github.com/goodtune/kproxy/discussions](https://github.com/goodtune/kproxy/discussions)

---

**Note**: KProxy is designed for home network parental controls and legitimate network monitoring. Always respect privacy and comply with legal requirements in your jurisdiction. Only install the CA certificate on devices you own or have explicit permission to monitor.
