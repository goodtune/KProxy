# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

KProxy is a transparent HTTP/HTTPS interception proxy with embedded DNS server for home network parental controls. It uses **fact-based Open Policy Agent (OPA)** evaluation where:
- **Facts** are gathered from requests (IP, MAC, domain, time, current usage)
- **Policies** are declarative Rego code defining access rules
- **Configuration** lives in OPA policies, not database

## Architecture Philosophy: Facts → OPA → Decision

KProxy follows a clean separation of concerns:
1. **Go code gathers facts**: Client IP/MAC, domain, time, current usage from database
2. **OPA evaluates policies**: Rego policies define devices, profiles, rules, and make decisions
3. **Go code enforces decisions**: Block, allow, inject timer, log requests

**What's in the database:**
- Operational data only: `daily_usage`, `usage_sessions`
- Network state: `dhcp_leases`

**What's NOT in the database:**
- ~~Devices, Profiles, Rules, TimeRules, UsageLimits, BypassRules~~ (moved to OPA policies)
- ~~request_logs, dns_logs~~ (logs written to structured logger - zerolog)
- ~~admin_users~~ (admin UI removed, use Prometheus metrics for monitoring)

## Build & Development Commands

### Building
```bash
make build          # Build kproxy binary (no CGO required with Redis storage)
make tidy           # Run go mod tidy
make clean          # Remove build artifacts
```

**Note**: Builds with `CGO_ENABLED=0` (no CGO required).

### Testing & Quality
```bash
make test           # Run all tests with race detection and coverage
make lint           # Run golangci-lint (requires golangci-lint installed)
opa test policies/  # Test OPA policies
```

### Running
```bash
make run            # Run kproxy locally with example config
sudo ./bin/kproxy -config /etc/kproxy/config.yaml  # Run with custom config
```

### CA Certificate Generation
```bash
sudo make generate-ca    # Generate CA certificates using scripts/generate-ca.sh
```

### Systemd Integration

KProxy supports **systemd socket activation** and **sd_notify protocol** for production deployments.

#### Benefits
- **No root privileges required** for binding privileged ports (80, 443, 53)
- **Zero-downtime restarts** - systemd holds connections during restart
- **Service readiness notification** - systemd knows when kproxy is ready
- **Automatic restart on failure**
- **Better security** - run as unprivileged user

#### Quick Start
```bash
# Install systemd units
sudo cp systemd/kproxy.socket /etc/systemd/system/
sudo cp systemd/kproxy.service /etc/systemd/system/
sudo systemctl daemon-reload

# Enable and start socket activation
sudo systemctl enable kproxy.socket
sudo systemctl start kproxy.socket

# Zero-downtime restart
sudo systemctl restart kproxy.service
```

See `systemd/README.md` for detailed installation and configuration instructions.

#### Implementation Details
- **Socket activation**: Uses `github.com/coreos/go-systemd/v22/activation` (pure Go, no CGO)
- **sd_notify**: Uses `github.com/coreos/go-systemd/v22/daemon` (pure Go, no CGO)
- **Named file descriptors**: HTTP, HTTPS, DNS (UDP/TCP), Metrics
- **Graceful fallback**: Works with or without systemd (auto-detects)

## Policy Configuration

All access control configuration is defined in **OPA Rego policies** in the `policies/` directory:

### Policy Files

- **`config.rego`**: Central configuration
  - Device definitions (MAC addresses, IPs, CIDR ranges)
  - Profile configurations (time restrictions, usage limits)
  - Access rules (allow/block domains by category)
  - Global bypass domains

- **`device.rego`**: Device identification logic
  - Identifies devices from client IP/MAC facts
  - Priority: MAC → Exact IP → CIDR range

- **`dns.rego`**: DNS action decisions
  - Determines BYPASS, INTERCEPT, or BLOCK
  - Checks global bypass domains

- **`proxy.rego`**: Proxy request evaluation
  - Main decision logic: ALLOW or BLOCK
  - Checks time restrictions
  - Evaluates rules by priority
  - Enforces usage limits

- **`helpers.rego`**: Utility functions
  - Domain matching (exact, wildcard, suffix)
  - CIDR matching
  - Time window checking

### Example Configuration

Edit `policies/config.rego` to configure your network:

```rego
devices := {
    "kids-ipad": {
        "name": "Kids iPad",
        "identifiers": ["aa:bb:cc:dd:ee:ff", "192.168.1.100"],
        "profile": "child"
    },
    "parents-laptop": {
        "name": "Parents Laptop",
        "identifiers": ["bb:cc:dd:ee:ff:00"],
        "profile": "adult"
    }
}

profiles := {
    "child": {
        "time_restrictions": {
            "weekday": {
                "days": [1, 2, 3, 4, 5],
                "start_hour": 15, "end_hour": 20
            }
        },
        "rules": [
            {"id": "allow-educational", "domains": ["*.khanacademy.org"], "action": "allow"},
            {"id": "block-social", "domains": ["*.tiktok.com"], "action": "block"}
        ],
        "usage_limits": {
            "entertainment": {"daily_minutes": 60, "domains": ["*.youtube.com"]}
        },
        "default_action": "block"
    }
}
```

### Testing Policies

```bash
# Test policies locally
opa test policies/ -v

# Evaluate a query
opa eval -d policies/ -i input.json "data.kproxy.dns.action"
```

### Remote Policies

KProxy supports loading policies from remote URLs for centralized management:

```yaml
policy:
  opa_policy_source: remote
  opa_policy_urls:
    - https://policy-server.example.com/policies/config.rego
    - https://policy-server.example.com/policies/device.rego
    - https://policy-server.example.com/policies/dns.rego
    - https://policy-server.example.com/policies/proxy.rego
    - https://policy-server.example.com/policies/helpers.rego
```

## Architecture Overview

### Component Dependency Flow

```
main.go
  │
  ├─> Database (Redis) - operational data only
  │     └─> Data: usage_sessions, daily_usage, dhcp_leases
  │
  ├─> Certificate Authority (CA)
  │     └─> Loads root & intermediate certs for dynamic TLS generation
  │
  ├─> Policy Engine - fact-based OPA evaluation
  │     ├─> OPA Engine (loads Rego policies from filesystem or remote)
  │     ├─> Gathers facts: IP, MAC, domain, time, current usage
  │     └─> Returns decisions: ALLOW/BLOCK/BYPASS with metadata
  │
  ├─> Usage Tracker - tracks usage by category
  │     ├─> Records activity sessions
  │     ├─> Queries current usage for policy evaluation
  │     └─> Connected to Policy Engine for usage facts
  │
  ├─> DNS Server - DNS-level routing decisions
  │     ├─> Gathers facts: client IP, domain
  │     ├─> Calls OPA for BYPASS/INTERCEPT/BLOCK decision
  │     ├─> Logs queries to structured logger (zerolog)
  │     └─> Returns proxy IP for intercepted domains
  │
  ├─> Proxy Server - HTTP/HTTPS request filtering
  │     ├─> Gathers facts: IP, MAC, host, path, time, usage
  │     ├─> Calls OPA for ALLOW/BLOCK decision
  │     ├─> Logs requests to structured logger (zerolog)
  │     └─> Generates TLS certificates
  │
  └─> Metrics Server - Prometheus metrics endpoint
        └─> Exposes metrics for monitoring (requests, DNS queries, blocks, usage, etc.)
```

### Critical Design Patterns

1. **Fact-Based OPA**: Go code gathers facts, OPA makes declarative policy decisions
2. **Configuration as Code**: Devices, profiles, rules defined in version-controlled Rego
3. **Two-Stage Filtering**: DNS decides bypass/intercept, Proxy enforces detailed rules
4. **Dynamic TLS**: On-demand certificate generation with LRU cache
5. **Category-Based Usage**: Track usage by category (entertainment, educational, etc.)
6. **Metrics-Based Monitoring**: Prometheus metrics for observability, no admin UI
7. **Structured Logging**: Logs written to zerolog (stdout/journal), not database

## Storage Backend

KProxy uses **Redis** for operational data storage (configured via `storage.redis` in config.yaml):

### Redis Storage
- **Benefits**: No CGO required, horizontal scaling, automatic TTL-based cleanup, atomic operations
- **Data structure**: Redis Hashes with Sets for indexes
- **Key patterns**:
  - `kproxy:session:{id}` - UsageSession data
  - `kproxy:sessions:active` - Set of active session IDs
  - `kproxy:usage:daily:{date}:{deviceID}:{limitID}` - DailyUsage data
  - `kproxy:dhcp:mac:{mac}` - DHCPLease data
  - `kproxy:dhcp:ip:{ip}` - IP→MAC secondary index

### Operational Data Only
Redis stores only operational data:
- **usage_sessions**: Active usage tracking sessions
- **daily_usage**: Accumulated usage time per device/category/date
- **dhcp_leases**: DHCP IP address leases

**Removed data:**
- ~~request_logs, dns_logs~~ → Logs written to structured logger (zerolog)
- ~~admin_users~~ → Admin UI removed, use Prometheus metrics for monitoring

## Policy Evaluation Flow

### DNS Level (policies/dns.rego)

**Input (facts):**
```json
{
  "client_ip": "192.168.1.100",
  "client_mac": "aa:bb:cc:dd:ee:ff",
  "domain": "youtube.com"
}
```

**Decision:**
- Check global bypass domains → BYPASS
- Default → INTERCEPT

### Proxy Level (policies/proxy.rego)

**Input (facts):**
```json
{
  "client_ip": "192.168.1.100",
  "client_mac": "aa:bb:cc:dd:ee:ff",
  "host": "youtube.com",
  "path": "/watch",
  "time": {"day_of_week": 2, "hour": 16, "minute": 30},
  "usage": {
    "entertainment": {"today_minutes": 45}
  }
}
```

**Decision logic:**
1. Identify device (MAC → IP → CIDR)
2. Get profile from config
3. Check time restrictions
4. Match rules by priority
5. Check usage limits
6. Return ALLOW/BLOCK with metadata

## Configuration Management

Configuration split between:
- **YAML file** (`configs/config.example.yaml`): Server settings, ports, TLS paths
- **Rego policies** (`policies/*.rego`): All access control logic

The YAML config is loaded once at startup. Rego policies can be:
- **Filesystem**: Loaded from local directory (e.g., `/etc/kproxy/policies`)
- **Remote**: Fetched from HTTPS URLs (production)

### Policy Reload

Policies are loaded at startup and can be reloaded without restarting the service by sending a **SIGHUP** signal:

```bash
# Reload policies (filesystem or remote)
sudo systemctl reload kproxy.service   # With systemd
sudo kill -HUP $(pidof kproxy)        # Direct signal

# The server will:
# - Re-read policy files from filesystem (if using filesystem source)
# - Re-fetch policies from remote URLs (if using remote source)
# - Re-compile all policies
# - Continue serving requests without downtime
```

**Note**: Changes to the YAML configuration file (`config.yaml`) require a full service restart.

## Key Implementation Details

### Device Identification (policies/device.rego)
- Priority: MAC address (most reliable) → Exact IP → CIDR range
- Defined in `policies/config.rego` devices map
- Evaluated by OPA from facts

### Domain Matching (helpers.rego)
- Exact match: `youtube.com`
- Wildcard: `*.youtube.com` matches `www.youtube.com`
- Suffix: `.youtube.com` matches `sub.youtube.com`

### Usage Tracking
- Category-based: tracks by category (entertainment, educational, etc.)
- Session-based with inactivity timeout (default 2 minutes)
- Usage facts passed to OPA for limit evaluation
- OPA decides if limit exceeded, Go records activity

### Certificate Generation
- Root CA + Intermediate CA loaded at startup
- Intermediate signs leaf certificates on-demand
- LRU cache (default 1000 entries, 24h TTL)

### Metrics & Observability

**Prometheus metrics** via `internal/metrics/metrics.go`:
- `kproxy_dns_queries_total` - DNS queries by device, action, query type
- `kproxy_dns_query_duration_seconds` - DNS query latency
- `kproxy_dns_upstream_errors_total` - Upstream DNS errors
- `kproxy_requests_total` - HTTP/HTTPS requests by device, host, action, method
- `kproxy_request_duration_seconds` - Request latency
- `kproxy_blocked_requests_total` - Blocked requests by device, reason
- `kproxy_certificates_generated_total` - TLS cert generation
- `kproxy_certificate_cache_hits_total` - Certificate cache hits
- `kproxy_certificate_cache_misses_total` - Certificate cache misses
- `kproxy_usage_minutes_consumed_total` - Usage minutes by device, category
- `kproxy_active_connections` - Active connections
- `kproxy_dhcp_requests_total` - DHCP requests by type
- `kproxy_dhcp_leases_active` - Active DHCP leases

**Structured logging** via zerolog:
- All DNS queries logged to stdout/journal with fields: `client_ip`, `domain`, `query_type`, `action`, `response_ip`, `upstream`, `latency_ms`
- All HTTP/HTTPS requests logged with fields: `client_ip`, `client_mac`, `method`, `host`, `path`, `user_agent`, `status_code`, `response_size`, `duration_ms`, `action`, `matched_rule`, `reason`, `category`, `encrypted`
- Logs routed via systemd journal, syslog, or log aggregation tools (Vector, Fluentd, etc.)

**Monitoring stack:**
- Use Prometheus to scrape metrics from `http://<server>:9090/metrics`
- Use Grafana or similar for dashboards and visualization
- Use log aggregation tools for log analysis and search

## OPA Integration

KProxy uses OPA as an embedded library for policy evaluation.

### Architecture

```
Policy Engine (Go)
  ├─> Gathers facts from request and database
  ├─> OPA Engine (internal/policy/opa/engine.go)
  │     ├─> Loads Rego policies from directory or URLs
  │     ├─> Compiles policies into prepared queries
  │     └─> Evaluates queries with input (facts)
  └─> Returns structured decision
```

### Policy Input Format

**DNS query:**
```json
{
  "client_ip": "192.168.1.100",
  "client_mac": "aa:bb:cc:dd:ee:ff",
  "domain": "youtube.com"
}
```

**Proxy request:**
```json
{
  "client_ip": "192.168.1.100",
  "client_mac": "aa:bb:cc:dd:ee:ff",
  "host": "youtube.com",
  "path": "/watch",
  "time": {"day_of_week": 2, "hour": 16, "minute": 30},
  "usage": {
    "entertainment": {"today_minutes": 45}
  }
}
```

### Configuration Sources

**Filesystem (default for development):**
```yaml
policy:
  opa_policy_source: filesystem
  opa_policy_dir: /etc/kproxy/policies  # or ./policies for dev
```

**Remote (production):**
```yaml
policy:
  opa_policy_source: remote
  opa_policy_urls:
    - https://policy-server.example.com/policies/config.rego
    - https://policy-server.example.com/policies/device.rego
    - https://policy-server.example.com/policies/dns.rego
    - https://policy-server.example.com/policies/proxy.rego
    - https://policy-server.example.com/policies/helpers.rego
  opa_http_timeout: 30s
  opa_http_retries: 3
```

## Development Guidelines

### Adding New Policy Features
1. Update `policies/config.rego` with new configuration structure
2. Update `policies/proxy.rego` or `policies/dns.rego` with evaluation logic
3. Update fact gathering in `internal/policy/engine.go` if needed (e.g., new facts from DB)
4. Test with `opa test policies/`
5. Update this documentation

### Changing Access Rules
1. Edit `policies/config.rego`
2. Update device identifiers, profiles, rules, or usage limits
3. For filesystem policies: changes auto-reload
4. For remote policies: update remote policy server

### Testing
- **Unit tests**: `go test -v -race -cover ./...`
- **Policy tests**: `opa test policies/ -v`
- **Integration tests**: Use mock OPA engine with test policies

## Common Gotchas

1. **Policy Changes**: Edit `.rego` files, not database. Configuration is code now.
2. **OPA Compilation Errors**: Invalid Rego syntax prevents startup. Test with `opa test`.
3. **Policy Source**:
   - **Filesystem**: Policies in `opa_policy_dir` (default `/etc/kproxy/policies`)
   - **Remote**: All URLs must be accessible at startup
4. **Remote Policy Security**: Use HTTPS, implement auth on policy server
5. **Storage Backend**: Redis (no CGO required)
6. **Port Permissions**: DNS (53), HTTP (80), HTTPS (443) require root/CAP_NET_BIND_SERVICE
7. **CA Trust**: Clients must trust root CA for HTTPS interception
8. **Usage Tracking**: Category names in `gatherUsageFacts()` must match policy categories
9. **Device Identification**: MAC is most reliable, but DNS queries don't have MAC (uses IP only)

## Migration from Old Architecture

The project was refactored from database-backed configuration to fact-based OPA:

**Old approach:**
- Devices, profiles, rules stored in database
- Go code loaded config from DB into memory
- OPA evaluated pre-loaded config data

**New approach:**
- Devices, profiles, rules defined in Rego policies
- Go code gathers facts (IP, MAC, time, usage)
- OPA evaluates facts against policies

**No migration tool needed**: Configuration must be redefined in `policies/config.rego`.

## File Structure

```
kproxy/
├── cmd/kproxy/main.go              # Application entry point
├── internal/
│   ├── policy/
│   │   ├── engine.go               # Fact gathering and OPA integration
│   │   ├── types.go                # Policy decision types
│   │   ├── clock.go                # Time interface for testing
│   │   └── opa/
│   │       └── engine.go           # OPA engine wrapper
│   ├── storage/
│   │   ├── store.go                # Storage interface (operational data only)
│   │   ├── types.go                # Storage types
│   │   └── redis/                  # Redis implementation
│   ├── usage/
│   │   ├── tracker.go              # Usage session tracking
│   │   └── reset.go                # Daily usage reset scheduler
│   ├── dns/server.go               # DNS server
│   ├── proxy/server.go             # HTTP/HTTPS proxy
│   ├── ca/ca.go                    # Certificate authority
│   ├── metrics/metrics.go          # Prometheus metrics
│   └── config/config.go            # Configuration loader
├── policies/
│   ├── config.rego                 # Central configuration
│   ├── device.rego                 # Device identification
│   ├── dns.rego                    # DNS decisions
│   ├── proxy.rego                  # Proxy decisions
│   └── helpers.rego                # Utility functions
└── configs/
    └── config.example.yaml         # Server configuration template
```
