# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

KProxy is a transparent HTTP/HTTPS interception proxy with embedded DNS server for home network parental controls. It combines DNS-level routing decisions with proxy-level policy enforcement, dynamic TLS certificate generation, and usage tracking.

## Build & Development Commands

### Building
```bash
make build          # Build kproxy binary (requires CGO_ENABLED=1)
make tidy           # Run go mod tidy
make clean          # Remove build artifacts
```

### Testing & Quality
```bash
make test           # Run all tests with race detection and coverage
make lint           # Run golangci-lint (requires golangci-lint installed)
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

### Deployment
```bash
make install        # Install binary and systemd service
make docker         # Build Docker image
```

## Architecture Overview

KProxy is a multi-component system initialized and orchestrated from `cmd/kproxy/main.go`. Understanding component dependencies is critical:

### Component Dependency Flow

```
main.go
  │
  ├─> Database (SQLite) - initialized first
  │     └─> Runs migrations on startup (internal/database/db.go)
  │
  ├─> Certificate Authority (CA)
  │     └─> Loads root & intermediate certs for dynamic TLS generation
  │
  ├─> Policy Engine - depends on Database
  │     ├─> Loads devices, profiles, rules, time rules, usage limits, bypass rules
  │     ├─> Provides device identification (IP/MAC)
  │     └─> Evaluates access decisions
  │
  ├─> Usage Tracker - depends on Database
  │     ├─> Tracks active sessions with inactivity timeout
  │     ├─> Accumulates usage time per device/limit
  │     └─> Connected to Policy Engine via SetUsageTracker()
  │
  ├─> Reset Scheduler - depends on Database
  │     └─> Runs daily reset of usage counters at configured time
  │
  ├─> DNS Server - depends on Policy Engine & Database
  │     ├─> Decides INTERCEPT/BYPASS/BLOCK at DNS level
  │     ├─> Returns proxy IP for intercepted domains
  │     └─> Forwards to upstream for bypassed domains
  │
  ├─> Proxy Server - depends on Policy Engine, CA, & Database
  │     ├─> Handles HTTP (port 80) and HTTPS (port 443) traffic
  │     ├─> Generates TLS certificates on-the-fly via CA
  │     ├─> Evaluates requests against policy rules
  │     └─> Logs all requests to database
  │
  └─> Metrics Server
        └─> Exposes Prometheus metrics on /metrics endpoint
```

### Critical Design Patterns

1. **Two-Stage Filtering**: DNS Server makes intercept/bypass decision first, then Proxy Server applies detailed policy rules on intercepted traffic.

2. **Policy Engine with OPA**: Both DNS and Proxy servers depend on the Policy Engine for device identification and policy decisions. The Policy Engine loads configuration from database into memory, then uses Open Policy Agent (OPA) for declarative policy evaluation. See "OPA Integration" section below for details.

3. **Database as Source of Truth**: All configuration (devices, profiles, rules, bypass rules) is stored in SQLite/BoltDB. Changes require modifying the database and calling `policyEngine.Reload()`.

4. **Dynamic TLS**: The CA component (`internal/ca/ca.go`) implements `GetCertificate` for the HTTPS server's TLS config, generating certificates on-demand with LRU cache.

5. **Usage Tracking**: Session-based tracking with inactivity timeout. Activity is recorded during policy evaluation, and usage stats are checked before allowing access to limited resources.

## Database Schema

The database uses SQLite with migration-based schema management. All tables defined in `internal/database/db.go`:

- **devices**: Device definitions with JSON identifiers array (IPs/MACs/CIDRs)
- **profiles**: Access profiles with default_allow flag
- **rules**: Domain/path-based allow/block rules with priority ordering
- **time_rules**: Time-of-day/day-of-week restrictions
- **usage_limits**: Daily time limits per category/domain with timer injection support
- **bypass_rules**: DNS-level bypass rules (never intercept these domains)
- **request_logs**: HTTP/HTTPS request logs
- **dns_logs**: DNS query logs
- **daily_usage**: Accumulated usage time per device/limit/date
- **usage_sessions**: Active usage tracking sessions

## Policy Evaluation Flow

**IMPORTANT**: Policy decisions are now made using Open Policy Agent (OPA) with Rego policies. The Go code prepares input data and calls OPA for decisions.

### DNS Level (policies/dns.rego)
1. Build input: client IP, domain, devices, bypass rules, global bypass
2. OPA evaluates `data.kproxy.dns.action`
3. Returns: BYPASS (forward to upstream), INTERCEPT (proxy), or BLOCK (0.0.0.0)
4. Logic:
   - Check global bypass patterns (e.g., `ocsp.*.com`)
   - Check device-specific bypass rules from database
   - Default: INTERCEPT

### Proxy Level (policies/proxy.rego)
1. Build input: request details, devices, profiles, time, usage stats
2. OPA evaluates `data.kproxy.proxy.decision`
3. Returns: PolicyDecision with action, reason, metadata
4. Logic flow in Rego:
   - Identify device by IP/MAC (policies/device.rego)
   - Check time restrictions (policies/time.rego)
   - Match rules by priority (domain/path matching in policies/helpers.rego)
   - For ALLOW rules: check usage limits (policies/usage.rego)
   - Fall back to profile's default_allow or global default_action

### Usage Limit Enforcement (policies/usage.rego)
- OPA checks if usage limits apply (by category or domain)
- Compares current usage against daily limits
- Returns limit_exceeded=true if over limit
- Go code records activity if limit not exceeded

## Configuration Management

Configuration is split between:
- **YAML file** (`configs/config.example.yaml`): Server settings, DNS, TLS, logging
- **SQLite database**: Dynamic policy configuration (devices, profiles, rules)

The YAML config is loaded once at startup via `internal/config/config.go` using Viper. Database-backed configuration is loaded by Policy Engine and can be reloaded without restart.

## Key Implementation Details

### Device Identification
- Primary: MAC address (if `use_mac_address: true`)
- Fallback: IP address or CIDR range
- Devices stored with JSON identifiers array: `["192.168.1.100", "aa:bb:cc:dd:ee:ff", "10.0.0.0/24"]`
- Policy Engine maintains two indexes: `devices` (by ID) and `devicesByMAC` (by MAC)

### Domain Matching (internal/policy/engine.go - matchDomain)
- Exact match
- Wildcard with regex conversion: `*.example.com`
- Suffix matching: `.example.com` matches `sub.example.com`
- Used for rules, bypass rules, and usage limit domains

### Certificate Generation
- Root CA and Intermediate CA loaded at startup
- Intermediate CA signs leaf certificates for intercepted domains
- Certificates cached in LRU cache (default 1000 entries, 24h TTL)
- Certificate validity configurable (default 24h)

### Metrics & Observability
All components emit Prometheus metrics via `internal/metrics/metrics.go`:
- `kproxy_dns_queries_total` - DNS queries by device/action
- `kproxy_requests_total` - HTTP/HTTPS requests by device/action
- `kproxy_blocked_requests_total` - Blocked requests by reason
- `kproxy_certificates_generated_total` - TLS certificate generation
- `kproxy_request_duration_seconds` - Request latency histogram

## OPA Integration

KProxy uses Open Policy Agent (OPA) as an embedded library for policy evaluation. Policy logic is written in declarative Rego language, not imperative Go.

### Architecture

```
Policy Engine (Go)
  ├─> Loads data from database (devices, profiles, rules)
  ├─> OPA Engine (internal/policy/opa/engine.go)
  │     ├─> Loads Rego policies from policy directory
  │     ├─> Compiles policies into prepared queries
  │     └─> Evaluates queries with input data
  └─> Builds JSON input & calls OPA for decisions
```

### Rego Policy Files (policies/ directory)

- **helpers.rego**: Utility functions
  - `match_domain(domain, pattern)` - Exact, wildcard, suffix matching
  - `match_path(path, rule_paths)` - Path prefix and glob matching
  - `within_time_window(current_time, time_rule)` - Time-of-day checks
  - `ip_in_cidr(ip, cidr)` - CIDR range matching

- **device.rego**: Device identification
  - `identified_device` - Returns device by MAC (priority) or IP/CIDR
  - `device_by_mac` - MAC address lookup
  - `device_by_ip` - IP/CIDR lookup

- **dns.rego**: DNS action decisions
  - `action` - Returns "BYPASS", "INTERCEPT", or "BLOCK"
  - Checks global bypass, device-specific bypass rules

- **time.rego**: Time-based access control
  - `allowed` - Check if current time within allowed windows
  - `allowed_for_rule(rule_id)` - Check for specific rule

- **usage.rego**: Usage limit evaluation
  - `applicable_limits` - Find limits matching request
  - `limit_exceeded(limit_id)` - Check if limit exceeded
  - `should_inject_timer` - Determine if timer overlay needed

- **proxy.rego**: Complete proxy request evaluation
  - `decision` - Main decision object with action, reason, metadata
  - Orchestrates device ID, time checks, rule matching, usage limits
  - Returns structured PolicyDecision

### Policy Input Format

DNS query input:
```json
{
  "client_ip": "192.168.1.100",
  "domain": "youtube.com",
  "global_bypass": ["ocsp.*.com", "*.apple.com"],
  "bypass_rules": [...],
  "devices": {...},
  "use_mac_address": true
}
```

Proxy request input:
```json
{
  "client_ip": "192.168.1.100",
  "client_mac": "aa:bb:cc:dd:ee:ff",
  "host": "youtube.com",
  "path": "/watch",
  "current_time": {"day_of_week": 2, "minutes": 540},
  "devices": {...},
  "profiles": {...},
  "usage_stats": {...},
  "default_action": "BLOCK"
}
```

### Working with OPA Policies

**Testing Rego policies:**
```bash
# Install OPA CLI
# Test a policy
opa test policies/ -v

# Evaluate a query interactively
opa eval -d policies/ -i input.json "data.kproxy.dns.action"
```

**Modifying policies:**
1. Edit .rego files in `policies/` directory
2. Restart KProxy or call reload (OPA reloads on restart)
3. OPA compilation errors will prevent startup

**Policy development workflow:**
1. Write Rego policy with test cases
2. Test with `opa test`
3. Deploy to policy directory (default: `/etc/kproxy/policies`)
4. Configure `policy.opa_policy_dir` in config.yaml if different location

### Configuration

KProxy supports loading policies from either **local filesystem** or **remote HTTP/HTTPS URLs**.

**Filesystem configuration** (default):
```yaml
policy:
  opa_policy_source: filesystem          # "filesystem" or "remote"
  opa_policy_dir: /etc/kproxy/policies   # Path to Rego policy files
  default_action: block                   # Fallback action
  use_mac_address: true                   # Prefer MAC for device ID
```

**Remote configuration** (centralized policy management):
```yaml
policy:
  opa_policy_source: remote              # "filesystem" or "remote"
  opa_policy_urls:                        # List of policy URLs
    - https://policy-server.example.com/policies/helpers.rego
    - https://policy-server.example.com/policies/device.rego
    - https://policy-server.example.com/policies/dns.rego
    - https://policy-server.example.com/policies/time.rego
    - https://policy-server.example.com/policies/usage.rego
    - https://policy-server.example.com/policies/proxy.rego
  opa_http_timeout: 30s                   # HTTP request timeout
  opa_http_retries: 3                     # Retry attempts on failure
  default_action: block
  use_mac_address: true
```

**Benefits of remote policies:**
- Centralized policy management across multiple KProxy instances
- Dynamic policy updates without filesystem access
- Version control and CI/CD integration
- Policies served from secure HTTPS endpoints

## Development Guidelines

### Adding New Policy Features
1. Add database migration to storage layer (BoltDB stores)
2. Add corresponding type to `internal/policy/types.go`
3. Add loader method to `internal/policy/engine.go`
4. **Update Rego policies** in `policies/` to incorporate new logic
5. Update `buildDNSInput()` or `buildProxyInput()` in `internal/policy/opa_integration.go` to include new data
6. Test with `opa test policies/` and integration tests
7. Update example config if needed

### Working with Database
- SQLite requires `CGO_ENABLED=1`
- Connection pool limited to 1 (SQLite limitation)
- All migrations in `getMigrations()` map, versioned sequentially
- Use transactions for multi-step changes

### Logging
- Structured logging with zerolog
- Each component gets logger with component name: `logger.With().Str("component", "dns").Logger()`
- Log levels: debug, info, warn, error
- JSON format for production, text format for development

### Testing
- Use `go test -v -race -cover ./...` for all tests
- Race detection enabled by default in make test
- Mock database and policy engine for unit tests

## Common Gotchas

1. **Policy Engine Reload**: After modifying database configuration, must call `policyEngine.Reload()` or restart service. For remote policies, reload will re-fetch from URLs.
2. **OPA Policy Changes**: Policy logic is now in Rego files. Modifying Go code in `engine.go` won't change policy behavior. Edit `.rego` files in the policies directory or update remote URLs instead.
3. **OPA Compilation Errors**: Invalid Rego syntax will prevent KProxy from starting. Test policies with `opa test` before deploying.
4. **Policy Source Configuration**:
   - **Filesystem mode**: Policies must be in directory specified by `policy.opa_policy_dir` (default: `/etc/kproxy/policies`). Development can use `./policies` with config override.
   - **Remote mode**: All policy URLs must be accessible at startup. Network failures will prevent KProxy from starting unless all retries succeed. Use HTTPS for production.
5. **Remote Policy Security**: When using remote policies:
   - Always use HTTPS in production to prevent MITM attacks
   - Implement proper authentication/authorization on policy server
   - Consider caching policies locally as backup
   - Monitor policy fetch failures in logs
6. **HTTP Retry Logic**: Remote policy fetches use exponential backoff (2s, 4s, 8s, 16s). Default 3 retries. Configure with `policy.opa_http_retries`.
7. **CGO Requirement**: Building requires `CGO_ENABLED=1` for BoltDB (and previously SQLite)
8. **Port Permissions**: DNS (53), HTTP (80), HTTPS (443) require root/CAP_NET_BIND_SERVICE
9. **CA Certificate Trust**: Clients must trust root CA for HTTPS interception to work
10. **Session Timeout**: Usage tracking sessions expire after inactivity_timeout (default 2 minutes)
11. **Global Bypass**: Critical domains (OCSP, CRL) must be in global_bypass to prevent certificate validation failures
