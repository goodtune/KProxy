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

2. **Policy Engine is Central**: Both DNS and Proxy servers depend on the Policy Engine for device identification and policy decisions. The Policy Engine loads all configuration from database into memory on startup and provides thread-safe access via RWMutex.

3. **Database as Source of Truth**: All configuration (devices, profiles, rules, bypass rules) is stored in SQLite. Changes require modifying the database and calling `policyEngine.Reload()`.

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

Understanding policy evaluation is essential for working with rules:

### DNS Level (internal/dns/server.go)
1. Identify device by client IP
2. Check global bypass patterns (e.g., `ocsp.*.com`)
3. Check device-specific bypass rules from database
4. Default: INTERCEPT (return proxy IP)

### Proxy Level (internal/policy/engine.go - Evaluate method)
1. Identify device by IP/MAC
2. Check time-of-access rules (if device has time restrictions)
3. Iterate rules by priority (descending)
4. For matching ALLOW rules: check usage limits before allowing
5. Fall back to profile's default_allow or global default_action

### Usage Limit Enforcement
- When a rule allows access and has a category, check if any usage_limits apply
- Usage limits can match by category or specific domains
- If limit exceeded: block with "usage_limit" block page
- If within limit: record activity and optionally inject timer (if inject_timer=1)

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

## Development Guidelines

### Adding New Policy Features
1. Add database migration to `internal/database/db.go`
2. Add corresponding type to `internal/policy/types.go`
3. Add loader method to `internal/policy/engine.go`
4. Update `Evaluate()` method to incorporate new policy logic
5. Update example config if needed

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

1. **Policy Engine Reload**: After modifying database configuration, must call `policyEngine.Reload()` or restart service
2. **CGO Requirement**: Building requires `CGO_ENABLED=1` due to modernc.org/sqlite
3. **Port Permissions**: DNS (53), HTTP (80), HTTPS (443) require root/CAP_NET_BIND_SERVICE
4. **CA Certificate Trust**: Clients must trust root CA for HTTPS interception to work
5. **Session Timeout**: Usage tracking sessions expire after inactivity_timeout (default 2 minutes)
6. **Global Bypass**: Critical domains (OCSP, CRL) must be in global_bypass to prevent certificate validation failures
