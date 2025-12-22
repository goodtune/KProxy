# KProxy Technical Plan

## Executive Summary

**KProxy** (Kids Proxy) is a transparent HTTP/HTTPS interception proxy designed for home networks to provide parental controls. It intercepts all web traffic, dynamically generates TLS certificates for HTTPS decryption, enforces per-device/per-child access rules (domain allowlists/denylists, path-level filtering, time-of-access rules, and usage limits), logs all requests, and can inject time-remaining overlays via Server-Sent Events for sites with time limits.

**Repository:** `github.com/goodtune/kproxy`

-----

## 1. Architecture Overview

### 1.1 High-Level Components

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Home Network                                    │
│                                                                              │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐                                │
│  │ Child A  │   │ Child B  │   │ Child C  │   (DNS set to KProxy IP)       │
│  │  Device  │   │  Device  │   │  Device  │                                │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘                                │
│       │              │              │                                       │
│       └──────────────┼──────────────┘                                       │
│                      │                                                       │
│                      ▼                                                       │
│         ┌────────────────────────────────────────┐                          │
│         │            KProxy Service              │                          │
│         │  ┌────────────────────────────────┐   │                          │
│         │  │   Embedded DNS Server          │   │  Port 53 (UDP/TCP)       │
│         │  │   • Intercept → Return proxy IP│   │                          │
│         │  │   • Bypass → Forward upstream  │   │                          │
│         │  │   • Low TTL (60s default)      │   │                          │
│         │  └────────────────────────────────┘   │                          │
│         │  ┌────────────────────────────────┐   │                          │
│         │  │   TLS Termination / MITM       │   │  Port 443 (HTTPS)        │
│         │  │   (Dynamic Cert Generation)    │   │  Port 80  (HTTP)         │
│         │  └────────────────────────────────┘   │                          │
│         │  ┌────────────────────────────────┐   │                          │
│         │  │   Policy Engine                │   │                          │
│         │  │   • Device identification      │   │                          │
│         │  │   • Domain/Path filtering      │   │                          │
│         │  │   • Bypass domain list         │   │                          │
│         │  │   • Time-of-access rules       │   │                          │
│         │  │   • Usage tracking             │   │                          │
│         │  └────────────────────────────────┘   │                          │
│         │  ┌────────────────────────────────┐   │                          │
│         │  │   Response Modifier            │   │                          │
│         │  │   • Time overlay injection     │   │                          │
│         │  │   • SSE endpoint for countdown │   │                          │
│         │  └────────────────────────────────┘   │                          │
│         │  ┌────────────────────────────────┐   │                          │
│         │  │   Request Logger               │   │                          │
│         │  │   • All HTTP requests logged   │   │                          │
│         │  │   • All DNS queries logged     │   │                          │
│         │  │   • Prometheus metrics         │   │                          │
│         │  └────────────────────────────────┘   │                          │
│         │  ┌────────────────────────────────┐   │                          │
│         │  │   Admin Web UI                 │   │  Port 8443 (Admin HTTPS) │
│         │  │   • Monitoring dashboard       │   │  Port 9090 (Metrics)     │
│         │  │   • Configuration management   │   │                          │
│         │  └────────────────────────────────┘   │                          │
│         └────────────────────────────────────────┘                          │
│                      │                                                       │
│                      ▼                                                       │
│         ┌────────────────────────────────────────┐                          │
│         │   step-ca (Embedded or External)      │                          │
│         │   • Root CA management                │                          │
│         │   • On-demand cert signing            │                          │
│         └────────────────────────────────────────┘                          │
│                      │                                                       │
└──────────────────────┼───────────────────────────────────────────────────────┘
                       │
                       ▼
              ┌────────────────┐
              │   Internet     │
              │   (+ Upstream  │
              │    DNS Server) │
              └────────────────┘
```

### 1.2 Component Responsibilities

|Component            |Responsibility                                                                                 |
|---------------------|-----------------------------------------------------------------------------------------------|
|**DNS Server**       |Resolves queries, returns proxy IP for intercepted domains, forwards bypass domains to upstream|
|**TLS Terminator**   |Accepts HTTPS connections, generates per-domain certificates using CA, decrypts traffic        |
|**HTTP Handler**     |Handles plain HTTP requests on port 80                                                         |
|**Policy Engine**    |Evaluates requests against rules, determines allow/block/time-limit/bypass                     |
|**Response Modifier**|Injects time-remaining overlay JavaScript/CSS when needed                                      |
|**SSE Server**       |Provides real-time countdown updates to injected overlays                                      |
|**Request Logger**   |Logs all requests and DNS queries to structured storage with metadata                          |
|**Metrics Exporter** |Exposes Prometheus metrics on dedicated port                                                   |
|**Admin UI Server**  |Serves web interface for monitoring and configuration                                          |
|**CA Integration**   |Manages certificate generation via step-ca library or external daemon                          |

-----

## 2. Technical Specifications

### 2.1 Technology Stack

|Layer              |Technology                                           |Rationale                                           |
|-------------------|-----------------------------------------------------|----------------------------------------------------|
|**Language**       |Go 1.22+                                             |Cross-platform, excellent concurrency, strong stdlib|
|**HTTP Framework** |`net/http` + `github.com/gorilla/mux`                |Standard library + flexible routing                 |
|**TLS/Certificate**|`crypto/tls`, `crypto/x509`, `smallstep/certificates`|Native Go crypto + step-ca integration              |
|**Database**       |SQLite (embedded) via `modernc.org/sqlite`           |Pure Go, zero dependencies, portable                |
|**Configuration**  |YAML + Environment Variables                         |Human-readable, 12-factor friendly                  |
|**Metrics**        |`prometheus/client_golang`                           |Industry standard observability                     |
|**Admin UI**       |Embedded SPA (React/Preact)                          |Single binary deployment                            |
|**Logging**        |`zerolog` or `slog` (Go 1.21+)                       |Structured, high-performance logging                |

### 2.2 Port Allocation

|Port|Protocol|Purpose                                        |
|----|--------|-----------------------------------------------|
|53  |UDP/TCP |DNS server (primary client configuration point)|
|80  |HTTP    |Proxy HTTP traffic                             |
|443 |HTTPS   |Proxy HTTPS traffic (TLS termination)          |
|8443|HTTPS   |Admin web interface                            |
|9090|HTTP    |Prometheus metrics endpoint                    |

-----

## 3. Certificate Authority Integration

### 3.1 Approach: Embed step-ca as a Library

The `smallstep/certificates` project provides Go packages that can be embedded directly. This avoids running a separate daemon.

**Key packages:**

- `github.com/smallstep/certificates/authority` - Core CA functionality
- `github.com/smallstep/certificates/ca` - Client library for CA operations
- `github.com/smallstep/crypto` - Cryptographic primitives

### 3.2 Certificate Generation Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Certificate Generation Flow                           │
│                                                                          │
│  1. Client initiates TLS handshake to proxy (SNI: example.com)          │
│                         │                                                │
│                         ▼                                                │
│  2. Proxy extracts SNI hostname                                         │
│                         │                                                │
│                         ▼                                                │
│  3. Check certificate cache for example.com                              │
│                         │                                                │
│            ┌────────────┴────────────┐                                  │
│            │                         │                                   │
│         [Cache Hit]             [Cache Miss]                            │
│            │                         │                                   │
│            │                         ▼                                   │
│            │           4. Generate new key pair (ECDSA P-256)           │
│            │                         │                                   │
│            │                         ▼                                   │
│            │           5. Create CSR for hostname                        │
│            │                         │                                   │
│            │                         ▼                                   │
│            │           6. Sign with Intermediate CA                      │
│            │                         │                                   │
│            │                         ▼                                   │
│            │           7. Cache certificate (TTL: 24h)                   │
│            │                         │                                   │
│            └─────────────┬───────────┘                                  │
│                          ▼                                               │
│  8. Complete TLS handshake with generated/cached certificate            │
│                          │                                               │
│                          ▼                                               │
│  9. Proxy decrypts, inspects, and forwards request                      │
└──────────────────────────────────────────────────────────────────────────┘
```

### 3.3 CA Initialization

```go
// Pseudocode for CA setup
type CertificateAuthority struct {
    rootCert     *x509.Certificate
    rootKey      crypto.PrivateKey
    intermCert   *x509.Certificate
    intermKey    crypto.PrivateKey
    certCache    *lru.Cache[string, *tls.Certificate]
    cacheTTL     time.Duration
}

func (ca *CertificateAuthority) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
    hostname := hello.ServerName
    
    // Check cache
    if cert, ok := ca.certCache.Get(hostname); ok {
        return cert, nil
    }
    
    // Generate new certificate
    cert, err := ca.generateCertificate(hostname)
    if err != nil {
        return nil, err
    }
    
    // Cache with TTL
    ca.certCache.Set(hostname, cert, ca.cacheTTL)
    return cert, nil
}
```

### 3.4 Root CA Trust Distribution

For TLS interception to work, client devices must trust the KProxy root CA:

1. **Initial Setup:** Admin UI provides downloadable root certificate
1. **Client Installation:**
- Windows: `certutil -addstore -user Root kproxy-ca.crt`
- macOS: `security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain kproxy-ca.crt`
- Linux: Copy to `/usr/local/share/ca-certificates/` and run `update-ca-certificates`
- iOS/Android: Install via profile/system settings

-----

## 4. Embedded DNS Server

### 4.1 Overview

The embedded DNS server simplifies deployment by eliminating external DNS configuration. Clients only need to point their DNS settings to the KProxy IP address. The DNS server intelligently routes queries:

- **Intercept Mode:** Returns the proxy’s IP address, routing traffic through KProxy
- **Bypass Mode:** Forwards query to upstream DNS and returns the real IP address

This allows certain domains (banking, OS updates, etc.) to bypass the proxy entirely while still logging all DNS activity.

### 4.2 DNS Resolution Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DNS Resolution Flow                                  │
│                                                                              │
│  1. Client queries: "example.com A?"                                        │
│                         │                                                    │
│                         ▼                                                    │
│  2. KProxy DNS Server receives query                                        │
│                         │                                                    │
│                         ▼                                                    │
│  3. Identify client device (by source IP)                                   │
│                         │                                                    │
│                         ▼                                                    │
│  4. Check bypass rules for domain                                           │
│                         │                                                    │
│            ┌────────────┴────────────┐                                      │
│            │                         │                                       │
│      [Bypass Match]           [No Bypass / Intercept]                       │
│            │                         │                                       │
│            ▼                         ▼                                       │
│  5a. Forward query to          5b. Return proxy IP                          │
│      upstream DNS                   (e.g., 192.168.1.100)                   │
│            │                         │                                       │
│            ▼                         │                                       │
│  6a. Return real IP with             │                                       │
│      original TTL (or capped)        │                                       │
│            │                         │                                       │
│            └─────────────┬───────────┘                                      │
│                          ▼                                                   │
│  7. Log DNS query (domain, client, action, response)                        │
│                          │                                                   │
│                          ▼                                                   │
│  8. Return response to client with configured TTL                           │
│     (default 60s for intercepted, preserve/cap for bypass)                  │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 Implementation Using miekg/dns

The `github.com/miekg/dns` library is the de facto standard for DNS in Go.

```go
package dns

import (
    "context"
    "net"
    "strings"
    "time"
    
    "github.com/miekg/dns"
)

type DNSServer struct {
    proxyIP        net.IP           // IP to return for intercepted domains
    upstreamDNS    []string         // Upstream DNS servers (e.g., ["8.8.8.8:53", "1.1.1.1:53"])
    policyEngine   *PolicyEngine
    logger         *DNSLogger
    
    // TTL settings
    interceptTTL   uint32           // TTL for intercepted responses (default: 60)
    bypassTTLCap   uint32           // Max TTL for bypass responses (0 = no cap)
    
    // DNS client for upstream queries
    client         *dns.Client
}

type DNSConfig struct {
    ListenAddr     string        `yaml:"listen_addr"`      // ":53"
    ProxyIP        string        `yaml:"proxy_ip"`         // IP to return for intercepted domains
    UpstreamDNS    []string      `yaml:"upstream_dns"`     // ["8.8.8.8:53", "1.1.1.1:53"]
    InterceptTTL   uint32        `yaml:"intercept_ttl"`    // Default: 60
    BypassTTLCap   uint32        `yaml:"bypass_ttl_cap"`   // Default: 300 (0 = no cap)
    EnableTCP      bool          `yaml:"enable_tcp"`       // Default: true
    EnableUDP      bool          `yaml:"enable_udp"`       // Default: true
    Timeout        time.Duration `yaml:"timeout"`          // Default: 5s
}

func NewDNSServer(config DNSConfig, policy *PolicyEngine, logger *DNSLogger) *DNSServer {
    return &DNSServer{
        proxyIP:      net.ParseIP(config.ProxyIP),
        upstreamDNS:  config.UpstreamDNS,
        policyEngine: policy,
        logger:       logger,
        interceptTTL: config.InterceptTTL,
        bypassTTLCap: config.BypassTTLCap,
        client: &dns.Client{
            Timeout: config.Timeout,
        },
    }
}

func (s *DNSServer) Start(addr string, enableUDP, enableTCP bool) error {
    dns.HandleFunc(".", s.handleDNSRequest)
    
    errChan := make(chan error, 2)
    
    if enableUDP {
        udpServer := &dns.Server{Addr: addr, Net: "udp"}
        go func() {
            if err := udpServer.ListenAndServe(); err != nil {
                errChan <- err
            }
        }()
    }
    
    if enableTCP {
        tcpServer := &dns.Server{Addr: addr, Net: "tcp"}
        go func() {
            if err := tcpServer.ListenAndServe(); err != nil {
                errChan <- err
            }
        }()
    }
    
    // Return first error or nil
    select {
    case err := <-errChan:
        return err
    case <-time.After(100 * time.Millisecond):
        return nil
    }
}

func (s *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
    msg := new(dns.Msg)
    msg.SetReply(r)
    msg.Authoritative = true
    
    // Get client IP for device identification
    clientIP := s.extractClientIP(w.RemoteAddr())
    
    for _, question := range r.Question {
        domain := strings.TrimSuffix(question.Name, ".")
        qtype := question.Qtype
        
        // Determine action based on policy
        action := s.policyEngine.GetDNSAction(clientIP, domain)
        
        var response dns.RR
        var logAction string
        
        switch action {
        case DNSActionIntercept:
            // Return proxy IP
            response = s.createInterceptResponse(question, domain)
            logAction = "INTERCEPT"
            
        case DNSActionBypass:
            // Forward to upstream and return real response
            upstreamResp, err := s.forwardToUpstream(r)
            if err != nil {
                // On error, fall back to intercept
                response = s.createInterceptResponse(question, domain)
                logAction = "INTERCEPT_FALLBACK"
            } else {
                // Copy answers from upstream, potentially cap TTL
                for _, ans := range upstreamResp.Answer {
                    if s.bypassTTLCap > 0 && ans.Header().Ttl > s.bypassTTLCap {
                        ans.Header().Ttl = s.bypassTTLCap
                    }
                    msg.Answer = append(msg.Answer, ans)
                }
                logAction = "BYPASS"
            }
            
        case DNSActionBlock:
            // Return NXDOMAIN or 0.0.0.0
            response = s.createBlockResponse(question, domain)
            logAction = "BLOCK"
        }
        
        if response != nil {
            msg.Answer = append(msg.Answer, response)
        }
        
        // Log the DNS query
        s.logger.LogDNS(&DNSLogEntry{
            Timestamp:  time.Now(),
            ClientIP:   clientIP.String(),
            Domain:     domain,
            QueryType:  dns.TypeToString[qtype],
            Action:     logAction,
            ResponseIP: s.getResponseIP(msg),
        })
    }
    
    w.WriteMsg(msg)
}

func (s *DNSServer) createInterceptResponse(q dns.Question, domain string) dns.RR {
    switch q.Qtype {
    case dns.TypeA:
        return &dns.A{
            Hdr: dns.RR_Header{
                Name:   q.Name,
                Rrtype: dns.TypeA,
                Class:  dns.ClassINET,
                Ttl:    s.interceptTTL,
            },
            A: s.proxyIP.To4(),
        }
    case dns.TypeAAAA:
        // Return empty or proxy IPv6 if available
        // For now, return no AAAA to force IPv4
        return nil
    default:
        return nil
    }
}

func (s *DNSServer) createBlockResponse(q dns.Question, domain string) dns.RR {
    // Return 0.0.0.0 for blocked domains (sinkhole)
    if q.Qtype == dns.TypeA {
        return &dns.A{
            Hdr: dns.RR_Header{
                Name:   q.Name,
                Rrtype: dns.TypeA,
                Class:  dns.ClassINET,
                Ttl:    s.interceptTTL,
            },
            A: net.ParseIP("0.0.0.0").To4(),
        }
    }
    return nil
}

func (s *DNSServer) forwardToUpstream(r *dns.Msg) (*dns.Msg, error) {
    // Try each upstream DNS server
    for _, upstream := range s.upstreamDNS {
        resp, _, err := s.client.Exchange(r, upstream)
        if err == nil {
            return resp, nil
        }
    }
    return nil, fmt.Errorf("all upstream DNS servers failed")
}

func (s *DNSServer) extractClientIP(addr net.Addr) net.IP {
    switch a := addr.(type) {
    case *net.UDPAddr:
        return a.IP
    case *net.TCPAddr:
        return a.IP
    default:
        return nil
    }
}

func (s *DNSServer) getResponseIP(msg *dns.Msg) string {
    for _, ans := range msg.Answer {
        if a, ok := ans.(*dns.A); ok {
            return a.A.String()
        }
    }
    return ""
}
```

### 4.4 DNS Actions

The policy engine determines the DNS action for each query:

```go
type DNSAction int

const (
    DNSActionIntercept DNSAction = iota  // Return proxy IP, route through KProxy
    DNSActionBypass                       // Forward to upstream, return real IP
    DNSActionBlock                        // Return 0.0.0.0 / NXDOMAIN
)

// BypassRule defines domains that should bypass the proxy
type BypassRule struct {
    ID          string   `json:"id"`
    Domain      string   `json:"domain"`       // "bank.example.com", "*.apple.com"
    Reason      string   `json:"reason"`       // "Banking", "OS Updates"
    Enabled     bool     `json:"enabled"`
    DeviceIDs   []string `json:"device_ids"`   // Empty = all devices
}

func (pe *PolicyEngine) GetDNSAction(clientIP net.IP, domain string) DNSAction {
    device := pe.identifyDevice(clientIP, nil)
    
    // 1. Check global bypass list (system-critical domains)
    if pe.isGlobalBypass(domain) {
        return DNSActionBypass
    }
    
    // 2. Check device-specific bypass rules
    if device != nil {
        for _, rule := range pe.bypassRules {
            if !rule.Enabled {
                continue
            }
            if len(rule.DeviceIDs) > 0 && !contains(rule.DeviceIDs, device.ID) {
                continue
            }
            if pe.matchDomain(domain, rule.Domain) {
                return DNSActionBypass
            }
        }
    }
    
    // 3. Check if domain is completely blocked at DNS level
    //    (optional: some domains can be blocked before HTTP)
    if pe.isDNSBlocked(device, domain) {
        return DNSActionBlock
    }
    
    // 4. Default: intercept and route through proxy
    return DNSActionIntercept
}

// Global bypass list - domains that should NEVER go through proxy
var globalBypassDomains = []string{
    // Certificate validation (OCSP, CRL)
    "ocsp.*.com",
    "crl.*.com",
    "*.ocsp.*.com",
    
    // OS updates (optional, configurable)
    // "*.apple.com",
    // "*.windowsupdate.com",
    
    // KProxy admin domain itself
    // (set dynamically based on config)
}
```

### 4.5 DNS Logging

All DNS queries are logged for visibility:

```go
type DNSLogEntry struct {
    ID          int64     `db:"id"`
    Timestamp   time.Time `db:"timestamp"`
    ClientIP    string    `db:"client_ip"`
    DeviceID    string    `db:"device_id"`
    DeviceName  string    `db:"device_name"`
    Domain      string    `db:"domain"`
    QueryType   string    `db:"query_type"`   // A, AAAA, CNAME, etc.
    Action      string    `db:"action"`       // INTERCEPT, BYPASS, BLOCK
    ResponseIP  string    `db:"response_ip"`
    Upstream    string    `db:"upstream"`     // Which upstream DNS was used (for bypass)
    Latency     int64     `db:"latency_ms"`
}

// SQL Schema addition
const dnsLogSchema = `
CREATE TABLE IF NOT EXISTS dns_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client_ip TEXT NOT NULL,
    device_id TEXT,
    device_name TEXT,
    domain TEXT NOT NULL,
    query_type TEXT NOT NULL,
    action TEXT NOT NULL,
    response_ip TEXT,
    upstream TEXT,
    latency_ms INTEGER
);

CREATE INDEX idx_dns_timestamp ON dns_logs(timestamp);
CREATE INDEX idx_dns_device ON dns_logs(device_id, timestamp);
CREATE INDEX idx_dns_domain ON dns_logs(domain, timestamp);
CREATE INDEX idx_dns_action ON dns_logs(action, timestamp);
`
```

### 4.6 TTL Strategy

Low TTL enables near-real-time configuration changes:

|Scenario               |TTL                              |Rationale                       |
|-----------------------|---------------------------------|--------------------------------|
|**Intercepted domains**|60s (configurable)               |Allows quick policy changes     |
|**Bypassed domains**   |Original or capped (300s default)|Respect upstream but limit cache|
|**Blocked domains**    |60s                              |Quick recovery if unblocked     |
|**Admin domain**       |60s                              |Ensure accessibility            |

```yaml
# Configuration options
dns:
  intercept_ttl: 60      # TTL for domains routed through proxy
  bypass_ttl_cap: 300    # Max TTL for bypassed domains (0 = no cap)
  block_ttl: 60          # TTL for blocked domains
```

### 4.7 Bypass Configuration Examples

```yaml
# Common bypass configurations
bypass_rules:
  # Banking - never intercept financial sites
  - id: "bypass-banking"
    domain: "*.bankofamerica.com"
    reason: "Banking"
    enabled: true
    
  - id: "bypass-chase"
    domain: "*.chase.com"
    reason: "Banking"
    enabled: true

  # Certificate validation - MUST bypass for TLS to work
  - id: "bypass-ocsp"
    domain: "ocsp.*"
    reason: "Certificate validation"
    enabled: true

  # Apple services (optional)
  - id: "bypass-apple"
    domain: "*.apple.com"
    reason: "OS Updates"
    enabled: true
    device_ids: []  # All devices

  # Gaming consoles might need bypass
  - id: "bypass-xbox"
    domain: "*.xboxlive.com"
    reason: "Xbox Live"
    enabled: true
    device_ids: ["device-xbox"]  # Only Xbox device

  # VPN/Security software
  - id: "bypass-vpn"
    domain: "*.nordvpn.com"
    reason: "VPN Service"
    enabled: false  # Disabled by default
```

### 4.8 DNS-Level Blocking (Optional)

For domains that should be completely inaccessible (not even reach the proxy):

```go
// DNS-level blocks - faster than HTTP-level, but less informative
type DNSBlockRule struct {
    ID       string `json:"id"`
    Domain   string `json:"domain"`
    Reason   string `json:"reason"`
    Enabled  bool   `json:"enabled"`
}

// Returns 0.0.0.0 / NXDOMAIN at DNS level
// User sees "site cannot be reached" instead of block page
// Use sparingly - HTTP-level blocking is more user-friendly
```

### 4.9 Client Configuration

With embedded DNS, client setup is simple:

**Manual Configuration:**

1. Set DNS server to KProxy IP (e.g., `192.168.1.100`)
1. Install root CA certificate
1. Done!

**Via DHCP (Router Configuration):**

1. Configure router DHCP to push KProxy IP as DNS server
1. All devices automatically use KProxy for DNS
1. Only managed devices need CA certificate installed

**Per-Device Override:**

- Devices can be configured individually in their network settings
- Useful when router DHCP cannot be modified

-----

## 5. Policy Engine Design

### 5.1 Data Model

```go
// Device represents a monitored device (child's computer/phone)
type Device struct {
    ID          string    `json:"id"`
    Name        string    `json:"name"`        // "Child A's Laptop"
    Identifiers []string  `json:"identifiers"` // MAC addresses, IP ranges
    ProfileID   string    `json:"profile_id"`  // Link to access profile
    Active      bool      `json:"active"`
    CreatedAt   time.Time `json:"created_at"`
    UpdatedAt   time.Time `json:"updated_at"`
}

// Profile contains access rules for a device or group
type Profile struct {
    ID          string        `json:"id"`
    Name        string        `json:"name"`         // "Child A Rules"
    Rules       []Rule        `json:"rules"`
    DefaultAllow bool         `json:"default_allow"` // Allowlist or denylist mode
    TimeRules   []TimeRule    `json:"time_rules"`
    UsageLimits []UsageLimit  `json:"usage_limits"`
    CreatedAt   time.Time     `json:"created_at"`
    UpdatedAt   time.Time     `json:"updated_at"`
}

// Rule defines domain/path filtering
type Rule struct {
    ID          string   `json:"id"`
    Domain      string   `json:"domain"`       // "youtube.com", "*.google.com"
    Paths       []string `json:"paths"`        // ["/watch", "/shorts"] or ["*"]
    Action      Action   `json:"action"`       // ALLOW, BLOCK
    Priority    int      `json:"priority"`     // Higher = evaluated first
    Category    string   `json:"category"`     // "social", "gaming", "homework"
    InjectTimer bool     `json:"inject_timer"` // Show time remaining overlay
}

type Action string
const (
    ActionAllow Action = "ALLOW"
    ActionBlock Action = "BLOCK"
)

// TimeRule restricts access by time of day
type TimeRule struct {
    ID        string    `json:"id"`
    DaysOfWeek []int    `json:"days_of_week"` // 0=Sunday, 6=Saturday
    StartTime  string   `json:"start_time"`   // "08:00"
    EndTime    string   `json:"end_time"`     // "21:00"
    RuleIDs    []string `json:"rule_ids"`     // Rules this applies to, empty = all
}

// UsageLimit tracks time spent on specific categories/domains
type UsageLimit struct {
    ID            string        `json:"id"`
    Category      string        `json:"category"`      // "gaming", "social"
    Domains       []string      `json:"domains"`       // Specific domains if not using category
    DailyMinutes  int           `json:"daily_minutes"` // 0 = unlimited
    ResetTime     string        `json:"reset_time"`    // "00:00" local time
    InjectTimer   bool          `json:"inject_timer"`  // Show countdown overlay
}

// UsageSession tracks active usage for time limits
type UsageSession struct {
    DeviceID    string
    LimitID     string
    StartedAt   time.Time
    LastActivity time.Time
    AccumulatedSeconds int64
}
```

### 5.2 Policy Evaluation Algorithm

```go
func (pe *PolicyEngine) Evaluate(req *ProxyRequest) *PolicyDecision {
    device := pe.identifyDevice(req.ClientIP, req.ClientMAC)
    if device == nil {
        return &PolicyDecision{Action: pe.defaultAction, Reason: "unknown device"}
    }
    
    profile := pe.getProfile(device.ProfileID)
    
    // 1. Check time-of-access rules
    if !pe.isWithinAllowedTime(profile, time.Now()) {
        return &PolicyDecision{
            Action: ActionBlock,
            Reason: "outside allowed hours",
            BlockPage: "time_restriction",
        }
    }
    
    // 2. Evaluate domain/path rules (priority order)
    rules := pe.sortByPriority(profile.Rules)
    for _, rule := range rules {
        if pe.matchesRule(req.Host, req.Path, rule) {
            // 3. Check usage limits if applicable
            if rule.Action == ActionAllow {
                limitDecision := pe.checkUsageLimits(device, profile, req)
                if limitDecision != nil {
                    return limitDecision
                }
            }
            
            return &PolicyDecision{
                Action:      rule.Action,
                Reason:      fmt.Sprintf("matched rule: %s", rule.ID),
                InjectTimer: rule.InjectTimer,
                Rule:        &rule,
            }
        }
    }
    
    // 4. Apply default action
    if profile.DefaultAllow {
        return &PolicyDecision{Action: ActionAllow, Reason: "default allow"}
    }
    return &PolicyDecision{Action: ActionBlock, Reason: "default deny"}
}

func (pe *PolicyEngine) matchesRule(host, path string, rule Rule) bool {
    // Domain matching with wildcard support
    if !pe.matchDomain(host, rule.Domain) {
        return false
    }
    
    // Path matching
    if len(rule.Paths) == 0 || contains(rule.Paths, "*") {
        return true
    }
    
    for _, rulePath := range rule.Paths {
        if strings.HasPrefix(path, rulePath) {
            return true
        }
    }
    return false
}
```

### 5.3 Device Identification

Devices are identified by:

1. **IP Address** - Primary identifier (requires static DHCP or reservations)
1. **MAC Address** - More reliable but requires ARP lookup
1. **HTTP Headers** - User-Agent fingerprinting (supplementary)

```go
func (pe *PolicyEngine) identifyDevice(clientIP net.IP, clientMAC net.HardwareAddr) *Device {
    // Try MAC address first (most reliable)
    if clientMAC != nil {
        if device := pe.devicesByMAC[clientMAC.String()]; device != nil {
            return device
        }
    }
    
    // Fall back to IP address
    for _, device := range pe.devices {
        for _, identifier := range device.Identifiers {
            if ipRange, err := netip.ParsePrefix(identifier); err == nil {
                if ipRange.Contains(netip.MustParseAddr(clientIP.String())) {
                    return device
                }
            }
            if identifier == clientIP.String() {
                return device
            }
        }
    }
    
    return nil
}
```

-----

## 6. Usage Tracking & Time Limits

### 6.1 Heuristic for “Active Time”

Simple page load count doesn’t reflect actual usage. The system tracks **active time** using:

1. **Request Activity:** Each HTTP request for a domain resets an inactivity timer
1. **Inactivity Threshold:** If no requests for 2 minutes, assume user stopped using the site
1. **Session-Based Tracking:** Group activity into sessions

```go
const (
    InactivityTimeout = 2 * time.Minute
    MinSessionDuration = 10 * time.Second
)

type UsageTracker struct {
    sessions map[string]*UsageSession // key: deviceID:limitID
    mu       sync.RWMutex
}

func (ut *UsageTracker) RecordActivity(deviceID, limitID string) *UsageSession {
    ut.mu.Lock()
    defer ut.mu.Unlock()
    
    key := deviceID + ":" + limitID
    session, exists := ut.sessions[key]
    
    now := time.Now()
    
    if !exists || now.Sub(session.LastActivity) > InactivityTimeout {
        // Start new session
        session = &UsageSession{
            DeviceID:    deviceID,
            LimitID:     limitID,
            StartedAt:   now,
            LastActivity: now,
        }
        ut.sessions[key] = session
    } else {
        // Continue existing session
        elapsed := now.Sub(session.LastActivity)
        if elapsed < InactivityTimeout {
            session.AccumulatedSeconds += int64(elapsed.Seconds())
        }
        session.LastActivity = now
    }
    
    return session
}

func (ut *UsageTracker) GetTodayUsage(deviceID, limitID string, resetTime string) time.Duration {
    // Query database for today's accumulated usage
    // Sum all sessions since last reset time
    // ...
}
```

### 6.2 Time Limit Enforcement

```go
func (pe *PolicyEngine) checkUsageLimits(device *Device, profile *Profile, req *ProxyRequest) *PolicyDecision {
    for _, limit := range profile.UsageLimits {
        if !pe.limitApplies(limit, req.Host) {
            continue
        }
        
        todayUsage := pe.usageTracker.GetTodayUsage(device.ID, limit.ID, limit.ResetTime)
        limitDuration := time.Duration(limit.DailyMinutes) * time.Minute
        
        if todayUsage >= limitDuration {
            return &PolicyDecision{
                Action:    ActionBlock,
                Reason:    fmt.Sprintf("daily limit exceeded: %v/%v", todayUsage, limitDuration),
                BlockPage: "usage_limit",
            }
        }
        
        // Record this activity
        session := pe.usageTracker.RecordActivity(device.ID, limit.ID)
        
        remaining := limitDuration - todayUsage
        return &PolicyDecision{
            Action:        ActionAllow,
            InjectTimer:   limit.InjectTimer,
            TimeRemaining: remaining,
            Session:       session,
        }
    }
    return nil
}
```

-----

## 7. Response Modification & Time Overlay

### 7.1 Injection Strategy

For sites with time limits and `InjectTimer: true`, inject a small overlay showing time remaining:

1. **Detect HTML responses:** Check `Content-Type: text/html`
1. **Buffer response body:** Read entire response into memory (for modest traffic, acceptable)
1. **Inject before `</body>`:** Add overlay HTML/CSS/JS
1. **Modify Content-Length:** Recalculate header

### 7.2 Overlay Implementation

```html
<!-- Injected before </body> -->
<div id="kproxy-overlay" style="
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: rgba(0,0,0,0.8);
    color: white;
    padding: 10px 15px;
    border-radius: 8px;
    font-family: -apple-system, BlinkMacSystemFont, sans-serif;
    font-size: 14px;
    z-index: 2147483647;
    box-shadow: 0 2px 10px rgba(0,0,0,0.3);
">
    <div>Time remaining: <span id="kproxy-time">--:--</span></div>
</div>
<script>
(function() {
    var timeEl = document.getElementById('kproxy-time');
    var overlay = document.getElementById('kproxy-overlay');
    var remaining = {{.TimeRemainingSeconds}};
    
    function formatTime(secs) {
        var m = Math.floor(secs / 60);
        var s = secs % 60;
        return m + ':' + (s < 10 ? '0' : '') + s;
    }
    
    function updateDisplay() {
        if (remaining <= 0) {
            overlay.style.background = 'rgba(200,0,0,0.9)';
            timeEl.textContent = 'Time expired';
            return;
        }
        timeEl.textContent = formatTime(remaining);
        if (remaining <= 60) {
            overlay.style.background = 'rgba(200,100,0,0.9)';
        }
    }
    
    // SSE connection for real-time updates
    var sessionId = '{{.SessionID}}';
    var evtSource = new EventSource('https://{{.AdminDomain}}/_kproxy/sse?session=' + sessionId);
    
    evtSource.onmessage = function(e) {
        var data = JSON.parse(e.data);
        remaining = data.remaining;
        updateDisplay();
        if (data.action === 'block') {
            window.location.href = 'https://{{.AdminDomain}}/_kproxy/blocked?reason=time_limit';
        }
    };
    
    evtSource.onerror = function() {
        // Fallback: decrement locally
        setInterval(function() {
            remaining--;
            updateDisplay();
        }, 1000);
    };
    
    updateDisplay();
})();
</script>
```

### 7.3 SSE Endpoint

```go
func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
    sessionID := r.URL.Query().Get("session")
    session := s.usageTracker.GetSession(sessionID)
    if session == nil {
        http.Error(w, "Invalid session", http.StatusBadRequest)
        return
    }
    
    // Set SSE headers
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")
    w.Header().Set("Connection", "keep-alive")
    w.Header().Set("Access-Control-Allow-Origin", "*")
    
    flusher, ok := w.(http.Flusher)
    if !ok {
        http.Error(w, "Streaming not supported", http.StatusInternalServerError)
        return
    }
    
    ticker := time.NewTicker(1 * time.Second)
    defer ticker.Stop()
    
    ctx := r.Context()
    
    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            remaining := s.calculateRemaining(session)
            action := "continue"
            if remaining <= 0 {
                action = "block"
            }
            
            data := map[string]interface{}{
                "remaining": int(remaining.Seconds()),
                "action":    action,
            }
            jsonData, _ := json.Marshal(data)
            
            fmt.Fprintf(w, "data: %s\n\n", jsonData)
            flusher.Flush()
            
            if action == "block" {
                return
            }
        }
    }
}
```

### 7.4 Selective Injection

Some sites break with response modification. Configuration allows disabling:

```yaml
response_modification:
  # Sites where timer injection is disabled even if rule says InjectTimer: true
  disabled_sites:
    - "banking.example.com"
    - "*.gov"
  # Only inject on these content types
  allowed_content_types:
    - "text/html"
```

-----

## 8. Request Logging

### 8.1 Log Schema

```go
type RequestLog struct {
    ID            int64     `db:"id"`
    Timestamp     time.Time `db:"timestamp"`
    DeviceID      string    `db:"device_id"`
    DeviceName    string    `db:"device_name"`
    ClientIP      string    `db:"client_ip"`
    Method        string    `db:"method"`
    Host          string    `db:"host"`
    Path          string    `db:"path"`
    Query         string    `db:"query"`
    UserAgent     string    `db:"user_agent"`
    ContentType   string    `db:"content_type"`
    StatusCode    int       `db:"status_code"`
    ResponseSize  int64     `db:"response_size"`
    Duration      int64     `db:"duration_ms"`
    Action        string    `db:"action"`        // ALLOW, BLOCK
    MatchedRuleID string    `db:"matched_rule_id"`
    Reason        string    `db:"reason"`
    Category      string    `db:"category"`
    Encrypted     bool      `db:"encrypted"`     // Was this HTTPS?
}
```

### 8.2 SQLite Schema

```sql
CREATE TABLE IF NOT EXISTS request_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    device_id TEXT NOT NULL,
    device_name TEXT,
    client_ip TEXT NOT NULL,
    method TEXT NOT NULL,
    host TEXT NOT NULL,
    path TEXT NOT NULL,
    query TEXT,
    user_agent TEXT,
    content_type TEXT,
    status_code INTEGER,
    response_size INTEGER,
    duration_ms INTEGER,
    action TEXT NOT NULL,
    matched_rule_id TEXT,
    reason TEXT,
    category TEXT,
    encrypted INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_logs_timestamp ON request_logs(timestamp);
CREATE INDEX idx_logs_device ON request_logs(device_id, timestamp);
CREATE INDEX idx_logs_host ON request_logs(host, timestamp);
CREATE INDEX idx_logs_action ON request_logs(action, timestamp);

-- Daily usage aggregation table
CREATE TABLE IF NOT EXISTS daily_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date DATE NOT NULL,
    device_id TEXT NOT NULL,
    limit_id TEXT NOT NULL,
    total_seconds INTEGER NOT NULL DEFAULT 0,
    UNIQUE(date, device_id, limit_id)
);

CREATE INDEX idx_usage_device_date ON daily_usage(device_id, date);
```

### 8.3 Log Rotation

```go
// Automatic cleanup of old logs
func (l *Logger) Cleanup(retentionDays int) error {
    cutoff := time.Now().AddDate(0, 0, -retentionDays)
    _, err := l.db.Exec(
        "DELETE FROM request_logs WHERE timestamp < ?",
        cutoff,
    )
    return err
}

// Run daily at midnight
func (l *Logger) StartCleanupScheduler(retentionDays int) {
    go func() {
        for {
            now := time.Now()
            next := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 5, 0, 0, now.Location())
            time.Sleep(next.Sub(now))
            
            if err := l.Cleanup(retentionDays); err != nil {
                log.Error().Err(err).Msg("log cleanup failed")
            }
        }
    }()
}
```

-----

## 9. Prometheus Metrics

### 9.1 Metric Definitions

```go
var (
    requestsTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "kproxy_requests_total",
            Help: "Total number of requests processed",
        },
        []string{"device", "host", "action", "method"},
    )
    
    requestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "kproxy_request_duration_seconds",
            Help:    "Request duration in seconds",
            Buckets: prometheus.DefBuckets,
        },
        []string{"device", "action"},
    )
    
    activeConnections = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "kproxy_active_connections",
            Help: "Number of active connections",
        },
    )
    
    certificatesGenerated = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "kproxy_certificates_generated_total",
            Help: "Total certificates generated",
        },
    )
    
    certificateCacheHits = prometheus.NewCounter(
        prometheus.CounterOpts{
            Name: "kproxy_certificate_cache_hits_total",
            Help: "Certificate cache hits",
        },
    )
    
    usageMinutesConsumed = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "kproxy_usage_minutes_consumed_total",
            Help: "Total usage minutes consumed",
        },
        []string{"device", "category"},
    )
    
    blockedRequests = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "kproxy_blocked_requests_total",
            Help: "Total blocked requests",
        },
        []string{"device", "reason"},
    )
    
    // DNS metrics
    dnsQueriesTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "kproxy_dns_queries_total",
            Help: "Total DNS queries received",
        },
        []string{"device", "action", "query_type"},
    )
    
    dnsQueryDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "kproxy_dns_query_duration_seconds",
            Help:    "DNS query duration in seconds",
            Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
        },
        []string{"action"},
    )
    
    dnsUpstreamErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "kproxy_dns_upstream_errors_total",
            Help: "DNS upstream query errors",
        },
        []string{"upstream"},
    )
)

func init() {
    prometheus.MustRegister(
        requestsTotal,
        requestDuration,
        activeConnections,
        certificatesGenerated,
        certificateCacheHits,
        usageMinutesConsumed,
        blockedRequests,
        dnsQueriesTotal,
        dnsQueryDuration,
        dnsUpstreamErrors,
    )
}
```

### 9.2 Metrics Server

```go
func (s *Server) startMetricsServer(addr string) {
    mux := http.NewServeMux()
    mux.Handle("/metrics", promhttp.Handler())
    mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK"))
    })
    
    server := &http.Server{
        Addr:    addr,
        Handler: mux,
    }
    
    go func() {
        if err := server.ListenAndServe(); err != http.ErrServerClosed {
            log.Fatal().Err(err).Msg("metrics server failed")
        }
    }()
}
```

-----

## 10. Admin Web Interface

### 10.1 Features

|Feature               |Description                                                                  |
|----------------------|-----------------------------------------------------------------------------|
|**Dashboard**         |Real-time overview: active devices, DNS queries, recent activity, usage stats|
|**Device Management** |Add/edit/remove devices, assign profiles                                     |
|**Profile Management**|Create/edit access profiles with rules                                       |
|**Rule Editor**       |Domain/path rules, categories, priorities                                    |
|**Bypass Rules**      |Configure domains that skip the proxy (banking, updates, etc.)               |
|**Time Rules**        |Configure allowed hours per device/profile                                   |
|**Usage Limits**      |Set daily time limits per category/domain                                    |
|**Live Activity**     |Real-time request stream (HTTP + DNS) with filtering                         |
|**DNS Logs**          |View all DNS queries, intercept/bypass/block decisions                       |
|**Reports**           |Daily/weekly usage reports per device                                        |
|**Blocked Log**       |Review blocked requests with reasons                                         |
|**Settings**          |CA cert download, DNS setup guide, system config                             |

### 10.2 API Endpoints

```
Admin API (served on admin domain, port 8443)

Authentication:
POST   /api/auth/login         - Login with credentials
POST   /api/auth/logout        - Logout
GET    /api/auth/me            - Current user info

Devices:
GET    /api/devices            - List all devices
POST   /api/devices            - Create device
GET    /api/devices/:id        - Get device details
PUT    /api/devices/:id        - Update device
DELETE /api/devices/:id        - Delete device

Profiles:
GET    /api/profiles           - List profiles
POST   /api/profiles           - Create profile
GET    /api/profiles/:id       - Get profile
PUT    /api/profiles/:id       - Update profile
DELETE /api/profiles/:id       - Delete profile

Rules:
GET    /api/profiles/:id/rules - List rules in profile
POST   /api/profiles/:id/rules - Add rule
PUT    /api/rules/:id          - Update rule
DELETE /api/rules/:id          - Delete rule

Time Rules:
GET    /api/profiles/:id/time-rules
POST   /api/profiles/:id/time-rules
PUT    /api/time-rules/:id
DELETE /api/time-rules/:id

Usage Limits:
GET    /api/profiles/:id/limits
POST   /api/profiles/:id/limits
PUT    /api/limits/:id
DELETE /api/limits/:id

Bypass Rules (DNS):
GET    /api/bypass-rules         - List all bypass rules
POST   /api/bypass-rules         - Create bypass rule
PUT    /api/bypass-rules/:id     - Update bypass rule
DELETE /api/bypass-rules/:id     - Delete bypass rule

Logs:
GET    /api/logs               - Query HTTP logs (paginated, filterable)
GET    /api/logs/dns           - Query DNS logs (paginated, filterable)
GET    /api/logs/live          - SSE stream of live requests (HTTP + DNS)

Reports:
GET    /api/reports/usage      - Usage statistics
GET    /api/reports/blocked    - Blocked request summary

System:
GET    /api/system/status      - System health
GET    /api/system/ca-cert     - Download root CA certificate
GET    /api/system/config      - Current configuration
PUT    /api/system/config      - Update configuration
```

### 10.3 Frontend Technology

**Recommended:** Embed a pre-built React/Preact SPA using `go:embed`:

```go
//go:embed ui/dist/*
var uiFS embed.FS

func (s *Server) setupAdminRoutes(mux *http.ServeMux) {
    // API routes
    mux.HandleFunc("/api/", s.handleAPI)
    
    // Static files
    uiContent, _ := fs.Sub(uiFS, "ui/dist")
    fileServer := http.FileServer(http.FS(uiContent))
    mux.Handle("/", fileServer)
}
```

-----

## 11. Configuration

### 11.1 Configuration File Structure

```yaml
# /etc/kproxy/config.yaml

server:
  # DNS server (primary entry point for clients)
  dns_port: 53
  dns_enable_udp: true
  dns_enable_tcp: true
  
  # Proxy ports
  http_port: 80
  https_port: 443
  
  # Admin interface
  admin_port: 8443
  admin_domain: "kproxy.home.local"  # Or FQDN of host
  
  # Metrics
  metrics_port: 9090
  
  # Bind address (0.0.0.0 for all interfaces)
  bind_address: "0.0.0.0"

dns:
  # Upstream DNS servers for bypass/forwarded queries
  upstream_servers:
    - "8.8.8.8:53"
    - "1.1.1.1:53"
  
  # TTL settings
  intercept_ttl: 60       # TTL for intercepted domains (low for quick config changes)
  bypass_ttl_cap: 300     # Max TTL for bypassed domains (0 = no cap, use upstream)
  block_ttl: 60           # TTL for blocked domains
  
  # Query timeout
  upstream_timeout: "5s"
  
  # Global bypass domains (always bypass, never intercept)
  global_bypass:
    - "ocsp.*.com"        # Certificate validation
    - "crl.*.com"
    - "*.ocsp.*"
    - "time.*.com"        # NTP-related
    - "time.*.gov"

tls:
  # CA certificate and key paths
  ca_cert: "/etc/kproxy/ca/root-ca.crt"
  ca_key: "/etc/kproxy/ca/root-ca.key"
  
  # Intermediate CA (for signing)
  intermediate_cert: "/etc/kproxy/ca/intermediate-ca.crt"
  intermediate_key: "/etc/kproxy/ca/intermediate-ca.key"
  
  # Certificate cache settings
  cert_cache_size: 1000
  cert_cache_ttl: "24h"
  cert_validity: "24h"

database:
  path: "/var/lib/kproxy/kproxy.db"

logging:
  level: "info"  # debug, info, warn, error
  format: "json" # json, text
  request_log_retention_days: 30

policy:
  # Default action for unknown devices
  default_action: "block"  # or "allow"
  
  # Default action for devices without matching rules
  default_allow: false
  
  # Device identification
  use_mac_address: true
  arp_cache_ttl: "5m"

usage_tracking:
  # Inactivity threshold for session tracking
  inactivity_timeout: "2m"
  
  # Minimum session duration to count
  min_session_duration: "10s"
  
  # Daily reset time (local timezone)
  daily_reset_time: "00:00"

response_modification:
  # Enable/disable timer injection
  enabled: true
  
  # Sites where injection is disabled
  disabled_hosts:
    - "*.bank.com"
    - "secure.*"
  
  # Content types to modify
  allowed_content_types:
    - "text/html"

admin:
  # Initial admin credentials (change on first login!)
  initial_username: "admin"
  initial_password: "changeme"
  
  # Session settings
  session_timeout: "24h"
  
  # Rate limiting
  rate_limit: 100  # requests per minute
```

### 11.2 Environment Variable Overrides

```bash
# All config values can be overridden with KPROXY_ prefix
KPROXY_SERVER_HTTP_PORT=8080
KPROXY_SERVER_ADMIN_DOMAIN=proxy.example.com
KPROXY_TLS_CA_CERT=/path/to/cert
KPROXY_DATABASE_PATH=/data/kproxy.db
KPROXY_LOGGING_LEVEL=debug
```

-----

## 12. Project Structure

```
github.com/goodtune/kproxy/
├── cmd/
│   └── kproxy/
│       └── main.go              # Entry point
├── internal/
│   ├── config/
│   │   └── config.go            # Configuration loading
│   ├── proxy/
│   │   ├── server.go            # Main proxy server
│   │   ├── http.go              # HTTP handler
│   │   ├── https.go             # HTTPS/TLS handler
│   │   └── transport.go         # Upstream transport
│   ├── dns/
│   │   ├── server.go            # DNS server implementation
│   │   ├── handler.go           # Query handling logic
│   │   ├── resolver.go          # Upstream DNS resolution
│   │   ├── cache.go             # DNS response caching (optional)
│   │   └── logger.go            # DNS query logging
│   ├── ca/
│   │   ├── ca.go                # Certificate authority
│   │   ├── cert.go              # Certificate generation
│   │   └── cache.go             # Certificate cache
│   ├── policy/
│   │   ├── engine.go            # Policy evaluation
│   │   ├── device.go            # Device identification
│   │   ├── rules.go             # Rule matching
│   │   └── time.go              # Time rules
│   ├── usage/
│   │   ├── tracker.go           # Usage tracking
│   │   ├── session.go           # Session management
│   │   └── limits.go            # Limit enforcement
│   ├── modifier/
│   │   ├── modifier.go          # Response modification
│   │   ├── inject.go            # HTML injection
│   │   └── templates/           # Overlay templates
│   ├── logger/
│   │   ├── logger.go            # Request logging
│   │   └── cleanup.go           # Log rotation
│   ├── metrics/
│   │   ├── metrics.go           # Prometheus metrics
│   │   └── server.go            # Metrics HTTP server
│   ├── admin/
│   │   ├── server.go            # Admin HTTP server
│   │   ├── auth.go              # Authentication
│   │   ├── handlers.go          # API handlers
│   │   └── sse.go               # Server-sent events
│   └── database/
│       ├── db.go                # Database connection
│       ├── migrations/          # Schema migrations
│       └── queries/             # SQL queries
├── ui/                          # Admin UI (React/Preact)
│   ├── src/
│   ├── public/
│   └── package.json
├── scripts/
│   ├── generate-ca.sh           # CA setup script
│   └── install-cert.sh          # Client cert install helper
├── configs/
│   └── config.example.yaml      # Example configuration
├── deployments/
│   ├── docker/
│   │   └── Dockerfile
│   ├── systemd/
│   │   └── kproxy.service
│   └── kubernetes/
│       └── deployment.yaml
├── docs/
│   ├── SETUP.md
│   ├── CONFIGURATION.md
│   └── API.md
├── go.mod
├── go.sum
├── Makefile
└── README.md
```

-----

## 13. Implementation Phases

### Phase 1: Core Proxy & DNS Server (Week 1-2)

**Deliverables:**

- [ ] Embedded DNS server (intercept mode only initially)
- [ ] DNS query logging
- [ ] HTTP proxy that forwards requests
- [ ] TLS termination with dynamic certificate generation
- [ ] Basic CA integration (generate certs on-the-fly)
- [ ] Certificate caching (LRU)
- [ ] Configuration file loading
- [ ] Basic logging (stdout)

**Testing:**

- DNS queries return proxy IP for all domains
- Proxy HTTP requests successfully
- Proxy HTTPS requests with generated certs
- Verify certificates are cached

### Phase 2: Policy Engine & DNS Bypass (Week 3-4)

**Deliverables:**

- [ ] Device identification (IP-based)
- [ ] Profile/rule data model
- [ ] Domain matching with wildcards
- [ ] DNS bypass rules (forward to upstream, return real IP)
- [ ] Path-based filtering for HTTP
- [ ] Allow/block decisions
- [ ] SQLite database integration
- [ ] Block page rendering

**Testing:**

- Bypass domains resolve to real IPs
- Intercepted domains resolve to proxy IP
- Block specific domains
- Allow specific paths on blocked domains
- Different rules per device

### Phase 3: Time Rules & Usage Tracking (Week 5-6)

**Deliverables:**

- [ ] Time-of-access restrictions
- [ ] Usage session tracking
- [ ] Daily usage aggregation
- [ ] Time limit enforcement
- [ ] Daily reset mechanism

**Testing:**

- Verify time windows work correctly
- Verify usage accumulates properly
- Verify daily reset works

### Phase 4: Response Modification (Week 7)

**Deliverables:**

- [ ] HTML response detection
- [ ] Timer overlay injection
- [ ] SSE endpoint for countdown updates
- [ ] Selective injection (disable for certain sites)

**Testing:**

- Overlay appears on time-limited sites
- Countdown updates in real-time
- Sites without injection work normally

### Phase 5: Admin Interface (Week 8-10)

**Deliverables:**

- [ ] Admin API endpoints
- [ ] Authentication system
- [ ] React/Preact frontend
- [ ] Dashboard with real-time stats
- [ ] Device/profile/rule management
- [ ] Log viewer
- [ ] CA certificate download

**Testing:**

- CRUD operations for all entities
- Real-time log streaming
- Report generation

### Phase 6: Metrics & Observability (Week 11)

**Deliverables:**

- [ ] Prometheus metrics endpoint
- [ ] All key metrics instrumented
- [ ] Health check endpoint
- [ ] Grafana dashboard template

**Testing:**

- Metrics scraping works
- Dashboards show meaningful data

### Phase 7: Hardening & Documentation (Week 12)

**Deliverables:**

- [ ] Error handling improvements
- [ ] Rate limiting
- [ ] Security review
- [ ] Performance optimization
- [ ] Documentation
- [ ] Docker image
- [ ] Systemd service file

-----

## 14. Key Dependencies

```go
// go.mod (key dependencies)
module github.com/goodtune/kproxy

go 1.22

require (
    // HTTP routing
    github.com/gorilla/mux v1.8.1
    
    // DNS server
    github.com/miekg/dns v1.1.58
    
    // Database
    modernc.org/sqlite v1.28.0
    
    // Configuration
    github.com/spf13/viper v1.18.2
    
    // Logging
    github.com/rs/zerolog v1.31.0
    
    // Metrics
    github.com/prometheus/client_golang v1.18.0
    
    // Certificate management (step-ca libraries)
    github.com/smallstep/certificates v0.25.2
    github.com/smallstep/crypto v0.41.0
    go.step.sm/crypto v0.41.0
    
    // Caching
    github.com/hashicorp/golang-lru/v2 v2.0.7
    
    // Testing
    github.com/stretchr/testify v1.8.4
)
```

-----

## 15. Deployment Considerations

### 15.1 Client DNS Configuration (Simplified)

With the embedded DNS server, client setup is straightforward:

**Option A: Configure DHCP to push KProxy as DNS (Recommended)**

- Configure your router’s DHCP server to assign KProxy IP as the DNS server
- All devices automatically use KProxy for DNS resolution
- KProxy decides per-domain whether to intercept or bypass

**Option B: Per-device manual configuration**

- Set DNS server to KProxy IP in device network settings
- Useful for testing or when router DHCP cannot be modified

**Option C: Selective device filtering**

- Only configure managed devices to use KProxy DNS
- Other devices use normal DNS and bypass the proxy entirely

**What clients need:**

1. DNS server set to KProxy IP (e.g., `192.168.1.100`)
1. KProxy root CA certificate installed (for HTTPS interception)
1. That’s it! No proxy settings required.

### 15.2 Network Requirements

- KProxy needs a **static IP** on the network
- Ports 53 (DNS), 80, 443, 8443, 9090 must not be blocked
- Devices need to **trust the KProxy root CA**
- Upstream internet connectivity for forwarded DNS queries

### 14.3 Resource Requirements

For a home network with 10 devices:

|Resource|Minimum|Recommended   |
|--------|-------|--------------|
|CPU     |1 core |2 cores       |
|RAM     |256MB  |512MB         |
|Disk    |1GB    |5GB (for logs)|

### 14.4 High Availability

For home use, single instance is sufficient. If HA is needed:

- Run multiple instances behind load balancer
- Share SQLite via networked storage (or migrate to PostgreSQL)
- Share CA keys between instances

-----

## 16. Security Considerations

### 15.1 CA Key Protection

- Store CA private key with restrictive permissions (600)
- Consider hardware security (YubiKey, TPM) for production
- Never expose CA key over network

### 15.2 Admin Interface Security

- HTTPS only for admin interface
- Strong password requirements
- Session timeout
- Rate limiting on auth endpoints
- CSRF protection

### 15.3 Data Privacy

- Logs contain sensitive browsing history
- Encrypt database at rest (SQLite encryption extension)
- Implement data retention policies
- Secure log access (admin only)

### 15.4 Network Security

- Bind admin interface to specific IP (not 0.0.0.0 if possible)
- Consider firewall rules to restrict access
- Regular security updates

-----

## 17. Testing Strategy

### 17.1 Unit Tests

- DNS query handling (intercept/bypass/block decisions)
- DNS domain matching with wildcards
- Policy engine rule matching
- Domain wildcard matching
- Time window calculations
- Usage tracking logic
- Certificate generation

### 17.2 Integration Tests

- DNS server responds correctly to queries
- DNS bypass forwards to upstream and returns real IP
- DNS intercept returns proxy IP
- Full proxy flow (HTTP and HTTPS)
- Database operations
- Admin API endpoints
- SSE streaming

### 17.3 End-to-End Tests

- Client configured with KProxy DNS resolves domains correctly
- Bypass domains reach real servers directly
- Browser testing with proxy configured
- Multiple devices with different rules
- Time limit enforcement
- Block page rendering

### 17.4 Performance Tests

- DNS query latency (target: <10ms for intercept, <50ms for bypass)
- Concurrent DNS queries (target: 1000 qps)
- Concurrent HTTP connections (target: 100 concurrent)
- Request throughput (target: 1000 req/s)
- Certificate generation latency (target: <50ms)
- Memory usage under load

-----

## 18. Future Enhancements

|Feature                   |Description                                    |Priority|
|--------------------------|-----------------------------------------------|--------|
|**SafeSearch Enforcement**|Force SafeSearch on Google/Bing/YouTube        |Medium  |
|**Content Categorization**|Auto-categorize domains using external service |Low     |
|**Mobile App**            |Parent monitoring app for iOS/Android          |Low     |
|**Machine Learning**      |Anomaly detection for unusual browsing patterns|Low     |
|**Multi-tenant**          |Support multiple families/households           |Low     |
|**WebSocket Support**     |Proxy WebSocket connections                    |Medium  |
|**QUIC/HTTP3**            |Support modern protocols                       |Future  |

-----

## Appendix A: Block Page Template

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked - KProxy</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 16px;
            padding: 40px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .icon { font-size: 64px; margin-bottom: 20px; }
        h1 { color: #333; margin-bottom: 16px; }
        p { color: #666; line-height: 1.6; margin-bottom: 24px; }
        .reason {
            background: #f5f5f5;
            padding: 16px;
            border-radius: 8px;
            font-family: monospace;
            color: #c00;
        }
        .info { font-size: 14px; color: #999; margin-top: 24px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">🚫</div>
        <h1>Access Blocked</h1>
        <p>This website has been blocked by your parent's content filter.</p>
        <div class="reason">{{.Reason}}</div>
        <p class="info">
            If you believe this is a mistake, please talk to your parent.<br>
            Blocked at: {{.Timestamp}}<br>
            Device: {{.DeviceName}}
        </p>
    </div>
</body>
</html>
```

-----

## Appendix B: Makefile

```makefile
.PHONY: all build test lint clean docker

VERSION := $(shell git describe --tags --always --dirty)
LDFLAGS := -X main.version=$(VERSION)

all: build

build:
	go build -ldflags "$(LDFLAGS)" -o bin/kproxy ./cmd/kproxy

build-ui:
	cd ui && npm install && npm run build

test:
	go test -v -race -cover ./...

lint:
	golangci-lint run

clean:
	rm -rf bin/
	rm -rf ui/dist/

docker:
	docker build -t kproxy:$(VERSION) .

run:
	go run ./cmd/kproxy -config configs/config.example.yaml

generate-ca:
	./scripts/generate-ca.sh

install:
	install -m 755 bin/kproxy /usr/local/bin/
	install -m 644 deployments/systemd/kproxy.service /etc/systemd/system/
	systemctl daemon-reload
```

-----

*Document Version: 1.0*  
*Last Updated: December 2025*  
*Author: Gary Reynolds*
