# KProxy Policy Tutorial

This tutorial guides you through writing KProxy policies using Open Policy Agent (OPA) and Rego, starting from a simple "block everything" policy and progressively building to advanced use cases.

## Table of Contents

1. [Understanding the Basics](#1-understanding-the-basics)
2. [Step 1: Block Everything (Default Deny)](#step-1-block-everything-default-deny)
3. [Step 2: Allow Google Search](#step-2-allow-google-search)
4. [Step 3: Allow Gmail](#step-3-allow-gmail)
5. [Step 4: Allow All Google Domains](#step-4-allow-all-google-domains)
6. [Step 5: Time-Based Restrictions by IP Subnet](#step-5-time-based-restrictions-by-ip-subnet)
7. [Step 6: Bypass Banking Sites](#step-6-bypass-banking-sites)
8. [Step 7: Block Advertisement Domains](#step-7-block-advertisement-domains)
9. [Advanced Topics](#advanced-topics)
10. [Testing Your Policies](#testing-your-policies)

## Prerequisites

Before starting this tutorial:
- You have KProxy installed and running
- You understand basic YAML and JSON syntax
- You've read the [main documentation](README.md) on OPA and Rego

## 1. Understanding the Basics

### Policy Files Structure

KProxy uses five main policy files in `/etc/kproxy/policies/`:

| File | Purpose | You Edit? |
|------|---------|-----------|
| `config.rego` | Devices, profiles, rules, limits | **YES** - This is where you configure everything |
| `device.rego` | Device identification logic | No - Core logic, rarely changed |
| `dns.rego` | DNS-level decisions | No - Core logic, rarely changed |
| `proxy.rego` | HTTP/HTTPS request decisions | No - Core logic, rarely changed |
| `helpers.rego` | Utility functions | No - Core logic, rarely changed |

**In this tutorial, we'll only edit `config.rego`.**

### How Policies Work

```
Request → KProxy gathers facts → OPA evaluates config.rego → Decision → Enforce
```

**Facts KProxy gathers:**
- `client_ip`: IP address of the device
- `client_mac`: MAC address of the device
- `host`: Domain being accessed (e.g., "youtube.com")
- `path`: URL path (e.g., "/watch?v=...")
- `time`: Current day/hour (`day_of_week`: 1=Monday, `hour`: 0-23)
- `usage`: Current usage minutes by category

**Decisions OPA returns:**
- **DNS**: BYPASS, INTERCEPT, or BLOCK
- **Proxy**: ALLOW or BLOCK (with metadata)

### Domain Matching Syntax

| Pattern | Matches | Examples |
|---------|---------|----------|
| `google.com` | Exact domain only | ✅ google.com<br>❌ www.google.com |
| `*.google.com` | Subdomains only | ✅ www.google.com<br>✅ mail.google.com<br>❌ google.com |
| `.google.com` | Domain + all subdomains | ✅ google.com<br>✅ www.google.com<br>✅ mail.google.com |

---

## Step 1: Block Everything (Default Deny)

**Goal**: Start with a secure baseline where all traffic is blocked.

### Edit `/etc/kproxy/policies/config.rego`:

```rego
package kproxy.config

# No devices defined yet
devices := {}

# Single profile that blocks everything
profiles := {
    "default": {
        "rules": [],              # No allow rules
        "default_action": "block" # Block everything
    }
}

# No global bypasses
global_bypass_domains := []
```

### What This Does

- **DNS**: All domains are intercepted (sent to proxy)
- **Proxy**: All requests are blocked
- **Result**: No internet access for anyone

### Testing

```bash
# Restart KProxy
sudo systemctl restart kproxy

# From a client device
curl -v http://example.com
# Expected: Connection refused or block page
```

**Why start here?** Security-first: explicitly allow only what's needed rather than blocking what you remember to restrict.

---

## Step 2: Allow Google Search

**Goal**: Allow all devices to search on Google while blocking everything else.

### Update `config.rego`:

```rego
package kproxy.config

devices := {}

profiles := {
    "default": {
        "rules": [
            {
                "id": "allow-google-search",
                "domains": [
                    ".google.com",           # google.com and all subdomains
                    ".gstatic.com",          # Google static assets
                    ".googleapis.com"        # Google APIs
                ],
                "action": "allow",
                "priority": 10
            }
        ],
        "default_action": "block"
    }
}

global_bypass_domains := []
```

### What This Does

- ✅ Allows: `google.com`, `www.google.com`, `www.gstatic.com`, `fonts.googleapis.com`
- ❌ Blocks: Everything else

### Key Concepts

**Why multiple domains?**
- Modern websites load resources from multiple domains
- `gstatic.com` serves Google's CSS, JavaScript, images
- `googleapis.com` provides API endpoints

**Priority field:**
- Lower numbers = higher priority
- Used when multiple rules could match
- Not critical in this simple example

---

## Step 3: Allow Gmail

**Goal**: Add Gmail access while keeping Google Search allowed.

### Update `config.rego`:

```rego
package kproxy.config

devices := {}

profiles := {
    "default": {
        "rules": [
            {
                "id": "allow-google-search",
                "domains": [
                    ".google.com",
                    ".gstatic.com",
                    ".googleapis.com"
                ],
                "action": "allow",
                "priority": 10
            },
            {
                "id": "allow-gmail",
                "domains": [
                    "mail.google.com",       # Gmail web interface
                    ".googleusercontent.com" # Gmail attachments/images
                ],
                "action": "allow",
                "priority": 10
            }
        ],
        "default_action": "block"
    }
}

global_bypass_domains := []
```

### What This Does

- ✅ Allows: Google Search + Gmail
- ❌ Blocks: Everything else

**Note:** `mail.google.com` is already covered by `.google.com` from the search rule, but we list it explicitly for clarity. The `googleusercontent.com` domain is new and needed for Gmail functionality.

---

## Step 4: Allow All Google Domains

**Goal**: Simplify by allowing all Google services (Search, Gmail, YouTube, Drive, etc.)

### Update `config.rego`:

```rego
package kproxy.config

devices := {}

profiles := {
    "default": {
        "rules": [
            {
                "id": "allow-all-google",
                "domains": [
                    ".google.com",
                    ".googleapis.com",
                    ".gstatic.com",
                    ".googleusercontent.com",
                    ".youtube.com",          # YouTube
                    ".ytimg.com",            # YouTube images
                    ".googlevideo.com",      # YouTube videos
                    ".ggpht.com",            # Google Photos thumbnails
                    ".goog",                 # New Google TLD
                    ".google"                # Another Google TLD
                ],
                "action": "allow",
                "priority": 10
            }
        ],
        "default_action": "block"
    }
}

global_bypass_domains := []
```

### What This Does

- ✅ Allows: All Google services (Search, Gmail, YouTube, Drive, Maps, etc.)
- ❌ Blocks: Everything else

### Why So Many Domains?

Google operates across many domains. To allow full functionality:
- `*.youtube.com` - Main YouTube site
- `*.googlevideo.com` - Video streaming CDN
- `*.ytimg.com` - Thumbnails and images
- `*.ggpht.com` - Google Photos content
- `.goog`, `.google` - New generic TLDs owned by Google

---

## Step 5: Time-Based Restrictions by IP Subnet

**Goal**: Different rules for children's devices (192.168.2.0/24 subnet) with time-based access.

**Scenario:**
- Children's devices: 192.168.2.0/24
- Adults' devices: 192.168.1.0/24
- Children can access internet:
  - **Weekdays**: 7-8 AM (before school) and 3-6 PM (after school, before dinner)
  - **Weekends**: All day

### Update `config.rego`:

```rego
package kproxy.config

# Define devices by subnet
devices := {
    "children-subnet": {
        "name": "Children's Devices",
        "identifiers": ["192.168.2.0/24"],  # CIDR notation
        "profile": "child"
    },
    "adults-subnet": {
        "name": "Adults' Devices",
        "identifiers": ["192.168.1.0/24"],
        "profile": "adult"
    }
}

profiles := {
    "child": {
        # Time restrictions
        "time_restrictions": {
            "weekday-morning": {
                "days": [1, 2, 3, 4, 5],  # Monday-Friday
                "start_hour": 7,          # 7 AM
                "end_hour": 8             # 8 AM
            },
            "weekday-afternoon": {
                "days": [1, 2, 3, 4, 5],  # Monday-Friday
                "start_hour": 15,         # 3 PM
                "end_hour": 18            # 6 PM
            },
            "weekend-allday": {
                "days": [6, 7],           # Saturday, Sunday
                "start_hour": 0,          # Midnight
                "end_hour": 24            # End of day
            }
        },
        # Access rules (same as before)
        "rules": [
            {
                "id": "allow-all-google",
                "domains": [
                    ".google.com",
                    ".googleapis.com",
                    ".gstatic.com",
                    ".googleusercontent.com",
                    ".youtube.com",
                    ".ytimg.com",
                    ".googlevideo.com",
                    ".ggpht.com"
                ],
                "action": "allow",
                "priority": 10
            }
        ],
        "default_action": "block"  # Block outside allowed times
    },
    "adult": {
        # No time restrictions
        "rules": [
            {
                "id": "allow-all-google",
                "domains": [
                    ".google.com",
                    ".googleapis.com",
                    ".gstatic.com",
                    ".googleusercontent.com",
                    ".youtube.com",
                    ".ytimg.com",
                    ".googlevideo.com",
                    ".ggpht.com"
                ],
                "action": "allow",
                "priority": 10
            }
        ],
        "default_action": "allow"  # Adults: allow everything by default
    }
}

global_bypass_domains := []
```

### What This Does

**Children (192.168.2.x):**
- ✅ **Weekday 7-8 AM**: Google services only
- ✅ **Weekday 3-6 PM**: Google services only
- ✅ **Weekend all day**: Google services only
- ❌ **Other times**: Blocked

**Adults (192.168.1.x):**
- ✅ **Always**: Everything allowed (no restrictions)

### Key Concepts

**Device Identification by CIDR:**
```rego
"identifiers": ["192.168.2.0/24"]  # Matches 192.168.2.0 - 192.168.2.255
```

**Time Windows:**
- `days`: 1=Monday, 2=Tuesday, ..., 7=Sunday
- `start_hour`, `end_hour`: 24-hour format (0-23)
- Multiple time windows allowed per profile

**How it works:**
1. KProxy identifies device by IP → profile
2. Checks if current time is within allowed windows
3. If outside time windows, blocks everything
4. If inside time window, evaluates rules

---

## Step 6: Bypass Banking Sites

**Goal**: Bypass HTTPS interception for banking and sensitive sites to avoid MITM issues.

**Why bypass?**
- Banks use certificate pinning (reject our proxy certificate)
- Security best practice: Don't MITM financial traffic
- OCSP/CRL validation should bypass proxy

### Update `config.rego`:

```rego
package kproxy.config

devices := {
    "children-subnet": {
        "name": "Children's Devices",
        "identifiers": ["192.168.2.0/24"],
        "profile": "child"
    },
    "adults-subnet": {
        "name": "Adults' Devices",
        "identifiers": ["192.168.1.0/24"],
        "profile": "adult"
    }
}

profiles := {
    "child": {
        "time_restrictions": {
            "weekday-morning": {
                "days": [1, 2, 3, 4, 5],
                "start_hour": 7,
                "end_hour": 8
            },
            "weekday-afternoon": {
                "days": [1, 2, 3, 4, 5],
                "start_hour": 15,
                "end_hour": 18
            },
            "weekend-allday": {
                "days": [6, 7],
                "start_hour": 0,
                "end_hour": 24
            }
        },
        "rules": [
            {
                "id": "allow-all-google",
                "domains": [
                    ".google.com",
                    ".googleapis.com",
                    ".gstatic.com",
                    ".googleusercontent.com",
                    ".youtube.com",
                    ".ytimg.com",
                    ".googlevideo.com",
                    ".ggpht.com"
                ],
                "action": "allow",
                "priority": 10
            }
        ],
        "default_action": "block"
    },
    "adult": {
        "rules": [
            {
                "id": "allow-all-google",
                "domains": [
                    ".google.com",
                    ".googleapis.com",
                    ".gstatic.com",
                    ".googleusercontent.com",
                    ".youtube.com",
                    ".ytimg.com",
                    ".googlevideo.com",
                    ".ggpht.com"
                ],
                "action": "allow",
                "priority": 10
            }
        ],
        "default_action": "allow"
    }
}

# Global bypass: skip proxy entirely for these domains
global_bypass_domains := [
    # Certificate validation (critical - browsers will fail without this)
    "ocsp.*.com",
    "ocsp.*.net",
    "*.ocsp.apple.com",
    "*.crl.apple.com",

    # Banking and financial services (example - add your banks)
    ".wellsfargo.com",
    ".bankofamerica.com",
    ".chase.com",
    ".citi.com",
    ".usbank.com",
    ".capitalone.com",

    # Payment processors
    ".paypal.com",
    ".stripe.com",
    ".square.com",

    # Government services (certificate pinning common)
    ".irs.gov",
    ".ssa.gov",

    # Healthcare (HIPAA compliance concerns)
    ".myhealth.va.gov",

    # OS/Software updates (may use certificate pinning)
    ".apple.com",
    ".microsoft.com",
    ".windowsupdate.com"
]
```

### What This Does

**Bypassed domains:**
- DNS returns real IP (not proxy IP)
- Traffic goes directly to internet (no interception)
- KProxy never sees the content

**Benefits:**
- ✅ Banking sites work without certificate errors
- ✅ Certificate validation (OCSP) works
- ✅ OS updates work reliably
- ✅ No privacy concerns with financial data

**Trade-offs:**
- ❌ Can't apply access rules to bypassed domains
- ❌ Can't log traffic to bypassed sites
- ❌ Can't block specific paths on bypassed domains

### Common Bypass Domains

Add domains that:
- Use certificate pinning
- Handle financial transactions
- Contain sensitive health information
- Are critical infrastructure (OS updates, security services)

---

## Step 7: Block Advertisement Domains

**Goal**: Block ad-serving domains at DNS level like Pi-hole.

**Strategy:**
- DNS-level blocking: return NXDOMAIN or 0.0.0.0
- Faster than proxy-level blocking (no HTTP connection needed)
- Saves bandwidth

### Update `config.rego`:

Add an ad-blocking profile that blocks known ad domains:

```rego
package kproxy.config

devices := {
    "children-subnet": {
        "name": "Children's Devices",
        "identifiers": ["192.168.2.0/24"],
        "profile": "child"
    },
    "adults-subnet": {
        "name": "Adults' Devices",
        "identifiers": ["192.168.1.0/24"],
        "profile": "adult-adblock"  # Changed to ad-blocking profile
    }
}

profiles := {
    "child": {
        "time_restrictions": {
            "weekday-morning": {
                "days": [1, 2, 3, 4, 5],
                "start_hour": 7,
                "end_hour": 8
            },
            "weekday-afternoon": {
                "days": [1, 2, 3, 4, 5],
                "start_hour": 15,
                "end_hour": 18
            },
            "weekend-allday": {
                "days": [6, 7],
                "start_hour": 0,
                "end_hour": 24
            }
        },
        "rules": [
            {
                "id": "allow-all-google",
                "domains": [
                    ".google.com",
                    ".googleapis.com",
                    ".gstatic.com",
                    ".googleusercontent.com",
                    ".youtube.com",
                    ".ytimg.com",
                    ".googlevideo.com",
                    ".ggpht.com"
                ],
                "action": "allow",
                "priority": 10
            }
        ],
        "default_action": "block"
    },
    "adult-adblock": {
        "rules": [
            # Block ads FIRST (higher priority = lower number)
            {
                "id": "block-ads",
                "domains": [
                    # Major ad networks
                    ".doubleclick.net",
                    ".googleadservices.com",
                    ".googlesyndication.com",
                    ".google-analytics.com",

                    # Facebook/Meta ads
                    ".facebook.net",
                    ".fbcdn.net",

                    # Ad networks
                    ".advertising.com",
                    ".2mdn.net",
                    ".adnxs.com",
                    ".adsafeprotected.com",
                    ".adsystem.com",
                    ".amazon-adsystem.com",

                    # Tracking
                    ".scorecardresearch.com",
                    ".chartbeat.com",
                    ".quantserve.com",

                    # Video ads
                    ".moatads.com",
                    ".imasdk.googleapis.com"
                ],
                "action": "block",
                "priority": 5  # Higher priority than allow rules
            },
            # Then allow Google services (except ads)
            {
                "id": "allow-all-google",
                "domains": [
                    ".google.com",
                    ".googleapis.com",
                    ".gstatic.com",
                    ".googleusercontent.com",
                    ".youtube.com",
                    ".ytimg.com",
                    ".googlevideo.com",
                    ".ggpht.com"
                ],
                "action": "allow",
                "priority": 10
            }
        ],
        "default_action": "allow"  # Allow everything else
    }
}

global_bypass_domains := [
    # Certificate validation
    "ocsp.*.com",
    "ocsp.*.net",
    "*.ocsp.apple.com",
    "*.crl.apple.com",

    # Banking
    ".wellsfargo.com",
    ".bankofamerica.com",
    ".chase.com",
    ".citi.com",
    ".usbank.com",
    ".capitalone.com",
    ".paypal.com",
    ".stripe.com",
    ".square.com",

    # Government
    ".irs.gov",
    ".ssa.gov",

    # OS updates
    ".apple.com",
    ".microsoft.com",
    ".windowsupdate.com"
]
```

### What This Does

**For adults (192.168.1.x):**
- ❌ Blocks: Known ad and tracking domains
- ✅ Allows: Google services (search, YouTube, Gmail)
- ✅ Allows: Everything else

**For children (192.168.2.x):**
- Unchanged: Time-based restrictions + Google only

### Priority System

Rules are evaluated in priority order (lower number = higher priority):

```rego
Priority 5  → Block ads first
Priority 10 → Allow Google services second
Default     → Allow/block everything else
```

**Why priority matters:**
- `googleadservices.com` matches both "block-ads" (priority 5) and "allow-all-google" (has `.google` in name)
- Priority 5 (block) wins, so ads are blocked even though it's a Google domain

### Expanding Ad Blocking

For comprehensive ad-blocking, use a Pi-hole blocklist:

**Option 1: Manual list (small)**
```rego
"domains": [
    ".doubleclick.net",
    ".adservice.google.com",
    # ... add more manually
]
```

**Option 2: Import from Pi-hole lists**

Use a script to convert Pi-hole lists to Rego:

```bash
#!/bin/bash
# convert-pihole-to-rego.sh

curl -s https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | \
  grep "^0.0.0.0" | \
  awk '{print "\"." $2 "\","}' | \
  sort -u > ad-domains.txt

echo 'Paste ad-domains.txt contents into config.rego "block-ads" domains list'
```

**Note:** Large blocklists (100k+ domains) may impact OPA performance. Start with top ad networks.

---

## Advanced Topics

### Usage Limits

Track and limit usage by category:

```rego
profiles := {
    "child": {
        # ... time restrictions ...
        "rules": [
            {
                "id": "allow-educational",
                "domains": ["*.khanacademy.org", "*.wikipedia.org"],
                "action": "allow",
                "priority": 5,
                "category": "educational"  # Track separately
            },
            {
                "id": "allow-entertainment",
                "domains": ["*.youtube.com", "*.netflix.com"],
                "action": "allow",
                "priority": 10,
                "category": "entertainment"  # Track with limit
            }
        ],
        "usage_limits": {
            "entertainment": {
                "daily_minutes": 60,  # 60 minutes per day
                "domains": ["*.youtube.com", "*.netflix.com"]
            }
        },
        "default_action": "block"
    }
}
```

**How it works:**
1. Request to YouTube is allowed (if within time window)
2. KProxy tracks active session time
3. After 60 minutes total today, YouTube is blocked
4. Resets at midnight

### Device Identification by MAC Address

More reliable than IP (survives DHCP changes):

```rego
devices := {
    "kids-ipad": {
        "name": "Kids iPad",
        "identifiers": ["aa:bb:cc:dd:ee:ff"],  # MAC address
        "profile": "child"
    },
    "kids-laptop": {
        "name": "Kids Laptop",
        "identifiers": ["bb:cc:dd:ee:ff:00"],
        "profile": "child"
    }
}
```

**Finding MAC addresses:**
```bash
# On KProxy server, check DHCP leases
redis-cli KEYS "kproxy:dhcp:*"

# Or check ARP table
arp -a

# On the device itself
# Linux/Mac
ip link show
ifconfig

# Windows
ipconfig /all
```

### Multiple Identifiers

Combine MAC, IP, and CIDR for redundancy:

```rego
devices := {
    "kids-ipad": {
        "name": "Kids iPad",
        "identifiers": [
            "aa:bb:cc:dd:ee:ff",  # MAC (most reliable)
            "192.168.2.100",      # Static IP (backup)
            "192.168.2.0/24"      # Subnet (fallback)
        ],
        "profile": "child"
    }
}
```

**Priority:** MAC → Exact IP → CIDR (first match wins)

### Path-Based Rules

Block specific paths on allowed domains:

```rego
rules := [
    {
        "id": "allow-youtube-education",
        "domains": ["*.youtube.com"],
        "paths": ["/education/*", "/channel/UC*"],  # Educational channels only
        "action": "allow",
        "priority": 5
    },
    {
        "id": "block-youtube-shorts",
        "domains": ["*.youtube.com"],
        "paths": ["/shorts/*"],  # Block YouTube Shorts
        "action": "block",
        "priority": 1  # Higher priority
    }
]
```

**Note:** Path matching currently requires custom implementation in `proxy.rego`. Check your KProxy version.

### Remote Policy Loading

Centralize policies for multiple KProxy instances:

**config.yaml:**
```yaml
policy:
  opa_policy_source: remote
  opa_policy_urls:
    - https://policy-server.example.com/kproxy/config.rego
    - https://policy-server.example.com/kproxy/device.rego
    - https://policy-server.example.com/kproxy/dns.rego
    - https://policy-server.example.com/kproxy/proxy.rego
    - https://policy-server.example.com/kproxy/helpers.rego
  opa_http_timeout: 30s
  opa_http_retries: 3
```

**Benefits:**
- Single source of truth
- Update all KProxy instances by updating server
- Version control policies in Git

**Security:** Use HTTPS and authentication on your policy server.

---

## Testing Your Policies

### 1. Validate Rego Syntax

```bash
# Check for syntax errors
opa test /etc/kproxy/policies/ -v
```

### 2. Test Specific Scenarios

Create test input files:

**test-child-weekday.json:**
```json
{
  "client_ip": "192.168.2.100",
  "client_mac": "aa:bb:cc:dd:ee:ff",
  "host": "youtube.com",
  "path": "/",
  "time": {
    "day_of_week": 2,
    "hour": 16,
    "minute": 30
  },
  "usage": {
    "entertainment": {
      "today_minutes": 30
    }
  }
}
```

**Evaluate:**
```bash
opa eval -d /etc/kproxy/policies/ \
  -i test-child-weekday.json \
  -f pretty \
  "data.kproxy.proxy.decision"
```

**Expected output:**
```json
{
  "action": "ALLOW",
  "device_id": "children-subnet",
  "profile": "child",
  "matched_rule": "allow-all-google",
  "category": "entertainment"
}
```

### 3. Test Time Boundaries

Test edge cases:
- Just before allowed time window
- Just after allowed time window
- Exactly at start/end hour

### 4. Monitor Logs

```bash
# Watch real-time decisions
sudo journalctl -u kproxy -f | grep -E "(ALLOW|BLOCK)"
```

### 5. Use OPA Playground

Test Rego logic online: [https://play.openpolicyagent.org/](https://play.openpolicyagent.org/)

Paste your `config.rego` and test with sample inputs.

---

## Common Pitfalls

### 1. Forgetting Required Domains

**Problem:** Site partially loads (broken images, CSS missing)

**Solution:** Check browser dev tools (F12) → Network tab → see which domains failed. Add to allow list.

### 2. Wrong Domain Syntax

```rego
# ❌ Wrong: Will only match exact "google.com"
"domains": ["google.com"]

# ✅ Correct: Matches google.com AND subdomains
"domains": [".google.com"]

# ✅ Also correct: Matches ONLY subdomains (not google.com itself)
"domains": ["*.google.com"]
```

### 3. Time Zone Confusion

KProxy uses server's local time. If server is UTC but you're in PST:
- `"start_hour": 15` means 3 PM **UTC**, not 3 PM PST
- Set server timezone with `timedatectl set-timezone America/Los_Angeles`

### 4. Rule Priority Conflicts

```rego
# ❌ Problem: YouTube allowed (priority 10) then blocked (priority 20)
rules := [
    {"id": "allow-google", "domains": [".google.com", ".youtube.com"], "action": "allow", "priority": 10},
    {"id": "block-youtube", "domains": [".youtube.com"], "action": "block", "priority": 20}
]
# Result: YouTube allowed (priority 10 wins)

# ✅ Solution: Block rule must have HIGHER priority (LOWER number)
rules := [
    {"id": "block-youtube", "domains": [".youtube.com"], "action": "block", "priority": 5},
    {"id": "allow-google", "domains": [".google.com"], "action": "allow", "priority": 10}
]
# Result: YouTube blocked (priority 5 wins)
```

### 5. Bypass vs. Allow Confusion

| Mechanism | Level | Can Block? | Can Log? | Use For |
|-----------|-------|------------|----------|---------|
| **Bypass** | DNS | ❌ No | ❌ No | Banking, OCSP, certificate pinning |
| **Allow** | Proxy | ✅ Yes (with higher priority block rule) | ✅ Yes | Normal internet access |

---

## Next Steps

1. **Start simple**: Begin with Step 1-4, get comfortable with basic rules
2. **Add devices**: Configure your actual devices with MAC addresses
3. **Implement time restrictions**: Use Step 5 as a template
4. **Secure sensitive sites**: Add bypasses for banking (Step 6)
5. **Block ads**: Implement Step 7 with your preferred blocklist
6. **Monitor**: Watch logs and metrics to refine policies
7. **Test thoroughly**: Use test inputs and real devices before going live

## Resources

- **[OPA Documentation](https://www.openpolicyagent.org/docs/latest/)** - Official OPA docs
- **[Rego Language](https://www.openpolicyagent.org/docs/latest/policy-language/)** - Rego reference
- **[OPA Playground](https://play.openpolicyagent.org/)** - Test Rego online
- **[KProxy README](README.md)** - Main documentation
- **[Pi-hole Blocklists](https://github.com/StevenBlack/hosts)** - Popular ad-blocking lists

## Getting Help

If you encounter issues:

1. **Validate syntax**: `opa test /etc/kproxy/policies/ -v`
2. **Check logs**: `sudo journalctl -u kproxy -f`
3. **Test locally**: Use `opa eval` with test inputs
4. **Ask for help**: Open an issue on GitHub with your config and logs

Happy filtering! 🎯
