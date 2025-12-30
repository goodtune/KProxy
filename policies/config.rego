package kproxy.config

# Device Configuration
# Define all devices with their identifiers (MAC addresses, IPs, or CIDR ranges)
# and their assigned profile.
#
# Example:
#   devices := {
#       "kids-ipad": {
#           "name": "Kids iPad",
#           "identifiers": ["aa:bb:cc:dd:ee:ff"],  # MAC address
#           "profile": "child"
#       }
#   }
#
# See docs/policy-tutorial.md for detailed examples.
devices := {}

# Profile Configuration
# Define access profiles with rules, time restrictions, and usage limits.
#
# The default profile below blocks all traffic as a secure baseline.
# Customize this configuration for your network - see docs/policy-tutorial.md
profiles := {
	"default": {
		"name": "Default Profile",
		"description": "Secure baseline - blocks all traffic",
		"rules": [],
		"time_restrictions": {},
		"usage_limits": {},
		"default_action": "block",
	},
}

# Global Bypass Domains
# These domains always bypass the proxy (never intercepted).
# Use for certificate validation and sensitive sites to avoid MITM.
#
# Example bypass domains:
#   - Certificate validation: "ocsp.*.com", "*.ocsp.apple.com"
#   - Banking: "*.chase.com", "*.wellsfargo.com"
#   - Government: "*.gov"
#
# See docs/policy-tutorial.md Step 6 for guidance on bypass domains.
bypass_domains := []
