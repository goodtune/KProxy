package kproxy.dns

import rego.v1

import data.kproxy.config
import data.kproxy.helpers

# DNS Action Decision
# Determines whether to BYPASS (forward upstream), INTERCEPT (proxy), or BLOCK (0.0.0.0)
#
# Input structure (facts only):
# {
#   "client_ip": "192.168.1.100",
#   "client_mac": "aa:bb:cc:dd:ee:ff",  // optional
#   "domain": "youtube.com"
# }
#
# Configuration comes from data.kproxy.config

# Highest priority: Global bypass domains (system-critical services)
# These should never be intercepted to prevent certificate validation errors
action := "BYPASS" if {
	some pattern in config.bypass_domains
	helpers.match_domain(input.domain, pattern)
}

# Default action: Intercept through proxy for policy evaluation
default action := "INTERCEPT"

# Future: Could add explicit BLOCK rules here for DNS-level blocking
# action := "BLOCK" if {
#   some pattern in config.dns_block_domains
#   helpers.match_domain(input.domain, pattern)
# }
