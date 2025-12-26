package kproxy.dns

import rego.v1

import data.kproxy.device
import data.kproxy.helpers

# DNS Action Decision
# Input structure:
# {
#   "client_ip": "192.168.1.100",
#   "domain": "youtube.com",
#   "global_bypass": ["ocsp.*.com", "*.apple.com"],
#   "bypass_rules": [
#     {
#       "id": "bypass-1",
#       "domain": "banking.example.com",
#       "enabled": true,
#       "device_ids": []  // empty = applies to all
#     }
#   ],
#   "devices": {...},  // device map for identification
#   "use_mac_address": true
# }

# Main decision - returns "INTERCEPT", "BYPASS", or "BLOCK"
action := "BYPASS" if {
	# Check global bypass patterns (system-critical)
	some pattern in input.global_bypass
	helpers.match_domain(input.domain, pattern)
}

action := "BYPASS" if {
	# Check device-specific bypass rules
	some rule in input.bypass_rules
	rule.enabled
	applies_to_device(rule)
	helpers.match_domain(input.domain, rule.domain)
}

action := "BLOCK" if {
	# Explicit block rules (if we add them in future)
	false # placeholder - not implemented yet
}

# Default action: intercept and route through proxy
default action := "INTERCEPT"

# Check if bypass rule applies to current device
applies_to_device(rule) if {
	# If device_ids is empty, rule applies to all
	count(rule.device_ids) == 0
}

applies_to_device(rule) if {
	# If device_ids is specified, check if device matches
	count(rule.device_ids) > 0
	identified := device.identified_device
	identified.id in rule.device_ids
}

# Helper: check if no device identified
no_device_identified if {
	not device.identified_device
}
