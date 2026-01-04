package kproxy.dns

import rego.v1

import data.kproxy.config
import data.kproxy.device
import data.kproxy.helpers

# DNS Action Decision
# Returns a structured decision with action and reason
#
# Input structure (facts only):
# {
#   "client_ip": "192.168.1.100",
#   "client_mac": "aa:bb:cc:dd:ee:ff",  // optional
#   "domain": "youtube.com"
# }
#
# Output structure:
# {
#   "action": "BYPASS" | "INTERCEPT" | "BLOCK",
#   "reason": "description of why this decision was made"
# }
#
# Configuration comes from data.kproxy.config

# Helper: Check if domain matches global bypass
global_bypass if {
	some pattern in config.bypass_domains
	helpers.match_domain(input.domain, pattern)
}

# Helper: Check if profile has a rule with specific action
profile_has_rule_with_action(action_to_check) if {
	dev := device.identified_device
	profile := config.profiles[dev.profile]
	some rule in profile.rules
	rule.action == action_to_check
	some domain_pattern in rule.domains
	helpers.match_domain(input.domain, domain_pattern)
}

# Helper: Check if profile has ANY rule that matches (regardless of action)
profile_has_matching_rule if {
	dev := device.identified_device
	profile := config.profiles[dev.profile]
	some rule in profile.rules
	some domain_pattern in rule.domains
	helpers.match_domain(input.domain, domain_pattern)
}

# Helper: Check if profile has default bypass
profile_default_bypass if {
	dev := device.identified_device
	profile := config.profiles[dev.profile]
	profile.default_action == "bypass"
}

# Priority 0: Always intercept server name for client setup
decision := {
	"action": "INTERCEPT",
	"reason": "kproxy server name (client setup)",
} if {
	helpers.match_domain(input.domain, input.server_name)
}

# Priority 1: Global bypass domains (system-critical services)
decision := {
	"action": "BYPASS",
	"reason": "global bypass domain",
} if {
	not helpers.match_domain(input.domain, input.server_name)
	global_bypass
}

# Priority 2: Profile rule with "bypass" action
decision := {
	"action": "BYPASS",
	"reason": "profile rule action is bypass",
} if {
	not helpers.match_domain(input.domain, input.server_name)
	not global_bypass
	profile_has_rule_with_action("bypass")
}

# Priority 3: Profile has a matching rule (block/allow) → INTERCEPT for proxy evaluation
decision := {
	"action": "INTERCEPT",
	"reason": "profile has matching rule requiring proxy evaluation",
} if {
	not helpers.match_domain(input.domain, input.server_name)
	not global_bypass
	not profile_has_rule_with_action("bypass")
	profile_has_matching_rule
}

# Priority 4: Profile default bypass (only if no rules matched)
decision := {
	"action": "BYPASS",
	"reason": "profile default action is bypass",
} if {
	not helpers.match_domain(input.domain, input.server_name)
	not global_bypass
	not profile_has_rule_with_action("bypass")
	not profile_has_matching_rule
	profile_default_bypass
}

# Default action: Intercept through proxy for policy evaluation
default decision := {
	"action": "INTERCEPT",
	"reason": "default intercept for policy evaluation",
}

# Future: Could add explicit BLOCK rules here for DNS-level blocking
# action := "BLOCK" if {
#   some pattern in config.dns_block_domains
#   helpers.match_domain(input.domain, pattern)
# }
