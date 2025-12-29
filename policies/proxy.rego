package kproxy.proxy

import rego.v1

import data.kproxy.config
import data.kproxy.device
import data.kproxy.helpers

# Proxy Request Evaluation
# Makes ALLOW/BLOCK decisions based on facts and configuration
#
# Input structure (facts only):
# {
#   "client_ip": "192.168.1.100",
#   "client_mac": "aa:bb:cc:dd:ee:ff",  // optional
#   "host": "youtube.com",
#   "path": "/watch",
#   "time": {
#     "day_of_week": 2,    // 0=Sunday, 1=Monday, etc.
#     "hour": 16,          // 0-23
#     "minute": 30         // 0-59
#   },
#   "usage": {  // Current usage from database
#     "entertainment": {"today_minutes": 45}
#   }
# }
#
# Configuration comes from data.kproxy.config

# Decision 1: Block unknown devices
decision := {
	"action": "BLOCK",
	"reason": "unknown device",
	"block_page": "unknown_device",
	"matched_rule_id": "",
	"category": "",
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	not device.identified_device
}

# Decision 2: Block if profile not found (should not happen with proper config)
decision := {
	"action": "BLOCK",
	"reason": "profile not configured",
	"block_page": "config_error",
	"matched_rule_id": "",
	"category": "",
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	dev := device.identified_device
	not config.profiles[dev.profile]
}

# Decision 3: Block if outside allowed time window
decision := {
	"action": "BLOCK",
	"reason": "outside allowed hours",
	"block_page": "time_restriction",
	"matched_rule_id": "",
	"category": "",
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	dev := device.identified_device
	profile := config.profiles[dev.profile]

	# Has time restrictions and currently outside allowed window
	count(profile.time_restrictions) > 0
	not within_allowed_time(profile.time_restrictions, input.time)
}

# Decision 4: Evaluate rules (priority order)
decision := result if {
	dev := device.identified_device
	profile := config.profiles[dev.profile]

	# Within allowed time (or no time restrictions)
	count(profile.time_restrictions) == 0
} else := result if {
	dev := device.identified_device
	profile := config.profiles[dev.profile]
	within_allowed_time(profile.time_restrictions, input.time)
} else := result if {
	dev := device.identified_device
	profile := config.profiles[dev.profile]

	# Find first matching rule
	rule := first_matching_rule(profile.rules, input.host, input.path)

	# Evaluate rule
	result := evaluate_rule(rule, profile)
}

# Decision 5: Default action (no matching rules)
decision := {
	"action": action,
	"reason": sprintf("default %s (no matching rules)", [lower(action)]),
	"block_page": block_page,
	"matched_rule_id": "",
	"category": "",
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	dev := device.identified_device
	profile := config.profiles[dev.profile]

	# No matching rules
	not first_matching_rule(profile.rules, input.host, input.path)

	# Use profile default action
	action := upper(profile.default_action)
	block_page := default_block_page(action)
}

# Helper: Check if current time is within any allowed window
within_allowed_time(restrictions, current_time) if {
	some window_name, window in restrictions
	within_time_window(window, current_time)
}

# Helper: Check if time is within a specific window
within_time_window(window, current_time) if {
	# Check day of week
	current_time.day_of_week in window.days

	# Calculate minutes since midnight
	current_minutes := (current_time.hour * 60) + current_time.minute
	start_minutes := (window.start_hour * 60) + window.start_minute
	end_minutes := (window.end_hour * 60) + window.end_minute

	# Within time range
	current_minutes >= start_minutes
	current_minutes < end_minutes
}

# Helper: Find first matching rule (rules are evaluated in order)
first_matching_rule(rules, host, path) := rule if {
	some rule in rules
	matches_rule(rule, host, path)
}

# Helper: Check if request matches a rule
matches_rule(rule, host, path) if {
	# Check if domain matches any in the rule
	some domain_pattern in rule.domains
	helpers.match_domain(host, domain_pattern)
}

# Helper: Evaluate a matched rule
evaluate_rule(rule, profile) := {
	"action": "BLOCK",
	"reason": sprintf("usage limit exceeded for %s", [rule.category]),
	"block_page": "usage_limit",
	"matched_rule_id": rule.id,
	"category": rule.category,
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": usage_category_id(rule.category),
} if {
	rule.action == "allow"
	rule.category != ""

	# Check if usage limit exists and is exceeded
	usage_limit_exceeded(profile, rule.category)
}

evaluate_rule(rule, profile) := {
	"action": "ALLOW",
	"reason": sprintf("matched rule: %s", [rule.id]),
	"block_page": "",
	"matched_rule_id": rule.id,
	"category": rule.category,
	"inject_timer": inject,
	"time_remaining_minutes": remaining,
	"usage_limit_id": limit_id,
} if {
	rule.action == "allow"

	# Not exceeded or no usage limit
	not usage_limit_exceeded(profile, rule.category)

	# Get usage limit info if exists
	inject := should_inject_timer(profile, rule.category)
	remaining := remaining_time(profile, rule.category)
	limit_id := usage_category_id(rule.category)
}

evaluate_rule(rule, profile) := {
	"action": "BLOCK",
	"reason": sprintf("matched block rule: %s", [rule.id]),
	"block_page": block_page_for_category(rule.category),
	"matched_rule_id": rule.id,
	"category": rule.category,
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	rule.action == "block"
}

# Helper: Check if usage limit is exceeded
usage_limit_exceeded(profile, category) if {
	category != ""
	limit := profile.usage_limits[category]
	used := input.usage[category].today_minutes
	used >= limit.daily_minutes
}

# Helper: Should inject timer overlay
should_inject_timer(profile, category) := inject if {
	category != ""
	limit := profile.usage_limits[category]
	inject := limit.inject_timer
}

should_inject_timer(profile, category) := false if {
	category == ""
}

should_inject_timer(profile, category) := false if {
	not profile.usage_limits[category]
}

# Helper: Calculate remaining time
remaining_time(profile, category) := remaining if {
	category != ""
	limit := profile.usage_limits[category]
	used := input.usage[category].today_minutes
	remaining := max([0, limit.daily_minutes - used])
}

remaining_time(profile, category) := 0 if {
	category == ""
}

remaining_time(profile, category) := 0 if {
	not profile.usage_limits[category]
}

# Helper: Get usage category ID for tracking
usage_category_id(category) := category if {
	category != ""
}

usage_category_id(category) := "" if {
	category == ""
}

# Helper: Get block page type
block_page_for_category(category) := "category_block" if {
	category != ""
}

block_page_for_category(category) := "default_block" if {
	category == ""
}

default_block_page(action) := "default_block" if {
	action == "BLOCK"
}

default_block_page(action) := "" if {
	action == "ALLOW"
}
