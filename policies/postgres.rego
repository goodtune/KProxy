package kproxy.postgres

import rego.v1

import data.kproxy.config
import data.kproxy.device
import data.kproxy.helpers

# PostgreSQL Connection Evaluation
# Makes ALLOW/BLOCK decisions for PostgreSQL connections
#
# Input structure (facts only):
# {
#   "client_ip": "192.168.1.100",
#   "client_mac": "aa:bb:cc:dd:ee:ff",  // optional
#   "database": "myapp",
#   "username": "appuser"
# }
#
# Output structure:
# {
#   "action": "ALLOW" | "BLOCK",
#   "reason": "description of why this decision was made",
#   "matched_rule_id": "rule-id",
#   "category": "database-category"
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

# Decision 2: Block if profile not found
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

# Decision 4: Check PostgreSQL-specific rules
decision := result if {
	dev := device.identified_device
	profile := config.profiles[dev.profile]

	# Time is allowed (or no time restrictions)
	count(profile.time_restrictions) == 0
	or within_allowed_time(profile.time_restrictions, input.time)

	# Get PostgreSQL rules
	postgres_rules := [rule |
		some rule in profile.postgres_rules
	]

	# Evaluate PostgreSQL rules
	some rule in postgres_rules
	match_postgres_rule(rule, input.database, input.username)
	result := evaluate_postgres_rule(rule, dev.id, dev.name)
}

# Decision 5: Apply default profile action
decision := {
	"action": default_action,
	"reason": sprintf("profile default action: %s", [profile.default_action]),
	"block_page": "",
	"matched_rule_id": "",
	"category": "",
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	dev := device.identified_device
	profile := config.profiles[dev.profile]

	# Time is allowed (or no time restrictions)
	count(profile.time_restrictions) == 0
	or within_allowed_time(profile.time_restrictions, input.time)

	# No PostgreSQL rules matched
	postgres_rules := [rule |
		some rule in profile.postgres_rules
	]
	not any([match_postgres_rule(rule, input.database, input.username) | some rule in postgres_rules])

	# Use profile default action
	default_action := upper(profile.default_action)
}

# Default fallback: block
default decision := {
	"action": "BLOCK",
	"reason": "no matching rule, default deny",
	"block_page": "",
	"matched_rule_id": "",
	"category": "",
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
}

# Helper: Check if within allowed time
within_allowed_time(time_restrictions, current_time) if {
	some restriction in time_restrictions

	# Check if current day matches
	some day in restriction.days
	day == current_time.day_of_week

	# Check if current time is within window
	current_minutes := (current_time.hour * 60) + current_time.minute
	start_minutes := restriction.start_hour * 60
	end_minutes := restriction.end_hour * 60

	current_minutes >= start_minutes
	current_minutes < end_minutes
}

# Helper: Check if PostgreSQL rule matches
match_postgres_rule(rule, database, username) if {
	# Match database pattern
	some db_pattern in rule.databases
	match_postgres_pattern(db_pattern, database)

	# Match username pattern (if specified)
	count(rule.usernames) == 0 # No username restriction
	or match_postgres_username(rule.usernames, username)
}

# Helper: Match PostgreSQL pattern (supports wildcards)
match_postgres_pattern(pattern, value) if {
	pattern == "*"
}

match_postgres_pattern(pattern, value) if {
	pattern == value
}

match_postgres_pattern(pattern, value) if {
	startswith(pattern, "*")
	endswith(value, trim_prefix(pattern, "*"))
}

match_postgres_pattern(pattern, value) if {
	endswith(pattern, "*")
	startswith(value, trim_prefix(pattern, "*"))
}

# Helper: Match PostgreSQL username
match_postgres_username(usernames, username) if {
	some user_pattern in usernames
	match_postgres_pattern(user_pattern, username)
}

# Helper: Evaluate PostgreSQL rule and return decision
evaluate_postgres_rule(rule, device_id, device_name) := result if {
	result := {
		"action": upper(rule.action),
		"reason": sprintf("matched postgres rule: %s", [rule.id]),
		"block_page": "",
		"matched_rule_id": rule.id,
		"category": rule.category,
		"inject_timer": false,
		"time_remaining_minutes": 0,
		"usage_limit_id": "",
	}
}
