package kproxy.proxy

import rego.v1

import data.kproxy.device
import data.kproxy.helpers
import data.kproxy.time as time_policy
import data.kproxy.usage

# Proxy Request Evaluation
# Input structure:
# {
#   "client_ip": "192.168.1.100",
#   "client_mac": "aa:bb:cc:dd:ee:ff",
#   "host": "youtube.com",
#   "path": "/watch",
#   "method": "GET",
#   "user_agent": "Mozilla/5.0...",
#   "encrypted": true,
#   "current_time": {
#     "day_of_week": 2,
#     "minutes": 540
#   },
#   "devices": {...},
#   "profiles": {
#     "profile-1": {
#       "id": "profile-1",
#       "name": "Child Profile",
#       "default_allow": false,
#       "rules": [
#         {
#           "id": "rule-1",
#           "domain": "youtube.com",
#           "paths": ["/watch"],
#           "action": "ALLOW",
#           "priority": 100,
#           "category": "entertainment",
#           "inject_timer": false
#         }
#       ],
#       "time_rules": [...],
#       "usage_limits": [...]
#     }
#   },
#   "usage_stats": {...},
#   "use_mac_address": true,
#   "default_action": "BLOCK"
# }

# Main decision output
decision := {
	"action": "BLOCK",
	"reason": "unknown device",
	"block_page": "default_block",
	"matched_rule_id": "",
	"category": "",
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	not device.identified_device
}

decision := {
	"action": "BLOCK",
	"reason": "no profile assigned",
	"block_page": "default_block",
	"matched_rule_id": "",
	"category": "",
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	identified := device.identified_device
	not input.profiles[identified.profile_id]
}

decision := {
	"action": "BLOCK",
	"reason": "outside allowed hours",
	"block_page": "time_restriction",
	"matched_rule_id": matched.id,
	"category": matched.category,
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	identified := device.identified_device
	profile := input.profiles[identified.profile_id]

	# Find matching rule (must exist)
	matched := first_matching_rule(profile)
	matched # Ensure matched is defined

	# Check time restriction for this specific rule
	not time_allowed_for_rule(profile, matched.id)
}

decision := result if {
	identified := device.identified_device
	profile := input.profiles[identified.profile_id]

	# Find matching rule (must exist)
	matched := first_matching_rule(profile)
	matched # Ensure matched is defined

	# Check time restriction for this specific rule
	time_allowed_for_rule(profile, matched.id)

	# Evaluate based on rule action
	result := evaluate_rule(matched, profile)
}

decision := {
	"action": action,
	"reason": "default allow",
	"block_page": "",
	"matched_rule_id": "",
	"category": "",
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	identified := device.identified_device
	profile := input.profiles[identified.profile_id]
	not first_matching_rule(profile)
	profile.default_allow
	action := "ALLOW"
}

decision := {
	"action": action,
	"reason": "default deny",
	"block_page": "default_block",
	"matched_rule_id": "",
	"category": "",
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	identified := device.identified_device
	profile := input.profiles[identified.profile_id]
	not first_matching_rule(profile)
	not profile.default_allow
	action := "BLOCK"
}

# Check if time is allowed for a specific rule
# If no time rules apply to this rule, it's always allowed
time_allowed_for_rule(profile, rule_id) if {
	# No time rules at all
	count(profile.time_rules) == 0
}

time_allowed_for_rule(profile, rule_id) if {
	# Has time rules, but none apply to this specific rule
	count(profile.time_rules) > 0
	not any_time_rule_applies(profile.time_rules, rule_id)
}

time_allowed_for_rule(profile, rule_id) if {
	# Has time rules that apply, check if current time is within allowed window
	count(profile.time_rules) > 0
	some time_rule in profile.time_rules
	applies_to_rule(time_rule, rule_id)
	helpers.within_time_window(input.current_time, time_rule)
}

# Check if any time rule applies to this rule ID
any_time_rule_applies(time_rules, rule_id) if {
	some time_rule in time_rules
	applies_to_rule(time_rule, rule_id)
}

# Check if time rule applies to specific rule ID
applies_to_rule(time_rule, rule_id) if {
	# If rule_ids is empty, applies to all rules
	count(time_rule.rule_ids) == 0
}

applies_to_rule(time_rule, rule_id) if {
	# If rule_ids specified, check if rule_id is in the list
	rule_id in time_rule.rule_ids
}

# Find first matching rule (by priority order - already sorted descending)
first_matching_rule(profile) := rule if {
	# Get all matching rules
	matching := [r | some r in profile.rules; matches_rule(r)]
	count(matching) > 0
	# Return first match (rules are already sorted by priority descending)
	rule := matching[0]
}

# Check if request matches a rule
matches_rule(rule) if {
	# Domain must match
	helpers.match_domain(input.host, rule.domain)

	# Path must match
	helpers.match_path(input.path, rule.paths)
}

# Evaluate a matched rule
evaluate_rule(rule, profile) := {
	"action": "BLOCK",
	"reason": reason,
	"block_page": "usage_limit",
	"matched_rule_id": rule.id,
	"category": rule.category,
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": limit_id,
} if {
	rule.action == "ALLOW"

	# Check usage limits
	usage_input := {
		"host": input.host,
		"category": rule.category,
		"usage_limits": profile.usage_limits,
		"usage_stats": input.usage_stats,
	}

	exceeded := usage.first_exceeded_limit with input as usage_input
	limit_id := exceeded.id
	used := input.usage_stats[limit_id].today_usage_minutes
	limit := exceeded.daily_minutes
	reason := sprintf("daily usage limit exceeded: %dm/%dm used", [used, limit])
}

evaluate_rule(rule, profile) := {
	"action": "ALLOW",
	"reason": sprintf("matched rule: %s", [rule.id]),
	"block_page": "",
	"matched_rule_id": rule.id,
	"category": rule.category,
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	rule.action == "ALLOW"

	# No usage limits or not exceeded
	usage_input := {
		"host": input.host,
		"category": rule.category,
		"usage_limits": profile.usage_limits,
		"usage_stats": input.usage_stats,
	}

	# Not exceeded
	not usage.first_exceeded_limit with input as usage_input
}

evaluate_rule(rule, profile) := {
	"action": rule.action,
	"reason": sprintf("matched rule: %s", [rule.id]),
	"block_page": get_block_page(rule),
	"matched_rule_id": rule.id,
	"category": rule.category,
	"inject_timer": rule.inject_timer,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	rule.action == "BLOCK"
}

evaluate_rule(rule, profile) := {
	"action": rule.action,
	"reason": sprintf("matched rule: %s", [rule.id]),
	"block_page": "",
	"matched_rule_id": rule.id,
	"category": rule.category,
	"inject_timer": false,
	"time_remaining_minutes": 0,
	"usage_limit_id": "",
} if {
	rule.action == "BYPASS"
}

# Helper: get remaining time
get_remaining_time(usage_input, inject_timer) := remaining if {
	inject_timer
	remaining := usage.remaining_time with input as usage_input
}

get_remaining_time(usage_input, inject_timer) := 0 if {
	not inject_timer
}

# Helper: get limit ID
get_limit_id(profile, category) := limit_id if {
	category != ""
	some limit in profile.usage_limits
	limit.category == category
	limit_id := limit.id
} else := ""

# Helper: construct allow reason
construct_allow_reason(rule, remaining, profile) := reason if {
	remaining > 0
	some limit in profile.usage_limits
	limit.category == rule.category
	reason := sprintf("usage limit: %dm remaining of %dm", [remaining, limit.daily_minutes])
} else := sprintf("matched rule: %s", [rule.id])

# Helper: determine block page type
get_block_page(rule) := "category_block" if {
	rule.category != ""
} else := "default_block"
