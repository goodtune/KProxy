package kproxy.time

import rego.v1

import data.kproxy.helpers

# Time-based access control
# Input structure:
# {
#   "current_time": {
#     "day_of_week": 2,  // 0=Sunday, 6=Saturday
#     "minutes": 540     // Minutes since midnight (9:00 AM = 540)
#   },
#   "time_rules": [
#     {
#       "id": "time-rule-1",
#       "days_of_week": [1, 2, 3, 4, 5],  // Monday-Friday
#       "start_time": "08:00",
#       "end_time": "21:00",
#       "rule_ids": []  // Empty means applies to all rules
#     }
#   ]
# }

# Main decision - is access allowed based on time?
allowed if {
	# If no time rules, always allowed
	count(input.time_rules) == 0
}

allowed if {
	# Check if current time falls within any allowed window
	some rule in input.time_rules
	helpers.within_time_window(input.current_time, rule)
}

# Helper to check specific rule ID (for future use with rule-specific time windows)
allowed_for_rule(rule_id) if {
	# If no time rules, always allowed
	count(input.time_rules) == 0
}

allowed_for_rule(rule_id) if {
	some time_rule in input.time_rules

	# Check if this time rule applies to this specific rule
	applies_to_rule(time_rule, rule_id)

	# Check if we're within the time window
	helpers.within_time_window(input.current_time, time_rule)
}

# Check if time rule applies to specific rule ID
applies_to_rule(time_rule, rule_id) if {
	# If rule_ids is empty, applies to all
	count(time_rule.rule_ids) == 0
}

applies_to_rule(time_rule, rule_id) if {
	# If rule_ids specified, check if rule_id is in the list
	rule_id in time_rule.rule_ids
}
