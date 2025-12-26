package kproxy.usage

import rego.v1

import data.kproxy.helpers

# Usage limit evaluation
# Input structure:
# {
#   "host": "youtube.com",
#   "category": "entertainment",  // from matched rule
#   "usage_limits": [
#     {
#       "id": "limit-1",
#       "category": "entertainment",
#       "domains": ["youtube.com", "netflix.com"],
#       "daily_minutes": 60,
#       "reset_time": "00:00",
#       "inject_timer": true
#     }
#   ],
#   "usage_stats": {
#     "limit-1": {
#       "today_usage_minutes": 45,
#       "remaining_minutes": 15,
#       "limit_exceeded": false
#     }
#   }
# }

# Find applicable limits
applicable_limits contains limit if {
	some limit in input.usage_limits

	# Match by category
	limit.category != ""
	limit.category == input.category
}

applicable_limits contains limit if {
	some limit in input.usage_limits

	# Match by specific domain
	some domain in limit.domains
	helpers.match_domain(input.host, domain)
}

# Check if any limit is exceeded
limit_exceeded(limit_id) if {
	stats := input.usage_stats[limit_id]
	stats.limit_exceeded == true
}

# Get first exceeded limit (for decision making)
first_exceeded_limit := limit if {
	some limit in applicable_limits
	limit_exceeded(limit.id)
	# Return first one found
} {
	# This syntax returns the first match
	limit := [l | some l in applicable_limits; limit_exceeded(l.id)][0]
}

# Check if should inject timer
should_inject_timer if {
	some limit in applicable_limits
	limit.inject_timer == true
	not limit_exceeded(limit.id)
}

# Get remaining time for timer display
remaining_time := minutes if {
	# Find first applicable limit with timer injection
	some limit in applicable_limits
	limit.inject_timer == true
	stats := input.usage_stats[limit.id]
	minutes := stats.remaining_minutes
}
