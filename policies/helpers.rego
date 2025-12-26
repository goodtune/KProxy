package kproxy.helpers

import rego.v1

# Domain matching with exact, wildcard, and suffix support

# Exact match
match_domain(domain, pattern) if {
	lower(domain) == lower(pattern)
}

# Wildcard match - convert glob pattern to regex
match_domain(domain, pattern) if {
	contains(pattern, "*")
	regex_pattern := concat("", ["^", replace_wildcard(pattern), "$"])
	regex.match(regex_pattern, lower(domain))
}

# Suffix matching - pattern starts with "."
# .example.com matches sub.example.com and example.com
match_domain(domain, pattern) if {
	startswith(pattern, ".")
	suffix := substring(pattern, 1, -1)
	# Either exact match without dot or ends with the pattern
	lower(domain) == lower(suffix)
}

match_domain(domain, pattern) if {
	startswith(pattern, ".")
	endswith(lower(domain), lower(pattern))
}

# Helper to convert glob wildcards to regex
replace_wildcard(pattern) := result if {
	# Quote meta characters except *
	quoted := replace_special_chars(pattern)
	# Replace \* with .*
	result := replace(quoted, "\\*", ".*")
}

# Simplified regex quoting - escape common special chars except *
replace_special_chars(s) := result if {
	s1 := replace(s, ".", "\\.")
	s2 := replace(s1, "+", "\\+")
	s3 := replace(s2, "?", "\\?")
	s4 := replace(s3, "(", "\\(")
	s5 := replace(s4, ")", "\\)")
	s6 := replace(s5, "[", "\\[")
	s7 := replace(s6, "]", "\\]")
	s8 := replace(s7, "{", "\\{")
	s9 := replace(s8, "}", "\\}")
	s10 := replace(s9, "^", "\\^")
	s11 := replace(s10, "$", "\\$")
	result := replace(s11, "|", "\\|")
}

# Time window checking
# Input: current_time = {day_of_week: 0-6, minutes: 0-1439}
# TimeRule: {days_of_week: [0,1,2], start_time: "08:00", end_time: "17:00"}

within_time_window(current_time, time_rule) if {
	# Check day of week
	current_time.day_of_week in time_rule.days_of_week

	# Parse start and end times
	start_minutes := parse_time_to_minutes(time_rule.start_time)
	end_minutes := parse_time_to_minutes(time_rule.end_time)

	# Check if current time is within window
	current_time.minutes >= start_minutes
	current_time.minutes < end_minutes
}

# Parse "HH:MM" to minutes since midnight
parse_time_to_minutes(time_str) := minutes if {
	parts := split(time_str, ":")
	count(parts) == 2
	hours := to_number(parts[0])
	mins := to_number(parts[1])
	minutes := (hours * 60) + mins
}

# Default to 0 if parse fails
parse_time_to_minutes(time_str) := 0 if {
	parts := split(time_str, ":")
	count(parts) != 2
}

# MAC address validation
is_mac_address(identifier) if {
	# Simple MAC validation: contains colons and is alphanumeric with colons
	contains(identifier, ":")
	count(split(identifier, ":")) == 6
}

# CIDR range checking
is_cidr(identifier) if {
	contains(identifier, "/")
}

# Check if IP is in CIDR range
# This is a simplified implementation - for production use OPA's built-in net.cidr_contains
ip_in_cidr(ip, cidr) if {
	# Use OPA's built-in network functions
	net.cidr_contains(cidr, ip)
}

# Path matching with prefix and glob support
match_path(path, rule_paths) if {
	# If rule_paths contains "*", match all paths
	"*" in rule_paths
}

match_path(path, rule_paths) if {
	# Check prefix matching
	some rule_path in rule_paths
	startswith(path, rule_path)
}

match_path(path, rule_paths) if {
	# Glob-style matching
	some rule_path in rule_paths
	contains(rule_path, "*")
	# Convert to regex pattern
	pattern := concat("", ["^", replace_wildcard(rule_path), "$"])
	regex.match(pattern, path)
}

# Lower case utility
lower(s) := lower_result if {
	lower_result := lower(s)
}
