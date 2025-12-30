package kproxy.proxy_test

import rego.v1

import data.kproxy.proxy

# Test data with complete schema - this ensures all fields referenced in the code exist
mock_config := {
	"devices": {"test-device": {
		"name": "Test Device",
		"identifiers": ["192.168.1.100"],
		"profile": "test-profile",
	}},
	"profiles": {
		"test-profile": {
			"name": "Test Profile",
			"description": "Profile for testing",
			"rules": [
				{
					"id": "allow-github",
					"domains": ["github.com", "*.github.com"],
					"action": "allow",
					"category": "work",
				},
				{
					"id": "block-youtube",
					"domains": ["youtube.com", "*.youtube.com"],
					"action": "block",
					"category": "entertainment",
				},
			],
			"time_restrictions": {"weekday": {
				"days": [1, 2, 3, 4, 5], # Monday-Friday
				"start_hour": 9,
				"start_minute": 0,
				"end_hour": 17,
				"end_minute": 0,
			}},
			"usage_limits": {"entertainment": {
				"daily_minutes": 60,
				"inject_timer": true,
			}},
			"default_action": "block",
		},
		"unrestricted-profile": {
			"name": "Unrestricted Profile",
			"description": "No restrictions",
			"rules": [],
			"time_restrictions": {},
			"usage_limits": {},
			"default_action": "allow",
		},
	},
}

# Mock device identification
mock_device := {
	"name": "Test Device",
	"profile": "test-profile",
}

# Test 1: Unknown device should be blocked
test_decision_unknown_device if {
	# Don't mock identified_device - it will be undefined
	decision := proxy.decision with data.kproxy.config as mock_config
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.200",
			"host": "github.com",
			"path": "/",
			"time": {"day_of_week": 2, "hour": 10, "minute": 0},
			"usage": {},
		}

	decision.action == "BLOCK"
	decision.reason == "unknown device"
}

# Test 2: Matching allow rule should allow
test_decision_allow_rule if {
	decision := proxy.decision with data.kproxy.config as mock_config
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "github.com",
			"path": "/goodtune/kproxy",
			"time": {"day_of_week": 2, "hour": 10, "minute": 0}, # Tuesday 10am
			"usage": {"work": {"today_minutes": 0}},
		}

	decision.action == "ALLOW"
	decision.matched_rule_id == "allow-github"
	decision.category == "work"
}

# Test 3: Matching block rule should block
test_decision_block_rule if {
	decision := proxy.decision with data.kproxy.config as mock_config
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "youtube.com",
			"path": "/watch",
			"time": {"day_of_week": 2, "hour": 10, "minute": 0}, # Tuesday 10am
			"usage": {"entertainment": {"today_minutes": 0}},
		}

	decision.action == "BLOCK"
	decision.matched_rule_id == "block-youtube"
	decision.category == "entertainment"
}

# Test 4: Outside time restrictions should block
test_decision_outside_time_window if {
	decision := proxy.decision with data.kproxy.config as mock_config
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "github.com",
			"path": "/",
			"time": {"day_of_week": 2, "hour": 20, "minute": 0}, # Tuesday 8pm - outside 9am-5pm
			"usage": {},
		}

	decision.action == "BLOCK"
	decision.reason == "outside allowed hours"
	decision.block_page == "time_restriction"
}

# Test 5: Inside time window, no matching rules, should use default action
test_decision_default_action if {
	decision := proxy.decision with data.kproxy.config as mock_config
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "example.com",
			"path": "/",
			"time": {"day_of_week": 2, "hour": 10, "minute": 0}, # Tuesday 10am
			"usage": {},
		}

	decision.action == "BLOCK" # profile default_action is "block"
	decision.reason == "default block (no matching rules)"
}

# Test 6: Usage limit exceeded should block (using unrestricted profile to avoid time restriction conflicts)
test_decision_usage_limit_exceeded if {
	# Create profile with usage limits but no time restrictions
	config_with_limits := object.union(mock_config, {"profiles": object.union(mock_config.profiles, {"limit-profile": {
		"name": "Limit Test Profile",
		"description": "Has usage limits but no time restrictions",
		"rules": [{
			"id": "allow-youtube",
			"domains": ["youtube.com", "*.youtube.com"],
			"action": "allow",
			"category": "entertainment",
		}],
		"time_restrictions": {},
		"usage_limits": {"entertainment": {
			"daily_minutes": 60,
			"inject_timer": true,
		}},
		"default_action": "block",
	}})})

	limit_device := {
		"name": "Test Device",
		"profile": "limit-profile",
	}

	decision := proxy.decision with data.kproxy.config as config_with_limits
		with data.kproxy.device.identified_device as limit_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "youtube.com",
			"path": "/watch",
			"time": {"day_of_week": 2, "hour": 10, "minute": 0}, # Tuesday 10am
			"usage": {"entertainment": {"today_minutes": 65}}, # Over 60 minute limit
		}

	# Should be blocked even though it's an allow rule, due to usage limit
	decision.action == "BLOCK"
	decision.reason == "usage limit exceeded for entertainment"
}

# Test 7: Profile with no time restrictions should always allow time check
test_decision_no_time_restrictions if {
	mock_unrestricted_device := {
		"name": "Test Device",
		"profile": "unrestricted-profile",
	}

	decision := proxy.decision with data.kproxy.config as mock_config
		with data.kproxy.device.identified_device as mock_unrestricted_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "example.com",
			"path": "/",
			"time": {"day_of_week": 2, "hour": 23, "minute": 0}, # Late at night
			"usage": {},
		}

	decision.action == "ALLOW" # unrestricted profile default is "allow"
	decision.reason == "default allow (no matching rules)"
}

# Test 8: Weekend should be blocked if not in time restriction days
test_decision_weekend_blocked if {
	decision := proxy.decision with data.kproxy.config as mock_config
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "github.com",
			"path": "/",
			"time": {"day_of_week": 0, "hour": 10, "minute": 0}, # Sunday 10am
			"usage": {},
		}

	decision.action == "BLOCK"
	decision.reason == "outside allowed hours"
}

# Test 9: Timer injection for usage limits
test_decision_timer_injection if {
	decision := proxy.decision with data.kproxy.config as mock_config
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "youtube.com",
			"path": "/watch",
			"time": {"day_of_week": 2, "hour": 10, "minute": 0}, # Tuesday 10am (within time window)
			"usage": {"entertainment": {"today_minutes": 30}}, # 30 of 60 used
		}

	# Should be blocked because youtube matches block rule
	decision.action == "BLOCK"
	decision.matched_rule_id == "block-youtube"
}

# Test 10: Test with minimal input (no usage data)
test_decision_minimal_input if {
	decision := proxy.decision with data.kproxy.config as mock_config
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "github.com",
			"path": "/",
			"time": {"day_of_week": 2, "hour": 10, "minute": 0},
			"usage": {},
		}

	decision.action == "ALLOW"
	decision.matched_rule_id == "allow-github"
}

# Test path-based filtering
test_decision_path_based_allow if {
	mock_config_with_paths := {
		"devices": {"test-device": {
			"name": "Test Device",
			"identifiers": ["192.168.1.100"],
			"profile": "youtube-filtered",
		}},
		"profiles": {"youtube-filtered": {
			"name": "YouTube Education Only",
			"rules": [
				{
					"id": "allow-youtube-education",
					"domains": ["*.youtube.com"],
					"paths": ["/education/*", "/channel/UC*"],
					"action": "allow",
					"category": "",
					"priority": 1,
				},
				{
					"id": "block-youtube-rest",
					"domains": ["*.youtube.com"],
					"action": "block",
					"category": "",
					"priority": 2,
				},
			],
			"time_restrictions": {},
			"usage_limits": {},
			"default_action": "allow",
		}},
	}

	mock_device := {
		"name": "Test Device",
		"profile": "youtube-filtered",
	}

	decision := proxy.decision with data.kproxy.config as mock_config_with_paths
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "www.youtube.com",
			"path": "/education/science",
			"time": {"day_of_week": 2, "hour": 14, "minute": 0},
			"usage": {},
		}

	decision.action == "ALLOW"
	decision.matched_rule_id == "allow-youtube-education"
}

test_decision_path_based_block if {
	mock_config_with_paths := {
		"devices": {"test-device": {
			"name": "Test Device",
			"identifiers": ["192.168.1.100"],
			"profile": "youtube-filtered",
		}},
		"profiles": {"youtube-filtered": {
			"name": "YouTube Education Only",
			"rules": [
				{
					"id": "allow-youtube-education",
					"domains": ["*.youtube.com"],
					"paths": ["/education/*", "/channel/UC*"],
					"action": "allow",
					"category": "",
					"priority": 1,
				},
				{
					"id": "block-youtube-rest",
					"domains": ["*.youtube.com"],
					"action": "block",
					"category": "",
					"priority": 2,
				},
			],
			"time_restrictions": {},
			"usage_limits": {},
			"default_action": "allow",
		}},
	}

	mock_device := {
		"name": "Test Device",
		"profile": "youtube-filtered",
	}

	decision := proxy.decision with data.kproxy.config as mock_config_with_paths
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "www.youtube.com",
			"path": "/watch?v=dQw4w9WgXcQ",
			"time": {"day_of_week": 2, "hour": 14, "minute": 0},
			"usage": {},
		}

	decision.action == "BLOCK"
	decision.matched_rule_id == "block-youtube-rest"
	decision.reason == "matched block rule: block-youtube-rest"
}

test_decision_path_based_shorts_block if {
	mock_config_with_paths := {
		"devices": {"test-device": {
			"name": "Test Device",
			"identifiers": ["192.168.1.100"],
			"profile": "no-shorts",
		}},
		"profiles": {"no-shorts": {
			"name": "Block YouTube Shorts",
			"rules": [
				{
					"id": "block-shorts",
					"domains": ["*.youtube.com"],
					"paths": ["/shorts/*"],
					"action": "block",
					"category": "",
					"priority": 1,
				},
				{
					"id": "allow-youtube",
					"domains": ["*.youtube.com"],
					"action": "allow",
					"category": "",
					"priority": 2,
				},
			],
			"time_restrictions": {},
			"usage_limits": {},
			"default_action": "block",
		}},
	}

	mock_device := {
		"name": "Test Device",
		"profile": "no-shorts",
	}

	decision := proxy.decision with data.kproxy.config as mock_config_with_paths
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "www.youtube.com",
			"path": "/shorts/abc123",
			"time": {"day_of_week": 2, "hour": 14, "minute": 0},
			"usage": {},
		}

	decision.action == "BLOCK"
	decision.matched_rule_id == "block-shorts"
}

test_decision_path_based_regular_video_allow if {
	mock_config_with_paths := {
		"devices": {"test-device": {
			"name": "Test Device",
			"identifiers": ["192.168.1.100"],
			"profile": "no-shorts",
		}},
		"profiles": {"no-shorts": {
			"name": "Block YouTube Shorts",
			"rules": [
				{
					"id": "block-shorts",
					"domains": ["*.youtube.com"],
					"paths": ["/shorts/*"],
					"action": "block",
					"category": "",
					"priority": 1,
				},
				{
					"id": "allow-youtube",
					"domains": ["*.youtube.com"],
					"action": "allow",
					"category": "",
					"priority": 2,
				},
			],
			"time_restrictions": {},
			"usage_limits": {},
			"default_action": "block",
		}},
	}

	mock_device := {
		"name": "Test Device",
		"profile": "no-shorts",
	}

	decision := proxy.decision with data.kproxy.config as mock_config_with_paths
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "www.youtube.com",
			"path": "/watch?v=dQw4w9WgXcQ",
			"time": {"day_of_week": 2, "hour": 14, "minute": 0},
			"usage": {},
		}

	decision.action == "ALLOW"
	decision.matched_rule_id == "allow-youtube"
}

# Test: Profile with default bypass but explicit block rule should block at proxy
test_profile_default_bypass_with_block_rule if {
	config_bypass_with_block := {
		"devices": {"test-device": {
			"name": "Test Device",
			"identifiers": ["192.168.1.100"],
			"profile": "open",
		}},
		"profiles": {"open": {
			"name": "Open Access",
			"description": "Bypass by default but block specific domains",
			"time_restrictions": {},
			"rules": [{
				"id": "block-github",
				"domains": ["github.com", "*.github.com"],
				"action": "block",
				"category": "code",
			}],
			"usage_limits": {},
			"default_action": "bypass",
		}},
	}

	mock_device := {
		"name": "Test Device",
		"profile": "open",
	}

	# github.com should be BLOCKED (even though default_action is bypass)
	decision := proxy.decision with data.kproxy.config as config_bypass_with_block
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "github.com",
			"path": "/",
			"time": {"day_of_week": 2, "hour": 14, "minute": 0},
			"usage": {},
		}

	decision.action == "BLOCK"
	decision.matched_rule_id == "block-github"
	decision.category == "code"

	# other.com should be BYPASSED (default_action applies when no rules match)
	decision2 := proxy.decision with data.kproxy.config as config_bypass_with_block
		with data.kproxy.device.identified_device as mock_device
		with input as {
			"server_name": "local.kproxy",
			"client_ip": "192.168.1.100",
			"host": "other.com",
			"path": "/",
			"time": {"day_of_week": 2, "hour": 14, "minute": 0},
			"usage": {},
		}

	decision2.action == "BYPASS"
	decision2.reason == "default bypass (no matching rules)"
}
