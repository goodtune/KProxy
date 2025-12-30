package kproxy.dns_test

import rego.v1

import data.kproxy.dns

# Test configuration
mock_config := {"bypass_domains": [
	"ocsp.apple.com",
	"*.ocsp.digicert.com",
	".crl.example.com",
]}

# Test 1: Bypass domain - exact match
test_action_bypass_exact if {
	result := dns.decision with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "ocsp.apple.com",
		}

	result.action == "BYPASS"
	result.reason == "global bypass domain"
}

# Test 2: Bypass domain - wildcard match
test_action_bypass_wildcard if {
	result := dns.decision with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "api.ocsp.digicert.com",
		}

	result.action == "BYPASS"
	result.reason == "global bypass domain"
}

# Test 3: Bypass domain - suffix match
test_action_bypass_suffix if {
	result := dns.decision with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "www.crl.example.com",
		}

	result.action == "BYPASS"
	result.reason == "global bypass domain"
}

# Test 4: Bypass domain - exact suffix match
test_action_bypass_suffix_exact if {
	result := dns.decision with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "crl.example.com",
		}

	result.action == "BYPASS"
	result.reason == "global bypass domain"
}

# Test 5: Non-bypass domain - should intercept
test_action_intercept if {
	result := dns.decision with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "www.example.com",
		}

	result.action == "INTERCEPT"
	result.reason == "default intercept for policy evaluation"
}

# Test 6: Empty bypass list - all domains intercepted
test_action_intercept_empty_bypass if {
	empty_config := {"bypass_domains": []}

	result := dns.decision with data.kproxy.config as empty_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "any.domain.com",
		}

	result.action == "INTERCEPT"
	result.reason == "default intercept for policy evaluation"
}

# Test 7: Multiple bypass patterns
test_action_bypass_multiple_patterns if {
	multi_config := {"bypass_domains": [
		"exact.com",
		"*.wildcard.com",
		".suffix.com",
	]}

	# Test exact
	result1 := dns.decision with data.kproxy.config as multi_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "exact.com",
		}
	result1.action == "BYPASS"
	result1.reason == "global bypass domain"

	# Test wildcard
	result2 := dns.decision with data.kproxy.config as multi_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "sub.wildcard.com",
		}
	result2.action == "BYPASS"
	result2.reason == "global bypass domain"

	# Test suffix
	result3 := dns.decision with data.kproxy.config as multi_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "www.suffix.com",
		}
	result3.action == "BYPASS"
	result3.reason == "global bypass domain"
}

# Test 8: Case insensitivity
test_action_bypass_case_insensitive if {
	result := dns.decision with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "OCSP.APPLE.COM",
		}

	result.action == "BYPASS"
	result.reason == "global bypass domain"
}

# Test 9: Subdomain not matching wildcard parent
test_action_intercept_subdomain_no_match if {
	result := dns.decision with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "ocsp.digicert.com", # No wildcard prefix
		}

	# Should NOT match *.ocsp.digicert.com
	result.action == "INTERCEPT"
}

# Test 10: Very long domain name
test_action_intercept_long_domain if {
	result := dns.decision with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "very.long.subdomain.example.domain.name.test.com",
		}

	result.action == "INTERCEPT"
}

# Test 11: IPv4 address as domain (shouldn't bypass unless configured)
test_action_intercept_ip_address if {
	result := dns.decision with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "1.2.3.4",
		}

	result.action == "INTERCEPT"
}

# Test 12: Special characters in domain
test_action_intercept_special_chars if {
	result := dns.decision with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "my-site.example.com",
		}

	result.action == "INTERCEPT"
}

# Test 13: Single label domain
test_action_intercept_single_label if {
	result := dns.decision with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "localhost",
		}

	result.action == "INTERCEPT"
}

# Test 14: Bypass with suffix pattern
test_action_bypass_suffix_comprehensive if {
	comprehensive_config := {"bypass_domains": [
		".apple.com",
		"google.com",
	]}

	# Test .apple.com suffix
	result1 := dns.decision with data.kproxy.config as comprehensive_config
		with input as {"domain": "www.apple.com"}
	result1.action == "BYPASS"
	result1.reason == "global bypass domain"

	# Test exact match
	result2 := dns.decision with data.kproxy.config as comprehensive_config
		with input as {"domain": "google.com"}
	result2.action == "BYPASS"
	result2.reason == "global bypass domain"
}

# Test 15: Bypass for a whole profile
test_action_bypass_by_profile if {
	comprehensive_config := {
		"devices": {"open-network": {
			"name": "open network",
			"identifiers": ["192.168.1.0/24"],
			"profile": "open",
		}},
		"profiles": {"open": {
			"name": "Open Access",
			"description": "Bypass everything, get out of the way!",
			"time_restrictions": {},
			"rules": [],
			"usage_limits": {},
			"default_action": "bypass",
		}},
		"bypass_domains": [],
	}

	result := dns.decision with data.kproxy.config as comprehensive_config
		with input as {
			"client_ip": "192.168.1.50",
			"client_mac": "",
			"domain": "example.com",
		}
	result.action == "BYPASS"
	result.reason == "profile default action is bypass"
}

# Test 16: Bypass in a rule
test_action_bypass_by_rule if {
	comprehensive_config := {
		"devices": {"coder-network": {
			"name": "coder network",
			"identifiers": ["192.168.3.0/24"],
			"profile": "coder",
		}},
		"profiles": {"coder": {
			"name": "Coder Access",
			"description": "Bypass all of GitHub block anything else.",
			"time_restrictions": {},
			"rules": [{
				"id": "allow-github",
				"domains": ["github.com", "*.github.com"],
				"action": "bypass",
				"category": "work",
			}],
			"usage_limits": {},
			"default_action": "block",
		}},
		"bypass_domains": [],
	}

	result := dns.decision with data.kproxy.config as comprehensive_config
		with input as {
			"client_ip": "192.168.3.50",
			"client_mac": "",
			"domain": "github.com",
		}
	result.action == "BYPASS"
	result.reason == "profile rule action is bypass"
}

# Test 17: Profile with default bypass but explicit block rule should INTERCEPT
test_profile_bypass_with_block_rule_intercepts if {
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
		"bypass_domains": [],
	}

	# github.com should INTERCEPT (not bypass) because there's an explicit rule
	result := dns.decision with data.kproxy.config as config_bypass_with_block
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "github.com",
		}
	result.action == "INTERCEPT"
	result.reason == "profile has matching rule requiring proxy evaluation"

	# other.com should BYPASS because no rule matches and default_action is bypass
	result2 := dns.decision with data.kproxy.config as config_bypass_with_block
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "other.com",
		}
	result2.action == "BYPASS"
	result2.reason == "profile default action is bypass"
}
