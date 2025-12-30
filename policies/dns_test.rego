package kproxy.dns_test

import rego.v1

import data.kproxy.dns

# Test configuration
mock_config := {
	"bypass_domains": [
		"ocsp.apple.com",
		"*.ocsp.digicert.com",
		".crl.example.com",
	],
}

# Test 1: Bypass domain - exact match
test_action_bypass_exact if {
	action := dns.action with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "ocsp.apple.com",
		}

	action == "BYPASS"
}

# Test 2: Bypass domain - wildcard match
test_action_bypass_wildcard if {
	action := dns.action with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "api.ocsp.digicert.com",
		}

	action == "BYPASS"
}

# Test 3: Bypass domain - suffix match
test_action_bypass_suffix if {
	action := dns.action with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "www.crl.example.com",
		}

	action == "BYPASS"
}

# Test 4: Bypass domain - exact suffix match
test_action_bypass_suffix_exact if {
	action := dns.action with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "crl.example.com",
		}

	action == "BYPASS"
}

# Test 5: Non-bypass domain - should intercept
test_action_intercept if {
	action := dns.action with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "www.example.com",
		}

	action == "INTERCEPT"
}

# Test 6: Empty bypass list - all domains intercepted
test_action_intercept_empty_bypass if {
	empty_config := {"bypass_domains": []}

	action := dns.action with data.kproxy.config as empty_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
			"domain": "any.domain.com",
		}

	action == "INTERCEPT"
}

# Test 7: Multiple bypass patterns
test_action_bypass_multiple_patterns if {
	multi_config := {
		"bypass_domains": [
			"exact.com",
			"*.wildcard.com",
			".suffix.com",
		],
	}

	# Test exact
	action1 := dns.action with data.kproxy.config as multi_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "exact.com",
		}
	action1 == "BYPASS"

	# Test wildcard
	action2 := dns.action with data.kproxy.config as multi_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "sub.wildcard.com",
		}
	action2 == "BYPASS"

	# Test suffix
	action3 := dns.action with data.kproxy.config as multi_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "www.suffix.com",
		}
	action3 == "BYPASS"
}

# Test 8: Case insensitivity
test_action_bypass_case_insensitive if {
	action := dns.action with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "OCSP.APPLE.COM",
		}

	action == "BYPASS"
}

# Test 9: Subdomain not matching wildcard parent
test_action_intercept_subdomain_no_match if {
	action := dns.action with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "ocsp.digicert.com", # No wildcard prefix
		}

	# Should NOT match *.ocsp.digicert.com
	action == "INTERCEPT"
}

# Test 10: Very long domain name
test_action_intercept_long_domain if {
	action := dns.action with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "very.long.subdomain.example.domain.name.test.com",
		}

	action == "INTERCEPT"
}

# Test 11: IPv4 address as domain (shouldn't bypass unless configured)
test_action_intercept_ip_address if {
	action := dns.action with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "1.2.3.4",
		}

	action == "INTERCEPT"
}

# Test 12: Special characters in domain
test_action_intercept_special_chars if {
	action := dns.action with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "my-site.example.com",
		}

	action == "INTERCEPT"
}

# Test 13: Single label domain
test_action_intercept_single_label if {
	action := dns.action with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"domain": "localhost",
		}

	action == "INTERCEPT"
}

# Test 14: Bypass with suffix pattern
test_action_bypass_suffix_comprehensive if {
	comprehensive_config := {
		"bypass_domains": [
			".apple.com",
			"google.com",
		],
	}

	# Test .apple.com suffix
	action1 := dns.action with data.kproxy.config as comprehensive_config
		with input as {"domain": "www.apple.com"}
	action1 == "BYPASS"

	# Test exact match
	action2 := dns.action with data.kproxy.config as comprehensive_config
		with input as {"domain": "google.com"}
	action2 == "BYPASS"
}
