package kproxy.device_test

import rego.v1

import data.kproxy.device

# Test configuration with various device identifiers
mock_config := {"devices": {
	"mac-device": {
		"name": "MAC Device",
		"identifiers": ["aa:bb:cc:dd:ee:ff"],
		"profile": "mac-profile",
	},
	"ip-device": {
		"name": "IP Device",
		"identifiers": ["192.168.1.100"],
		"profile": "ip-profile",
	},
	"cidr-device": {
		"name": "CIDR Device",
		"identifiers": ["10.0.0.0/24"],
		"profile": "cidr-profile",
	},
	"multi-identifier-device": {
		"name": "Multi Identifier Device",
		"identifiers": [
			"11:22:33:44:55:66",
			"172.16.0.50",
			"192.168.100.0/28",
		],
		"profile": "multi-profile",
	},
}}

# Test 1: Identify device by MAC address
test_identify_by_mac if {
	dev := device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.200",
			"client_mac": "aa:bb:cc:dd:ee:ff",
		}

	dev.name == "MAC Device"
	dev.profile == "mac-profile"
}

# Test 2: Identify device by exact IP match
test_identify_by_exact_ip if {
	dev := device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
		}

	dev.name == "IP Device"
	dev.profile == "ip-profile"
}

# Test 3: Identify device by CIDR range
test_identify_by_cidr if {
	dev := device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "10.0.0.50",
			"client_mac": "",
		}

	dev.name == "CIDR Device"
	dev.profile == "cidr-profile"
}

# Test 4: MAC takes priority over IP
test_mac_priority_over_ip if {
	dev := device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.100", # Matches ip-device
			"client_mac": "aa:bb:cc:dd:ee:ff", # Matches mac-device
		}

	# MAC should win
	dev.name == "MAC Device"
	dev.profile == "mac-profile"
}

# Test 5: Exact IP takes priority over CIDR
test_ip_priority_over_cidr if {
	config_with_overlap := {"devices": {
		"cidr-device": {
			"name": "CIDR Device",
			"identifiers": ["192.168.1.0/24"],
			"profile": "cidr-profile",
		},
		"exact-ip-device": {
			"name": "Exact IP Device",
			"identifiers": ["192.168.1.100"],
			"profile": "exact-profile",
		},
	}}

	dev := device.identified_device with data.kproxy.config as config_with_overlap
		with input as {
			"client_ip": "192.168.1.100",
			"client_mac": "",
		}

	# Exact IP should win over CIDR
	dev.name == "Exact IP Device"
	dev.profile == "exact-profile"
}

# Test 6: Multi-identifier device - match by MAC
test_multi_identifier_by_mac if {
	dev := device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "1.2.3.4",
			"client_mac": "11:22:33:44:55:66",
		}

	dev.name == "Multi Identifier Device"
	dev.profile == "multi-profile"
}

# Test 7: Multi-identifier device - match by exact IP
test_multi_identifier_by_ip if {
	dev := device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "172.16.0.50",
			"client_mac": "",
		}

	dev.name == "Multi Identifier Device"
	dev.profile == "multi-profile"
}

# Test 8: Multi-identifier device - match by CIDR
test_multi_identifier_by_cidr if {
	dev := device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.100.5",
			"client_mac": "",
		}

	dev.name == "Multi Identifier Device"
	dev.profile == "multi-profile"
}

# Test 9: Unknown device (no match) - identified_device should be undefined
test_unknown_device if {
	not device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "99.99.99.99",
			"client_mac": "ff:ff:ff:ff:ff:ff",
		}
}

# Test 10: Empty MAC should not match MAC identifier
test_empty_mac_no_match if {
	not device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.200",
			"client_mac": "",
		}
}

# Test 11: Case sensitivity of MAC address
test_mac_case_insensitive if {
	dev := device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "192.168.1.200",
			"client_mac": "AA:BB:CC:DD:EE:FF", # Uppercase
		}

	dev.name == "MAC Device"
	dev.profile == "mac-profile"
}

# Test 12: CIDR boundary - first IP in range
test_cidr_first_ip if {
	dev := device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "10.0.0.0",
			"client_mac": "",
		}

	dev.name == "CIDR Device"
	dev.profile == "cidr-profile"
}

# Test 13: CIDR boundary - last IP in range
test_cidr_last_ip if {
	dev := device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "10.0.0.255",
			"client_mac": "",
		}

	dev.name == "CIDR Device"
	dev.profile == "cidr-profile"
}

# Test 14: CIDR outside range
test_cidr_outside_range if {
	not device.identified_device with data.kproxy.config as mock_config
		with input as {
			"client_ip": "10.0.1.0",
			"client_mac": "",
		}
}
