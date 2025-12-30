package kproxy.helpers_test

import rego.v1

import data.kproxy.helpers

# Test domain matching - exact matches
test_match_domain_exact if {
	helpers.match_domain("example.com", "example.com")
}

test_match_domain_exact_no_match if {
	not helpers.match_domain("example.com", "other.com")
}

# Test domain matching - wildcard subdomain
test_match_domain_wildcard_subdomain if {
	helpers.match_domain("www.example.com", "*.example.com")
}

test_match_domain_wildcard_no_match_multiple_levels if {
	# Wildcard * only matches one subdomain level, not multiple
	# For multiple levels, use suffix matching (.example.com)
	not helpers.match_domain("sub.www.example.com", "*.example.com")
}

test_match_domain_wildcard_no_match_parent if {
	not helpers.match_domain("example.com", "*.example.com")
}

test_match_domain_wildcard_no_match_different if {
	not helpers.match_domain("www.other.com", "*.example.com")
}

# Test domain matching - suffix matching
test_match_domain_suffix if {
	helpers.match_domain("www.example.com", ".example.com")
}

test_match_domain_suffix_deep if {
	helpers.match_domain("a.b.c.example.com", ".example.com")
}

test_match_domain_suffix_exact if {
	helpers.match_domain("example.com", ".example.com")
}

test_match_domain_suffix_no_match if {
	not helpers.match_domain("notexample.com", ".example.com")
}

test_match_domain_suffix_no_match_different if {
	not helpers.match_domain("www.other.com", ".example.com")
}

# Test CIDR matching with ip_in_cidr
test_ip_in_cidr_in_range if {
	helpers.ip_in_cidr("192.168.1.100", "192.168.1.0/24")
}

test_ip_in_cidr_first_ip if {
	helpers.ip_in_cidr("192.168.1.0", "192.168.1.0/24")
}

test_ip_in_cidr_last_ip if {
	helpers.ip_in_cidr("192.168.1.255", "192.168.1.0/24")
}

test_ip_in_cidr_outside_range if {
	not helpers.ip_in_cidr("192.168.2.0", "192.168.1.0/24")
}

test_ip_in_cidr_small_subnet if {
	helpers.ip_in_cidr("10.0.0.5", "10.0.0.0/28")
}

test_ip_in_cidr_small_subnet_outside if {
	not helpers.ip_in_cidr("10.0.0.20", "10.0.0.0/28")
}

test_ip_in_cidr_large_subnet if {
	helpers.ip_in_cidr("10.50.100.200", "10.0.0.0/8")
}

test_ip_in_cidr_slash_32 if {
	helpers.ip_in_cidr("192.168.1.100", "192.168.1.100/32")
}

test_ip_in_cidr_slash_32_no_match if {
	not helpers.ip_in_cidr("192.168.1.101", "192.168.1.100/32")
}

# Test identifier type detection
test_is_mac_address_valid if {
	helpers.is_mac_address("aa:bb:cc:dd:ee:ff")
}

test_is_mac_address_uppercase if {
	helpers.is_mac_address("AA:BB:CC:DD:EE:FF")
}

test_is_mac_address_invalid if {
	not helpers.is_mac_address("192.168.1.1")
}

test_is_cidr_valid if {
	helpers.is_cidr("192.168.1.0/24")
}

test_is_cidr_slash_32 if {
	helpers.is_cidr("10.0.0.1/32")
}

test_is_cidr_invalid if {
	not helpers.is_cidr("192.168.1.1")
}

# Test edge cases
test_match_domain_empty_pattern if {
	not helpers.match_domain("example.com", "")
}

test_match_domain_empty_host if {
	not helpers.match_domain("", "example.com")
}

test_ip_in_cidr_invalid_ip if {
	not helpers.ip_in_cidr("not-an-ip", "192.168.1.0/24")
}

# Test complex wildcard patterns
test_match_domain_wildcard_asterisk_middle if {
	# Test that *.example.com matches subdomains
	helpers.match_domain("api.example.com", "*.example.com")
	helpers.match_domain("web.example.com", "*.example.com")
}

# Test case sensitivity
test_match_domain_case_sensitive if {
	helpers.match_domain("Example.Com", "example.com")
}

test_match_domain_uppercase if {
	helpers.match_domain("WWW.EXAMPLE.COM", "*.example.com")
}

# Test special characters in domains
test_match_domain_with_dash if {
	helpers.match_domain("my-site.example.com", "*.example.com")
}

test_match_domain_with_number if {
	helpers.match_domain("api2.example.com", "*.example.com")
}

# Test CIDR edge cases
test_ip_in_cidr_class_a if {
	helpers.ip_in_cidr("10.255.255.255", "10.0.0.0/8")
}

test_ip_in_cidr_class_b if {
	helpers.ip_in_cidr("172.16.255.255", "172.16.0.0/16")
}

test_ip_in_cidr_class_c if {
	helpers.ip_in_cidr("192.168.1.254", "192.168.1.0/24")
}

# Test localhost and private ranges
test_ip_in_cidr_localhost if {
	helpers.ip_in_cidr("127.0.0.1", "127.0.0.0/8")
}

test_ip_in_cidr_private_10 if {
	helpers.ip_in_cidr("10.1.2.3", "10.0.0.0/8")
}

test_ip_in_cidr_private_172 if {
	helpers.ip_in_cidr("172.16.1.1", "172.16.0.0/12")
}

test_ip_in_cidr_private_192 if {
	helpers.ip_in_cidr("192.168.0.1", "192.168.0.0/16")
}

# Test time window checking
test_within_time_window_valid if {
	current_time := {"day_of_week": 1, "minutes": 600} # Monday 10:00 AM
	time_rule := {
		"days_of_week": [1, 2, 3, 4, 5],
		"start_time": "09:00",
		"end_time": "17:00",
	}
	helpers.within_time_window(current_time, time_rule)
}

test_within_time_window_start_boundary if {
	current_time := {"day_of_week": 1, "minutes": 540} # Monday 9:00 AM
	time_rule := {
		"days_of_week": [1, 2, 3, 4, 5],
		"start_time": "09:00",
		"end_time": "17:00",
	}
	helpers.within_time_window(current_time, time_rule)
}

test_within_time_window_end_boundary if {
	current_time := {"day_of_week": 1, "minutes": 1020} # Monday 5:00 PM
	time_rule := {
		"days_of_week": [1, 2, 3, 4, 5],
		"start_time": "09:00",
		"end_time": "17:00",
	}
	helpers.within_time_window(current_time, time_rule)
}

test_within_time_window_wrong_day if {
	current_time := {"day_of_week": 0, "minutes": 600} # Sunday 10:00 AM
	time_rule := {
		"days_of_week": [1, 2, 3, 4, 5],
		"start_time": "09:00",
		"end_time": "17:00",
	}
	not helpers.within_time_window(current_time, time_rule)
}

test_within_time_window_before_start if {
	current_time := {"day_of_week": 1, "minutes": 480} # Monday 8:00 AM
	time_rule := {
		"days_of_week": [1, 2, 3, 4, 5],
		"start_time": "09:00",
		"end_time": "17:00",
	}
	not helpers.within_time_window(current_time, time_rule)
}

test_within_time_window_after_end if {
	current_time := {"day_of_week": 1, "minutes": 1080} # Monday 6:00 PM
	time_rule := {
		"days_of_week": [1, 2, 3, 4, 5],
		"start_time": "09:00",
		"end_time": "17:00",
	}
	not helpers.within_time_window(current_time, time_rule)
}

# Test time parsing
test_parse_time_to_minutes_morning if {
	helpers.parse_time_to_minutes("09:00") == 540
}

test_parse_time_to_minutes_afternoon if {
	helpers.parse_time_to_minutes("17:30") == 1050
}

test_parse_time_to_minutes_midnight if {
	helpers.parse_time_to_minutes("00:00") == 0
}

test_parse_time_to_minutes_end_of_day if {
	helpers.parse_time_to_minutes("23:59") == 1439
}

test_parse_time_to_minutes_invalid_format if {
	helpers.parse_time_to_minutes("invalid") == 0
}

test_parse_time_to_minutes_no_colon if {
	helpers.parse_time_to_minutes("0900") == 0
}

# Test path matching
test_match_path_null_paths if {
	helpers.match_path("/any/path", null)
}

test_match_path_empty_paths if {
	helpers.match_path("/any/path", [])
}

test_match_path_wildcard_all if {
	helpers.match_path("/any/path", ["*"])
}

test_match_path_prefix_match if {
	helpers.match_path("/api/users/123", ["/api/users"])
}

test_match_path_prefix_no_match if {
	not helpers.match_path("/other/path", ["/api/users"])
}

test_match_path_exact_match if {
	helpers.match_path("/api/login", ["/api/login"])
}

# Glob pattern tests
test_match_path_glob_suffix_wildcard if {
	helpers.match_path("/api/users/123", ["/api/users/*"])
}

test_match_path_glob_middle_wildcard if {
	helpers.match_path("/api/users/123", ["/api/*/123"])
}

test_match_path_glob_youtube_shorts if {
	helpers.match_path("/shorts/abc123", ["/shorts/*"])
}

test_match_path_glob_youtube_channel if {
	helpers.match_path("/channel/UC12345", ["/channel/UC*"])
}

test_match_path_glob_no_match if {
	not helpers.match_path("/other/path", ["/api/users/*"])
}

test_match_path_glob_multiple_wildcards if {
	helpers.match_path("/api/v1/users/123/profile", ["/api/*/users/*/profile"])
}

test_match_path_glob_with_query_string if {
	helpers.match_path("/watch?v=abc123", ["/watch*"])
}

test_match_path_glob_education_path_single_level if {
	# * matches only one path segment
	helpers.match_path("/education/math", ["/education/*"])
}

test_match_path_glob_education_path_no_match_multiple_levels if {
	# * does not match multiple path segments
	not helpers.match_path("/education/math/algebra", ["/education/*"])
}

test_match_path_glob_education_path_double_wildcard if {
	# ** matches multiple path segments (Ant-style)
	helpers.match_path("/education/math/algebra", ["/education/**"])
}

test_match_path_glob_exact_no_wildcard if {
	not helpers.match_path("/api/users", ["/api/users/*"])
}

test_match_path_glob_special_chars_in_path if {
	helpers.match_path("/api/v2.0/users", ["/api/v2.0/*"])
}

test_match_path_glob_root_wildcard_single_level if {
	# /* matches only one segment at root level
	helpers.match_path("/anything", ["/*"])
}

test_match_path_glob_root_wildcard_no_match_deep if {
	# /* does NOT match multiple segments
	not helpers.match_path("/anything/here", ["/*"])
}

test_match_path_glob_root_double_wildcard if {
	# /** matches multiple segments from root
	helpers.match_path("/anything/here", ["/**"])
}

test_match_path_glob_combined_with_prefix if {
	# Should match via prefix, not glob
	helpers.match_path("/api/users/123", ["/api/users"])
}

test_match_path_multiple_paths if {
	helpers.match_path("/admin/settings", ["/api/users", "/admin/settings", "/public"])
}

test_match_path_no_match_multiple if {
	not helpers.match_path("/other/path", ["/api/users", "/admin/settings", "/public"])
}

# Test Ant-style path patterns (* for one segment, ** for multiple)
test_match_path_ant_single_wildcard_one_level if {
	# /path/* matches /path/file.xml
	helpers.match_path("/path/file.xml", ["/path/*"])
}

test_match_path_ant_single_wildcard_no_match_deep if {
	# /path/* does NOT match /path/subdir/file.xml
	not helpers.match_path("/path/subdir/file.xml", ["/path/*"])
}

test_match_path_ant_double_wildcard_one_level if {
	# /path/** matches /path/file.xml
	helpers.match_path("/path/file.xml", ["/path/**"])
}

test_match_path_ant_double_wildcard_deep if {
	# /path/** matches /path/subdir/file.xml
	helpers.match_path("/path/subdir/file.xml", ["/path/**"])
}

test_match_path_ant_double_wildcard_very_deep if {
	# /path/** matches /path/a/b/c/d/file.xml
	helpers.match_path("/path/a/b/c/d/file.xml", ["/path/**"])
}

test_match_path_ant_pattern_with_suffix if {
	# /path/**/*.xml matches /path/subdir/file.xml
	helpers.match_path("/path/subdir/file.xml", ["/path/**/*.xml"])
}

test_match_path_ant_pattern_with_suffix_deep if {
	# /path/**/*.xml matches /path/a/b/c/file.xml
	helpers.match_path("/path/a/b/c/file.xml", ["/path/**/*.xml"])
}

test_match_path_ant_pattern_with_suffix_no_match if {
	# /path/**/*.xml does NOT match /path/subdir/file.txt
	not helpers.match_path("/path/subdir/file.txt", ["/path/**/*.xml"])
}

test_match_path_ant_single_at_root if {
	# /path/*.xml matches /path/file.xml
	helpers.match_path("/path/file.xml", ["/path/*.xml"])
}

test_match_path_ant_single_at_root_no_match_deep if {
	# /path/*.xml does NOT match /path/subdir/file.xml
	not helpers.match_path("/path/subdir/file.xml", ["/path/*.xml"])
}
