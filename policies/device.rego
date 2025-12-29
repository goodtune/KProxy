package kproxy.device

import rego.v1

import data.kproxy.config
import data.kproxy.helpers

# Device Identification from Facts
# Identifies which device made the request based on client IP and MAC
#
# Input structure (facts only):
# {
#   "client_ip": "192.168.1.100",
#   "client_mac": "aa:bb:cc:dd:ee:ff"  // optional, may be empty
# }
#
# Device configuration comes from data.kproxy.config.devices

# Identify device by MAC address (highest priority, most reliable)
identified_device := device if {
	# MAC address provided
	input.client_mac != ""

	# Find matching device in config
	some device_id, device in config.devices
	some identifier in device.identifiers
	is_mac_address(identifier)
	lower(identifier) == lower(input.client_mac)
}

# Identify device by exact IP match (second priority)
identified_device := device if {
	# MAC not available or didn't match
	not device_by_mac

	# Find matching device by exact IP
	some device_id, device in config.devices
	some identifier in device.identifiers
	is_ip_address(identifier)
	input.client_ip == identifier
}

# Identify device by CIDR range (third priority)
identified_device := device if {
	# MAC and exact IP didn't match
	not device_by_mac
	not device_by_exact_ip

	# Find matching device by CIDR
	some device_id, device in config.devices
	some identifier in device.identifiers
	is_cidr(identifier)
	helpers.ip_in_cidr(input.client_ip, identifier)
}

# Get the device ID (for logging/tracking)
device_id := did if {
	device := identified_device
	some did, d in config.devices
	d == device
}

# Helper: check if device was identified by MAC
device_by_mac if {
	input.client_mac != ""
	some device_id, device in config.devices
	some identifier in device.identifiers
	is_mac_address(identifier)
	lower(identifier) == lower(input.client_mac)
}

# Helper: check if device was identified by exact IP
device_by_exact_ip if {
	some device_id, device in config.devices
	some identifier in device.identifiers
	is_ip_address(identifier)
	input.client_ip == identifier
}

# Helper: check if identifier is MAC address
is_mac_address(id) if {
	contains(id, ":")
	count(split(id, ":")) == 6
}

# Helper: check if identifier is IP address (not MAC, not CIDR)
is_ip_address(id) if {
	not contains(id, ":")
	not contains(id, "/")
}

# Helper: check if identifier is CIDR range
is_cidr(id) if {
	contains(id, "/")
}
