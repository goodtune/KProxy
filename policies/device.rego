package kproxy.device

import rego.v1

import data.kproxy.helpers

# Device identification by IP, MAC, or CIDR
# Input structure:
# {
#   "client_ip": "192.168.1.100",
#   "client_mac": "aa:bb:cc:dd:ee:ff",  // optional
#   "devices": {
#     "device-1": {
#       "id": "device-1",
#       "name": "Child iPad",
#       "identifiers": ["192.168.1.100", "aa:bb:cc:dd:ee:ff"],
#       "profile_id": "profile-1",
#       "active": true
#     }
#   },
#   "use_mac_address": true
# }

# Primary identification result
identified_device := device if {
	# Try MAC address first (most reliable)
	input.use_mac_address
	input.client_mac != ""
	count(device_by_mac) > 0
	some device in device_by_mac
}

identified_device := device if {
	# Fall back to IP/CIDR matching
	count(device_by_ip) > 0
	some device in device_by_ip
}

# MAC address lookup
device_by_mac contains device if {
	some device_id, device in input.devices
	device.active
	some identifier in device.identifiers
	helpers.is_mac_address(identifier)
	lower(identifier) == lower(input.client_mac)
}

# IP address lookup (exact or CIDR)
device_by_ip contains device if {
	some device_id, device in input.devices
	device.active
	some identifier in device.identifiers

	# Exact IP match
	not helpers.is_cidr(identifier)
	not helpers.is_mac_address(identifier)
	identifier == input.client_ip
}

device_by_ip contains device if {
	some device_id, device in input.devices
	device.active
	some identifier in device.identifiers

	# CIDR range match
	helpers.is_cidr(identifier)
	helpers.ip_in_cidr(input.client_ip, identifier)
}
