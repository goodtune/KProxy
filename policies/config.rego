package kproxy.config

# Device Configuration
# Define all devices with their identifiers (MAC addresses, IPs, or CIDR ranges)
# and their assigned profile
devices := {
	"kids-ipad": {
		"name": "Kids iPad",
		"identifiers": ["aa:bb:cc:dd:ee:ff", "192.168.1.100"],
		"profile": "child",
	},
	"parents-laptop": {
		"name": "Parents Laptop",
		"identifiers": ["bb:cc:dd:ee:ff:00", "192.168.1.10"],
		"profile": "adult",
	},
	"guest-network": {
		"name": "Guest Network",
		"identifiers": ["192.168.2.0/24"],
		"profile": "guest",
	},
}

# Profile Configuration
# Define access profiles with rules, time restrictions, and usage limits
profiles := {
	"child": {
		"name": "Child Profile",
		"description": "Restricted access for children with time limits",
		# Time restrictions by day type
		"time_restrictions": {
			"weekday": {
				"days": [1, 2, 3, 4, 5], # Monday-Friday
				"start_hour": 15, # 3 PM
				"start_minute": 0,
				"end_hour": 20, # 8 PM
				"end_minute": 0,
			},
			"weekend": {
				"days": [0, 6], # Sunday, Saturday
				"start_hour": 8, # 8 AM
				"start_minute": 0,
				"end_hour": 21, # 9 PM
				"end_minute": 0,
			},
		},
		# Domain rules (evaluated in order)
		"rules": [
			{
				"id": "allow-educational",
				"domains": ["*.pbskids.org", "*.khanacademy.org", "*.coolmathgames.com"],
				"action": "allow",
				"category": "educational",
			},
			{
				"id": "allow-youtube-limited",
				"domains": ["*.youtube.com", "*.googlevideo.com"],
				"action": "allow",
				"category": "entertainment",
			},
			{
				"id": "block-social-media",
				"domains": ["*.tiktok.com", "*.instagram.com", "*.facebook.com", "*.snapchat.com"],
				"action": "block",
				"category": "social-media",
			},
			{
				"id": "block-adult-content",
				"domains": ["*.adult-content.com", "*.gambling.com"],
				"action": "block",
				"category": "adult",
			},
		],
		# Usage limits (daily time limits per category or domain)
		"usage_limits": {
			"entertainment": {
				"daily_minutes": 60,
				"reset_hour": 0, # Midnight
				"domains": ["*.youtube.com", "*.googlevideo.com"],
				"inject_timer": true,
			},
		},
		# Default action when no rules match
		"default_action": "block",
	},
	"adult": {
		"name": "Adult Profile",
		"description": "Unrestricted access for adults",
		# No time restrictions
		"time_restrictions": {},
		# Minimal rules (mostly for bypass)
		"rules": [
			{
				"id": "block-known-malware",
				"domains": ["*.malware-site.com", "*.phishing.com"],
				"action": "block",
				"category": "security",
			},
		],
		# No usage limits
		"usage_limits": {},
		# Default allow for adults
		"default_action": "allow",
	},
	"guest": {
		"name": "Guest Profile",
		"description": "Limited access for guest network",
		# Time restrictions (e.g., night hours blocked)
		"time_restrictions": {
			"all": {
				"days": [0, 1, 2, 3, 4, 5, 6],
				"start_hour": 6, # 6 AM
				"start_minute": 0,
				"end_hour": 23, # 11 PM
				"end_minute": 0,
			},
		},
		# Basic web access, block potentially harmful content
		"rules": [
			{
				"id": "block-adult-content",
				"domains": ["*.adult-content.com", "*.gambling.com"],
				"action": "block",
				"category": "adult",
			},
			{
				"id": "block-file-sharing",
				"domains": ["*.torrent.com", "*.piratebay.org"],
				"action": "block",
				"category": "file-sharing",
			},
		],
		"usage_limits": {},
		# Default allow for basic web browsing
		"default_action": "allow",
	},
}

# Global Bypass Domains
# These domains always bypass the proxy (never intercepted)
# Typically used for system-critical services
bypass_domains := [
	# Certificate validation (must bypass to prevent cert errors)
	"ocsp.*.com",
	"*.ocsp.apple.com",
	"ocsp.digicert.com",
	"crl.*.com",
	# Apple services (better performance and reliability)
	"*.apple.com",
	"*.icloud.com",
	"*.mzstatic.com",
	# Banking (sensitive, better to bypass)
	"*.bank.com",
	"*.chase.com",
	"*.wellsfargo.com",
	# Government sites
	"*.gov",
]
