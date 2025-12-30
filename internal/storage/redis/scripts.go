package redis

import _ "embed"

var (
	//go:embed scripts/upsert_session.lua
	upsertSessionScript string

	//go:embed scripts/increment_daily_usage.lua
	incrementDailyUsageScript string

	//go:embed scripts/create_dhcp_lease.lua
	createDHCPLeaseScript string
)
