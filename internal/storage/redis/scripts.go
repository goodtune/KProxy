package redis

const (
	// upsertSessionScript atomically updates a session and its indexes
	upsertSessionScript = `
local session_key = KEYS[1]     -- kproxy:session:{sessionID}
local active_set = KEYS[2]      -- kproxy:sessions:active
local device_key = KEYS[3]      -- kproxy:sessions:device:{deviceID}:{limitID}

local session_id = ARGV[1]
local device_id = ARGV[2]
local limit_id = ARGV[3]
local started_at = ARGV[4]
local last_activity = ARGV[5]
local accumulated_seconds = ARGV[6]
local active = ARGV[7]

-- Set session fields
redis.call('HSET', session_key,
  'id', session_id,
  'device_id', device_id,
  'limit_id', limit_id,
  'started_at', started_at,
  'last_activity', last_activity,
  'accumulated_seconds', accumulated_seconds,
  'active', active
)

-- Update indexes based on active status
if active == '1' then
  -- Active session: add to active set and device mapping
  redis.call('SADD', active_set, session_id)
  redis.call('SET', device_key, session_id)
else
  -- Inactive session: remove from active set and device mapping
  redis.call('SREM', active_set, session_id)
  redis.call('DEL', device_key)
  -- Set TTL on inactive sessions (90 days = 7776000 seconds)
  redis.call('EXPIRE', session_key, 7776000)
end

return 'OK'
`

	// incrementDailyUsageScript atomically increments or creates daily usage
	incrementDailyUsageScript = `
local usage_key = KEYS[1]     -- kproxy:usage:daily:{date}:{deviceID}:{limitID}
local index_key = KEYS[2]     -- kproxy:usage:daily:index:{date}

local date = ARGV[1]
local device_id = ARGV[2]
local limit_id = ARGV[3]
local seconds = tonumber(ARGV[4])

-- Check if key exists
local exists = redis.call('EXISTS', usage_key)

if exists == 0 then
  -- Create new entry
  redis.call('HSET', usage_key,
    'date', date,
    'device_id', device_id,
    'limit_id', limit_id,
    'total_seconds', seconds
  )
  -- Set TTL to 90 days (7776000 seconds)
  redis.call('EXPIRE', usage_key, 7776000)

  -- Add to date index
  local index_value = device_id .. ':' .. limit_id
  redis.call('SADD', index_key, index_value)
  redis.call('EXPIRE', index_key, 7776000)
else
  -- Increment existing entry
  redis.call('HINCRBY', usage_key, 'total_seconds', seconds)
end

return 'OK'
`

	// createDHCPLeaseScript atomically creates or updates a DHCP lease
	createDHCPLeaseScript = `
local mac_key = KEYS[1]        -- kproxy:dhcp:mac:{mac}
local ip_key = KEYS[2]         -- kproxy:dhcp:ip:{ip}
local leases_set = KEYS[3]     -- kproxy:dhcp:leases

local mac = ARGV[1]
local ip = ARGV[2]
local hostname = ARGV[3]
local expires_at = ARGV[4]
local ttl_seconds = tonumber(ARGV[5])
local updated_at = ARGV[6]
local created_at = ARGV[7]

-- Get existing created_at if lease exists
local existing_created = redis.call('HGET', mac_key, 'created_at')
if existing_created then
  created_at = existing_created
end

-- Set lease data
redis.call('HSET', mac_key,
  'mac', mac,
  'ip', ip,
  'hostname', hostname,
  'expires_at', expires_at,
  'created_at', created_at,
  'updated_at', updated_at
)

-- Update secondary index (IP → MAC)
redis.call('SET', ip_key, mac)

-- Add to leases set
redis.call('SADD', leases_set, mac)

-- Set TTL if valid
if ttl_seconds > 0 then
  redis.call('EXPIRE', mac_key, ttl_seconds)
  redis.call('EXPIRE', ip_key, ttl_seconds)
end

return 'OK'
`
)
