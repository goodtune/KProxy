-- create_dhcp_lease.lua
-- Atomically creates or updates a DHCP lease
--
-- KEYS:
--   KEYS[1]: mac_key        (kproxy:dhcp:mac:{mac})
--   KEYS[2]: ip_key         (kproxy:dhcp:ip:{ip})
--   KEYS[3]: leases_set     (kproxy:dhcp:leases)
--
-- ARGV:
--   ARGV[1]: mac
--   ARGV[2]: ip
--   ARGV[3]: hostname
--   ARGV[4]: expires_at
--   ARGV[5]: ttl_seconds
--   ARGV[6]: updated_at
--   ARGV[7]: created_at

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
