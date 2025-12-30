-- increment_daily_usage.lua
-- Atomically increments or creates daily usage
--
-- KEYS:
--   KEYS[1]: usage_key     (kproxy:usage:daily:{date}:{deviceID}:{limitID})
--   KEYS[2]: index_key     (kproxy:usage:daily:index:{date})
--
-- ARGV:
--   ARGV[1]: date
--   ARGV[2]: device_id
--   ARGV[3]: limit_id
--   ARGV[4]: seconds

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
