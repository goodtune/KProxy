-- upsert_session.lua
-- Atomically updates a session and its indexes
--
-- KEYS:
--   KEYS[1]: session_key     (kproxy:session:{sessionID})
--   KEYS[2]: active_set      (kproxy:sessions:active)
--   KEYS[3]: device_key      (kproxy:sessions:device:{deviceID}:{limitID})
--
-- ARGV:
--   ARGV[1]: session_id
--   ARGV[2]: device_id
--   ARGV[3]: limit_id
--   ARGV[4]: started_at
--   ARGV[5]: last_activity
--   ARGV[6]: accumulated_seconds
--   ARGV[7]: active (1 or 0)

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
