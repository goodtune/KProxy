# Redis Lua Scripts

This directory contains Lua scripts used by KProxy's Redis storage backend. These scripts are embedded into the Go binary using Go's `embed` directive and executed atomically within Redis.

## Scripts

### upsert_session.lua

Atomically updates a usage session and its indexes.

**Purpose**: Maintains consistency between session data, active session set, and device-to-session mapping.

**Keys**:
- `KEYS[1]`: Session key (`kproxy:session:{sessionID}`)
- `KEYS[2]`: Active sessions set (`kproxy:sessions:active`)
- `KEYS[3]`: Device mapping key (`kproxy:sessions:device:{deviceID}:{limitID}`)

**Arguments**:
- `ARGV[1]`: session_id
- `ARGV[2]`: device_id
- `ARGV[3]`: limit_id
- `ARGV[4]`: started_at (Unix timestamp)
- `ARGV[5]`: last_activity (Unix timestamp)
- `ARGV[6]`: accumulated_seconds
- `ARGV[7]`: active (1 or 0)

**Behavior**:
- Sets all session fields in a hash
- If active=1: Adds session to active set and creates device mapping
- If active=0: Removes from active set, deletes device mapping, sets 90-day TTL

### increment_daily_usage.lua

Atomically increments or creates a daily usage record.

**Purpose**: Safely increment usage totals with automatic index management.

**Keys**:
- `KEYS[1]`: Usage key (`kproxy:usage:daily:{date}:{deviceID}:{limitID}`)
- `KEYS[2]`: Date index (`kproxy:usage:daily:index:{date}`)

**Arguments**:
- `ARGV[1]`: date (YYYY-MM-DD)
- `ARGV[2]`: device_id
- `ARGV[3]`: limit_id
- `ARGV[4]`: seconds (to add)

**Behavior**:
- If key doesn't exist: Creates new entry with initial seconds, adds to index, sets 90-day TTL
- If key exists: Increments total_seconds field

### create_dhcp_lease.lua

Atomically creates or updates a DHCP lease with bidirectional indexes.

**Purpose**: Maintains consistency between MAC→IP and IP→MAC mappings.

**Keys**:
- `KEYS[1]`: MAC key (`kproxy:dhcp:mac:{mac}`)
- `KEYS[2]`: IP key (`kproxy:dhcp:ip:{ip}`)
- `KEYS[3]`: Leases set (`kproxy:dhcp:leases`)

**Arguments**:
- `ARGV[1]`: mac
- `ARGV[2]`: ip
- `ARGV[3]`: hostname
- `ARGV[4]`: expires_at (RFC3339 timestamp)
- `ARGV[5]`: ttl_seconds
- `ARGV[6]`: updated_at (RFC3339 timestamp)
- `ARGV[7]`: created_at (RFC3339 timestamp)

**Behavior**:
- Preserves original created_at if lease already exists
- Updates all lease fields
- Creates IP→MAC secondary index
- Adds MAC to leases set
- Sets TTL if ttl_seconds > 0

## Testing

Lua scripts are tested in isolation using `miniredis` (an in-memory Redis implementation that supports Lua scripting).

Run tests:
```bash
go test -v ./internal/storage/redis -run TestUpsertSessionScript
go test -v ./internal/storage/redis -run TestIncrementDailyUsageScript
go test -v ./internal/storage/redis -run TestCreateDHCPLeaseScript
```

Run all script tests:
```bash
go test -v ./internal/storage/redis -run Script
```

## Development

When modifying Lua scripts:

1. Edit the `.lua` file directly
2. The Go code will automatically pick up changes via `//go:embed`
3. Add test cases to `scripts_test.go`
4. Run tests to verify behavior
5. Consider atomicity - scripts execute as a single Redis transaction

## Language Server Support

Since scripts are now in separate `.lua` files, you can use Lua language servers for:
- Syntax highlighting
- Code completion
- Linting
- Static analysis

Recommended LSP: `lua-language-server`

## Why Lua Scripts?

Redis Lua scripts provide:
- **Atomicity**: All operations execute as a single transaction
- **Performance**: Reduces round-trips between client and server
- **Consistency**: Prevents race conditions in multi-field updates
- **Simplicity**: Complex logic in a concise scripting language

## Script Guidelines

- Keep scripts focused on a single operation
- Document KEYS and ARGV clearly
- Use local variables to improve readability
- Return meaningful values ('OK', counts, etc.)
- Set appropriate TTLs for ephemeral data
- Test edge cases (empty sets, non-existent keys, etc.)
