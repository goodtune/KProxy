# KProxy Storage Refactor Plan

## Goals

- Remove the `modernc.org/sqlite`/CGO dependency so `go build` works everywhere.
- Match the updated server specification that standardizes on a pluggable storage interface backed by a pure-Go KV store.
- Simplify persistence logic (no migrations) while keeping a path for richer backends later.

## Current State

- `internal/database/db.go` opens a SQLite database, runs migrations, and returns `*database.DB` (thin wrapper over `*sql.DB`).
- `cmd/kproxy/main.go` constructs downstream components with this DB handle.
- Policy engine (`internal/policy/engine.go`) runs SQL queries to load devices/profiles/rules/time rules/usage limits and keeps them in memory.
- Usage tracker (`internal/usage/tracker.go`, `reset.go`) persists sessions, aggregates, and cleanup metadata through SQL statements.
- DNS server (`internal/dns/server.go`) writes DNS log rows.
- Proxy server (`internal/proxy/server.go`) records HTTP logs and references `database.DB` for block pages/decisions.
- Scripts (`scripts/sample-data.sql`, `scripts/load-sample-data.sh`) assume SQLite files.
- Config (`configs/*.yaml`, `config.yaml`, `internal/config`) exposes a `database.path` option.

## Target Architecture (from `specs/SERVER.md`)

- Introduce repository interfaces (`DeviceStore`, `ProfileStore`, `RuleStore`, `UsageStore`, `LogStore`, etc.) collected under an `internal/storage` package.
- Default backend: embedded KV store (Bolt/Pebble) storing JSON blobs under deterministic keys:
  - `devices/<deviceID>`, `profiles/<profileID>`, `usage/daily/...`, `logs/http/...`, etc.
  - Companion index buckets (`indexes/http/device/<deviceID>/...`) for efficient filtering.
- Config exposes `storage.path` and `storage.type` (default `bolt`).
- All business logic depends only on repositories; swapping in SQLite/Postgres later only requires another implementation of the interfaces.

## Implementation Roadmap

1. **Introduce storage interfaces**
   - Create `internal/storage/store.go` defining root interfaces for devices, profiles, bypass rules, usage (sessions + aggregates), request logs, DNS logs, and block pages.
   - Add helper DTOs (mirroring existing structs) plus serialization helpers (JSON marshal/unmarshal, key builders).

2. **Bolt backend**
   - Add `internal/storage/bolt` package implementing the interfaces using `go.etcd.io/bbolt`.
   - Define buckets/index layout per the spec (`logs/http`, `indexes/http/device`, etc.).
   - Provide batched read/write helpers, TTL deletion utilities, and prefix scans needed by log queries.
   - Wire metrics (e.g., log writes, storage latency) if needed.

3. **Wire storage into startup/config**
   - Update `internal/config` to validate `storage.path`/`storage.type` (rename existing `database` fields).
   - Update `cmd/kproxy/main.go` to open the storage backend instead of `database.New`, ensure graceful close.
   - Remove `internal/database` package after consumers are migrated.

4. **Refactor policy engine**
   - Replace direct SQL in `internal/policy/engine.go` with calls to the `DeviceStore`/`ProfileStore`.
   - Provide reload mechanisms that iterate over store keys.
   - Update constructors/tests to accept storage interfaces (facilitates mocking).

5. **Refactor usage tracking**
   - Update `internal/usage/tracker.go` and `reset.go` to persist sessions/daily aggregates through `UsageStore`.
   - Replace SQL aggregation logic with prefix scans (e.g., iterate `usage/sessions/<deviceID>/`).
   - Ensure concurrency-safe updates (use Bolt transactions).

6. **Refactor logging**
   - Update DNS logging (`internal/dns/server.go`) and HTTP logging (`internal/proxy/server.go`) to insert JSON blobs into `LogStore`.
   - Rework query APIs (admin/log streaming) to use index buckets instead of SQL `SELECT`.
   - Update cleanup routines to call `LogStore.DeleteBefore(prefix, cutoff)` rather than SQL `DELETE`.

7. **Remove SQL-only assets**
   - Delete `scripts/sample-data.sql`, `scripts/load-sample-data.sh`, and any migration helpers.
   - Update docs/README/Makefile targets referencing SQLite.

8. **Config & code cleanup**
   - Rename env vars to `KPROXY_STORAGE_PATH`, `KPROXY_STORAGE_TYPE`.
   - Update `configs/*.yaml`, `config.yaml`, `specs/` docs accordingly (spec already updated).
   - Remove `modernc.org/sqlite` from `go.mod`, add `go.etcd.io/bbolt` (or chosen backend).

9. **Testing**
   - Unit-test storage interfaces with Bolt backend (including concurrency and TTL cleanup).
   - Adapt existing policy/usage/log tests to use an in-memory Bolt file (temp dir) instead of SQLite.
   - Run integration tests to confirm basic flows (DNS logging, proxy logging, usage limits) still work.

10. **Follow-ups (optional)**
    - Provide a stub `NoopLogStore` for stateless/demo mode.
    - Document how to add alternative storage implementations (e.g., Postgres) via build tags or plugins.

## Rollout Strategy

- Land the storage package + Bolt backend first behind feature branches.
- Introduce adapters into each subsystem incrementally (policy → usage → logging) to keep diffs manageable.
- After all components depend on storage interfaces, remove the SQLite code and CGO dependency.
- Update CI/build scripts and ensure `go test ./...` succeeds without CGO/toolchain tweaks.
