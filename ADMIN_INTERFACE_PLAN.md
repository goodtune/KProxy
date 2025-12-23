# KProxy Admin Interface Implementation Plan (Phase 5)

## Overview
Implement a comprehensive web-based admin interface to provide visibility and control over the KProxy system.

## Technology Stack

### Backend
- **HTTP Router**: `gorilla/mux` (lightweight, mature)
- **Session Management**: `gorilla/sessions` + JWT tokens
- **Authentication**: `golang.org/x/crypto/bcrypt` for password hashing
- **Storage**: BoltDB through `internal/storage` interfaces (pure Go, no CGO required)

### Frontend
- **UI Framework**: **htmx** (server-side rendering, minimal JS)
- **CSS Framework**: **Tailwind CSS** (via CDN)
- **Charts**: **Chart.js** (usage statistics visualization)
- **Icons**: **Heroicons**
- **Date/Time**: **Flatpickr**

**Rationale**: htmx chosen for simplicity, no build pipeline required, server-side rendering aligns with Go strengths.

## Plan Completeness Review
- **Scope coverage**: The plan thoroughly enumerates backend APIs, storage interfaces, UI flows, observability, and documentation, so no entire domain of work appears missing.
- **Detail gaps**: Rollout and migration steps (e.g., how to seed the new `admin_users` bucket in existing deployments, or how to back up/recover BoltDB changes) are not described, and automated/regression testing is only named in Phase 5.10 without outlining concrete scenarios.
- **Implementation status**: Phase 5.1–5.2 code exists (`internal/admin`, `internal/storage`, `cmd/kproxy/main.go`), but the listed dependency on `gorilla/sessions` never landed—either adopt it or update the stack assumptions. Later API/UI phases remain unstarted.

## Project Structure

```
/home/user/KProxy/
├── internal/
│   ├── admin/              # NEW - Admin interface package
│   │   ├── server.go       # HTTP server setup
│   │   ├── auth.go         # Authentication & session management
│   │   ├── middleware.go   # Auth middleware, logging, rate limiting
│   │   ├── handlers.go     # Route handlers registry
│   │   ├── api/            # API handlers by domain
│   │   │   ├── devices.go
│   │   │   ├── profiles.go
│   │   │   ├── rules.go
│   │   │   ├── time_rules.go
│   │   │   ├── usage_limits.go
│   │   │   ├── bypass_rules.go
│   │   │   ├── logs.go
│   │   │   ├── sessions.go
│   │   │   ├── stats.go
│   │   │   └── system.go
│   │   ├── web/            # Web UI handlers (htmx endpoints)
│   │   │   ├── dashboard.go
│   │   │   ├── devices.go
│   │   │   ├── profiles.go
│   │   │   ├── rules.go
│   │   │   ├── logs.go
│   │   │   └── sessions.go
│   │   ├── static/         # Embedded static files
│   │   │   ├── css/
│   │   │   │   └── admin.css
│   │   │   ├── js/
│   │   │   │   └── admin.js
│   │   │   └── templates/
│   │   │       ├── layout.html
│   │   │       ├── login.html
│   │   │       ├── dashboard.html
│   │   │       ├── devices.html
│   │   │       ├── profiles.html
│   │   │       ├── rules.html
│   │   │       ├── logs.html
│   │   │       └── components/
│   │   └── models.go
│   └── [existing packages...]
└── cmd/kproxy/
    └── main.go             # MODIFY - Initialize admin server
```

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/me` - Current user
- `POST /api/auth/change-password` - Change password

### Device Management
- `GET /api/devices` - List devices
- `GET /api/devices/:id` - Get device
- `POST /api/devices` - Create device
- `PUT /api/devices/:id` - Update device
- `DELETE /api/devices/:id` - Delete device
- `GET /api/devices/:id/status` - Device status

### Profile Management
- `GET /api/profiles` - List profiles
- `GET /api/profiles/:id` - Get profile with rules
- `POST /api/profiles` - Create profile
- `PUT /api/profiles/:id` - Update profile
- `DELETE /api/profiles/:id` - Delete profile

### Rules Management
- `GET /api/profiles/:id/rules` - List rules
- `POST /api/profiles/:id/rules` - Create rule
- `PUT /api/rules/:id` - Update rule
- `DELETE /api/rules/:id` - Delete rule
- `POST /api/rules/:id/reorder` - Change priority
- Time rules, usage limits, bypass rules follow similar pattern

### Logs & Monitoring
- `GET /api/logs/requests` - Request logs with filters
- `GET /api/logs/dns` - DNS logs with filters
- `DELETE /api/logs/requests` - Clear old logs
- `DELETE /api/logs/dns` - Clear old DNS logs

### Usage & Sessions
- `GET /api/sessions/active` - Active sessions
- `DELETE /api/sessions/:id` - Terminate session
- `GET /api/usage/daily` - Daily usage stats
- `GET /api/usage/summary` - Usage summary

### Statistics & Dashboard
- `GET /api/stats/dashboard` - Dashboard stats
- `GET /api/stats/devices` - Per-device stats
- `GET /api/stats/top-domains` - Most accessed domains
- `GET /api/stats/blocked` - Blocked requests stats
- `GET /api/stats/timeline` - Request timeline

### System Control
- `POST /api/system/reload` - Reload policy engine
- `GET /api/system/health` - Health check
- `GET /api/system/metrics` - Prometheus metrics
- `GET /api/system/config` - Current config (safe subset)

### Web UI Endpoints
- `GET /` - Redirect to dashboard
- `GET /admin/login` - Login page
- `GET /admin/dashboard` - Dashboard
- `GET /admin/devices` - Devices management
- `GET /admin/profiles` - Profiles management
- `GET /admin/logs` - Logs viewer
- `GET /admin/sessions` - Sessions viewer
- Various htmx partial endpoints for dynamic updates

## Storage Schema Extension

New BoltDB bucket for admin users:

**Bucket**: `admin_users`
**Key Format**: `username` (string)
**Value Format**: JSON blob

```go
type AdminUser struct {
    ID           string    `json:"id"`
    Username     string    `json:"username"`
    PasswordHash string    `json:"password_hash"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
    LastLogin    *time.Time `json:"last_login,omitempty"`
}
```

This will be stored in the BoltDB database alongside existing buckets (devices, profiles, rules, etc.).

## BoltDB Storage Architecture

KProxy now uses BoltDB (bbolt) instead of SQLite, providing:
- **Pure Go**: No CGO required, easier cross-compilation
- **Embedded**: Single file database, no external dependencies
- **Interface-based**: Clean abstraction through `storage.Store` interface

### Existing Storage Structure

```
internal/storage/
├── store.go              # Root Store interface and sub-interfaces
├── types.go              # Data types (Device, Profile, Rule, etc.)
├── util.go               # Helper functions
└── bolt/
    ├── bolt.go           # BoltDB Store implementation
    ├── device_store.go   # DeviceStore implementation
    ├── profile_store.go  # ProfileStore implementation
    ├── rule_store.go     # RuleStore implementation
    ├── time_rule_store.go
    ├── usage_limit_store.go
    ├── bypass_rule_store.go
    ├── usage_store.go    # UsageStore for sessions/daily usage
    ├── log_store.go      # LogStore for HTTP/DNS logs
    └── bolt_test.go
```

### Admin Interface Storage Integration

We will extend the storage interfaces to include admin user management:

1. **Add to `internal/storage/store.go`**:
   - Add `AdminUsers() AdminUserStore` method to `Store` interface
   - Define `AdminUserStore` interface with Get/List/Upsert/Delete methods

2. **Add to `internal/storage/types.go`**:
   - Define `AdminUser` struct

3. **Create `internal/storage/bolt/admin_user_store.go`**:
   - Implement AdminUserStore interface
   - Use `admin_users` bucket
   - Key: username, Value: JSON-encoded AdminUser

This follows the existing pattern used for devices, profiles, and rules.

### Required Storage Interface Extensions

The current `LogStore` interface only supports adding and deleting logs:

```go
type LogStore interface {
    AddRequestLog(ctx context.Context, log RequestLog) error
    AddDNSLog(ctx context.Context, log DNSLog) error
    DeleteRequestLogsBefore(ctx context.Context, cutoff time.Time) (int, error)
    DeleteDNSLogsBefore(ctx context.Context, cutoff time.Time) (int, error)
}
```

For the admin interface, we'll need to extend this with query methods:

```go
type LogStore interface {
    // ... existing methods ...

    // Query methods for admin interface
    QueryRequestLogs(ctx context.Context, filter RequestLogFilter) ([]RequestLog, error)
    QueryDNSLogs(ctx context.Context, filter DNSLogFilter) ([]DNSLog, error)
}

type RequestLogFilter struct {
    DeviceID   string
    Domain     string
    Action     Action
    StartTime  *time.Time
    EndTime    *time.Time
    Limit      int
    Offset     int
}

type DNSLogFilter struct {
    DeviceID   string
    Domain     string
    Action     string
    StartTime  *time.Time
    EndTime    *time.Time
    Limit      int
    Offset     int
}
```

These query methods will use BoltDB's index buckets for efficient filtering.

## Implementation Phases

### Phase 5.1: Foundation
1. Add dependencies (gorilla/mux, gorilla/sessions, JWT, bcrypt) — pending `gorilla/sessions` import in `go.mod`
2. [x] Create `internal/admin` package structure (`internal/admin/*.go`, static assets)
3. [x] Add AdminUserStore interface and BoltDB implementation (`internal/storage/store.go`, `internal/storage/bolt/admin_user_store.go`)
4. [x] Implement authentication (password hashing, JWT, sessions) (`internal/admin/auth.go`)
5. [x] Implement middleware (auth, logging, rate limiting) (`internal/admin/middleware.go`)
6. [x] Create basic HTTP server (`internal/admin/server.go`)

### Phase 5.2: Authentication & UI Shell
7. [x] Implement login/logout handlers (`internal/admin/handlers.go`)
8. [x] Create initial admin user from config (`internal/admin/init.go`, `cmd/kproxy/main.go`)
9. [x] Build HTML templates (layout, login, dashboard shell) (`internal/admin/static/templates/*.html`)
10. [x] Implement web handlers for basic pages (`internal/admin/server.go`)
11. [x] Set up static asset serving (`internal/admin/server.go`, `internal/admin/static`)
12. Test authentication flow — pending automated/manual verification evidence

### Phase 5.3: Device Management
13. Implement device API handlers using `store.Devices()` (CRUD)
14. Implement device web handlers
15. Create device management UI
16. Test device operations

### Phase 5.4: Profile Management
17. Implement profile API handlers using `store.Profiles()`
18. Implement profile web handlers
19. Create profile UI (tabbed interface)
20. Test profile management

### Phase 5.5: Rules Management
21. Implement rules API using `store.Rules()`, `store.TimeRules()`, `store.UsageLimits()`, `store.BypassRules()`
22. Create rules UI with priority ordering
23. Implement policy reload after changes
24. Test all rule types

### Phase 5.6: Logs & Monitoring
25. Implement log API with filters using `store.Logs()` (extend with query methods)
26. Create log viewer UI
27. Add real-time updates
28. Test log viewing

### Phase 5.7: Usage & Sessions
29. Implement sessions API using `store.Usage()`
30. Implement statistics API (aggregate data from storage)
31. Create session management UI
32. Create usage statistics views

### Phase 5.8: Dashboard & Statistics
33. Implement dashboard statistics
34. Build dashboard UI with charts
35. Add auto-refresh
36. Test dashboard accuracy

### Phase 5.9: System Control
37. Implement system control endpoints
38. Add settings page
39. [x] Implement password change (`internal/admin/handlers.go`, `/api/auth/change-password`)
40. Add configuration viewer

### Phase 5.10: Integration & Testing
41. [x] Integrate admin server into main.go (`cmd/kproxy/main.go`)
42. [x] Update config.example.yaml (`configs/config.example.yaml`)
43. Comprehensive testing
44. Add Prometheus metrics for admin

### Phase 5.11: Polish & Security
45. Security hardening (CSRF, XSS, rate limiting)
46. UI/UX improvements (loading states, notifications)
47. Add confirmation dialogs
48. Performance optimization

### Phase 5.12: Documentation
49. Create user guide
50. Update README.md
51. Update CLAUDE.md

## Integration Points

### Storage
- Use `storage.Store` interface from main
- Add admin user store to storage interfaces
- Access via `store.AdminUsers()` method

### Policy Engine
```go
// After policy changes
if err := policyEngine.Reload(); err != nil {
    logger.Error().Err(err).Msg("Failed to reload policy")
    return err
}
```

### Usage Tracker
- Read active sessions
- Terminate sessions via `tracker.StopSession()`
- Query daily_usage table

### Logging
```go
logger := logger.With().Str("component", "admin").Logger()
```

### Metrics
- Add admin-specific metrics
- Proxy to existing metrics server

## Security Considerations

### Authentication
- Bcrypt (cost 12) for passwords
- HTTP-only, Secure, SameSite cookies
- JWT tokens (24h expiration)
- Session invalidation on logout

### Authorization
- All admin endpoints require auth
- Single admin role (multi-role future)

### Input Validation
- Server-side validation
- Parameterized queries
- Template auto-escaping

### Rate Limiting
- 100 req/min per session
- 5 req/min for login

### HTTPS
- Admin over HTTPS recommended
- HSTS header

### CSRF Protection
- CSRF tokens
- SameSite cookies
- Origin validation

## Future Enhancements

1. Multi-user & RBAC
2. API keys for automation
3. Audit log
4. Bulk import/export (CSV, JSON)
5. Advanced analytics
6. Email/webhook notifications
7. Mobile app
8. Dark mode
9. Backup/restore
10. Configuration templates

## Critical Files

- `internal/storage/store.go` - Add AdminUserStore interface
- `internal/storage/bolt/bolt.go` - Add admin user bucket and implementation
- `internal/policy/engine.go` - Reload() integration
- `cmd/kproxy/main.go` - Initialize admin server
- `internal/config/config.go` - AdminConfig extensions (already exists)
- `internal/metrics/metrics.go` - Server pattern reference
