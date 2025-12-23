# KProxy Admin Interface Implementation Plan (Phase 5)

## Overview
Implement a comprehensive web-based admin interface to provide visibility and control over the KProxy system.

## Technology Stack

### Backend
- **HTTP Router**: `gorilla/mux` (lightweight, mature)
- **Session Management**: `gorilla/sessions` + JWT tokens
- **Authentication**: `golang.org/x/crypto/bcrypt` for password hashing
- **Database**: Existing SQLite through `internal/database`

### Frontend
- **UI Framework**: **htmx** (server-side rendering, minimal JS)
- **CSS Framework**: **Tailwind CSS** (via CDN)
- **Charts**: **Chart.js** (usage statistics visualization)
- **Icons**: **Heroicons**
- **Date/Time**: **Flatpickr**

**Rationale**: htmx chosen for simplicity, no build pipeline required, server-side rendering aligns with Go strengths.

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

## Database Schema Extension

New migration for admin users:

```sql
CREATE TABLE IF NOT EXISTS admin_users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login DATETIME
);

CREATE INDEX idx_admin_users_username ON admin_users(username);
```

## Implementation Phases

### Phase 5.1: Foundation
1. Add dependencies (gorilla/mux, gorilla/sessions, JWT, bcrypt)
2. Create `internal/admin` package structure
3. Add admin_users table migration
4. Implement authentication (password hashing, JWT, sessions)
5. Implement middleware (auth, logging, rate limiting)
6. Create basic HTTP server

### Phase 5.2: Authentication & UI Shell
7. Implement login/logout handlers
8. Create initial admin user from config
9. Build HTML templates (layout, login, dashboard shell)
10. Implement web handlers for basic pages
11. Set up static asset serving
12. Test authentication flow

### Phase 5.3: Device Management
13. Implement device API handlers (CRUD)
14. Implement device web handlers
15. Create device management UI
16. Test device operations

### Phase 5.4: Profile Management
17. Implement profile API handlers
18. Implement profile web handlers
19. Create profile UI (tabbed interface)
20. Test profile management

### Phase 5.5: Rules Management
21. Implement rules API (regular, time, usage, bypass)
22. Create rules UI with priority ordering
23. Implement policy reload after changes
24. Test all rule types

### Phase 5.6: Logs & Monitoring
25. Implement log API with filters and pagination
26. Create log viewer UI
27. Add real-time updates
28. Test log viewing

### Phase 5.7: Usage & Sessions
29. Implement sessions API
30. Implement statistics API
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
39. Implement password change
40. Add configuration viewer

### Phase 5.10: Integration & Testing
41. Integrate admin server into main.go
42. Update config.example.yaml
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

### Database
- Use `*database.DB` from main
- Reuse migration pattern

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

- `internal/database/db.go` - Add admin migration
- `internal/policy/engine.go` - Reload() integration
- `cmd/kproxy/main.go` - Initialize admin server
- `internal/config/config.go` - AdminConfig extensions
- `internal/metrics/metrics.go` - Server pattern reference
