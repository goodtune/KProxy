package storage

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a record is missing from storage.
var ErrNotFound = errors.New("storage: record not found")

// Store represents the root storage interface.
// Simplified storage: only operational data (usage tracking, DHCP leases)
// Removed: admin UI (admin_users), logs (request_logs, dns_logs)
// Configuration lives in OPA policies, not database
type Store interface {
	Close() error
	Usage() UsageStore
	DHCPLeases() DHCPLeaseStore
}

// REMOVED: DeviceStore, ProfileStore, RuleStore, TimeRuleStore, UsageLimitStore, BypassRuleStore
// Configuration is now managed in OPA policies (policies/config.rego)
// REMOVED: LogStore - logs now written to structured loggers (zerolog)
// REMOVED: AdminUserStore - admin UI removed, use metrics + Prometheus for monitoring

// UsageStore manages usage tracking data.
type UsageStore interface {
	UpsertSession(ctx context.Context, session UsageSession) error
	DeleteSession(ctx context.Context, id string) error
	GetSession(ctx context.Context, id string) (*UsageSession, error)
	ListActiveSessions(ctx context.Context) ([]UsageSession, error)
	GetDailyUsage(ctx context.Context, date string, deviceID, limitID string) (*DailyUsage, error)
	ListDailyUsage(ctx context.Context, date string) ([]DailyUsage, error)
	IncrementDailyUsage(ctx context.Context, date string, deviceID, limitID string, seconds int64) error
	DeleteDailyUsageBefore(ctx context.Context, cutoffDate string) (int, error)
	DeleteInactiveSessionsBefore(ctx context.Context, cutoff time.Time) (int, error)
}

// DHCPLeaseStore manages DHCP IP address leases.
type DHCPLeaseStore interface {
	Get(ctx context.Context, mac string) (*DHCPLease, error)
	GetByMAC(ctx context.Context, mac string) (*DHCPLease, error)
	GetByIP(ctx context.Context, ip string) (*DHCPLease, error)
	List(ctx context.Context) ([]DHCPLease, error)
	Create(ctx context.Context, lease *DHCPLease) error
	Delete(ctx context.Context, mac string) error
	DeleteExpired(ctx context.Context) (int, error)
}
