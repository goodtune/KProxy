package storage

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a record is missing from storage.
var ErrNotFound = errors.New("storage: record not found")

// Store represents the root storage interface.
// Refactored to fact-based OPA: removed devices, profiles, rules, time_rules, usage_limits, bypass_rules
// Configuration now lives in OPA policies, not database
type Store interface {
	Close() error
	Usage() UsageStore
	Logs() LogStore
	AdminUsers() AdminUserStore
	DHCPLeases() DHCPLeaseStore
}

// REMOVED: DeviceStore, ProfileStore, RuleStore, TimeRuleStore, UsageLimitStore, BypassRuleStore
// Configuration is now managed in OPA policies (policies/config.rego)
// Not in database anymore

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

// LogStore manages request and DNS logs.
type LogStore interface {
	AddRequestLog(ctx context.Context, log RequestLog) error
	AddDNSLog(ctx context.Context, log DNSLog) error
	QueryRequestLogs(ctx context.Context, filter RequestLogFilter) ([]RequestLog, error)
	QueryDNSLogs(ctx context.Context, filter DNSLogFilter) ([]DNSLog, error)
	DeleteRequestLogsBefore(ctx context.Context, cutoff time.Time) (int, error)
	DeleteDNSLogsBefore(ctx context.Context, cutoff time.Time) (int, error)
}

// RequestLogFilter defines criteria for querying request logs.
type RequestLogFilter struct {
	DeviceID  string
	Domain    string
	Action    Action
	StartTime *time.Time
	EndTime   *time.Time
	Limit     int
	Offset    int
}

// DNSLogFilter defines criteria for querying DNS logs.
type DNSLogFilter struct {
	DeviceID  string
	Domain    string
	Action    string // "intercept", "bypass", "block"
	StartTime *time.Time
	EndTime   *time.Time
	Limit     int
	Offset    int
}

// AdminUserStore manages admin user accounts.
type AdminUserStore interface {
	Get(ctx context.Context, username string) (*AdminUser, error)
	List(ctx context.Context) ([]AdminUser, error)
	Upsert(ctx context.Context, user AdminUser) error
	Delete(ctx context.Context, username string) error
	UpdateLastLogin(ctx context.Context, username string, loginTime time.Time) error
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
