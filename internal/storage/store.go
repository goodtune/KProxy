package storage

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned when a record is missing from storage.
var ErrNotFound = errors.New("storage: record not found")

// Store represents the root storage interface.
type Store interface {
	Close() error
	Devices() DeviceStore
	Profiles() ProfileStore
	Rules() RuleStore
	TimeRules() TimeRuleStore
	UsageLimits() UsageLimitStore
	BypassRules() BypassRuleStore
	Usage() UsageStore
	Logs() LogStore
	AdminUsers() AdminUserStore
}

// DeviceStore manages device persistence.
type DeviceStore interface {
	Get(ctx context.Context, id string) (*Device, error)
	List(ctx context.Context) ([]Device, error)
	ListActive(ctx context.Context) ([]Device, error)
	Upsert(ctx context.Context, device Device) error
	Delete(ctx context.Context, id string) error
}

// ProfileStore manages profiles.
type ProfileStore interface {
	Get(ctx context.Context, id string) (*Profile, error)
	List(ctx context.Context) ([]Profile, error)
	Upsert(ctx context.Context, profile Profile) error
	Delete(ctx context.Context, id string) error
}

// RuleStore manages domain rules.
type RuleStore interface {
	Get(ctx context.Context, profileID, id string) (*Rule, error)
	ListByProfile(ctx context.Context, profileID string) ([]Rule, error)
	Upsert(ctx context.Context, rule Rule) error
	Delete(ctx context.Context, profileID, id string) error
}

// TimeRuleStore manages time-based rules.
type TimeRuleStore interface {
	Get(ctx context.Context, profileID, id string) (*TimeRule, error)
	ListByProfile(ctx context.Context, profileID string) ([]TimeRule, error)
	Upsert(ctx context.Context, rule TimeRule) error
	Delete(ctx context.Context, profileID, id string) error
}

// UsageLimitStore manages usage limits.
type UsageLimitStore interface {
	Get(ctx context.Context, profileID, id string) (*UsageLimit, error)
	ListByProfile(ctx context.Context, profileID string) ([]UsageLimit, error)
	Upsert(ctx context.Context, limit UsageLimit) error
	Delete(ctx context.Context, profileID, id string) error
}

// BypassRuleStore manages bypass rules.
type BypassRuleStore interface {
	Get(ctx context.Context, id string) (*BypassRule, error)
	List(ctx context.Context) ([]BypassRule, error)
	ListEnabled(ctx context.Context) ([]BypassRule, error)
	Upsert(ctx context.Context, rule BypassRule) error
	Delete(ctx context.Context, id string) error
}

// UsageStore manages usage tracking data.
type UsageStore interface {
	UpsertSession(ctx context.Context, session UsageSession) error
	DeleteSession(ctx context.Context, id string) error
	GetSession(ctx context.Context, id string) (*UsageSession, error)
	GetDailyUsage(ctx context.Context, date string, deviceID, limitID string) (*DailyUsage, error)
	IncrementDailyUsage(ctx context.Context, date string, deviceID, limitID string, seconds int64) error
	DeleteDailyUsageBefore(ctx context.Context, cutoffDate string) (int, error)
	DeleteInactiveSessionsBefore(ctx context.Context, cutoff time.Time) (int, error)
}

// LogStore manages request and DNS logs.
type LogStore interface {
	AddRequestLog(ctx context.Context, log RequestLog) error
	AddDNSLog(ctx context.Context, log DNSLog) error
	DeleteRequestLogsBefore(ctx context.Context, cutoff time.Time) (int, error)
	DeleteDNSLogsBefore(ctx context.Context, cutoff time.Time) (int, error)
}

// AdminUserStore manages admin user accounts.
type AdminUserStore interface {
	Get(ctx context.Context, username string) (*AdminUser, error)
	List(ctx context.Context) ([]AdminUser, error)
	Upsert(ctx context.Context, user AdminUser) error
	Delete(ctx context.Context, username string) error
	UpdateLastLogin(ctx context.Context, username string, loginTime time.Time) error
}
