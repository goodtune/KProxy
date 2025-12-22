package usage

import (
	"time"
)

// Session represents an active usage tracking session
type Session struct {
	ID                 string
	DeviceID           string
	LimitID            string
	StartedAt          time.Time
	LastActivity       time.Time
	AccumulatedSeconds int64
	Active             bool
}

// DailyUsage represents aggregated daily usage
type DailyUsage struct {
	Date         time.Time
	DeviceID     string
	LimitID      string
	TotalSeconds int64
}

// UsageStats represents current usage statistics
type UsageStats struct {
	TodayUsage     time.Duration
	RemainingToday time.Duration
	LimitExceeded  bool
	ActiveSession  *Session
}
