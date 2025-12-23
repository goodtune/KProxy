package storage

import "time"

// Action represents an action stored in rules/logs.
type Action string

const (
	ActionAllow  Action = "ALLOW"
	ActionBlock  Action = "BLOCK"
	ActionBypass Action = "BYPASS"
)

// Device represents a monitored device.
type Device struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Identifiers []string  `json:"identifiers"`
	ProfileID   string    `json:"profile_id"`
	Active      bool      `json:"active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Profile contains access rules for a device or group.
type Profile struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	DefaultAllow bool      `json:"default_allow"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// Rule defines domain/path filtering.
type Rule struct {
	ID          string   `json:"id"`
	ProfileID   string   `json:"profile_id"`
	Domain      string   `json:"domain"`
	Paths       []string `json:"paths"`
	Action      Action   `json:"action"`
	Priority    int      `json:"priority"`
	Category    string   `json:"category"`
	InjectTimer bool     `json:"inject_timer"`
}

// TimeRule restricts access by time of day.
type TimeRule struct {
	ID         string   `json:"id"`
	ProfileID  string   `json:"profile_id"`
	DaysOfWeek []int    `json:"days_of_week"`
	StartTime  string   `json:"start_time"`
	EndTime    string   `json:"end_time"`
	RuleIDs    []string `json:"rule_ids"`
}

// UsageLimit tracks time spent on specific categories/domains.
type UsageLimit struct {
	ID           string   `json:"id"`
	ProfileID    string   `json:"profile_id"`
	Category     string   `json:"category"`
	Domains      []string `json:"domains"`
	DailyMinutes int      `json:"daily_minutes"`
	ResetTime    string   `json:"reset_time"`
	InjectTimer  bool     `json:"inject_timer"`
}

// BypassRule defines domains that should bypass the proxy.
type BypassRule struct {
	ID        string    `json:"id"`
	Domain    string    `json:"domain"`
	Reason    string    `json:"reason"`
	Enabled   bool      `json:"enabled"`
	DeviceIDs []string  `json:"device_ids"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UsageSession represents a tracked usage session.
type UsageSession struct {
	ID                 string    `json:"id"`
	DeviceID           string    `json:"device_id"`
	LimitID            string    `json:"limit_id"`
	StartedAt          time.Time `json:"started_at"`
	LastActivity       time.Time `json:"last_activity"`
	AccumulatedSeconds int64     `json:"accumulated_seconds"`
	Active             bool      `json:"active"`
}

// DailyUsage aggregates usage per day/device/limit.
type DailyUsage struct {
	Date         string `json:"date"`
	DeviceID     string `json:"device_id"`
	LimitID      string `json:"limit_id"`
	TotalSeconds int64  `json:"total_seconds"`
}

// RequestLog represents an HTTP request log entry.
type RequestLog struct {
	ID           string    `json:"id"`
	Timestamp    time.Time `json:"timestamp"`
	DeviceID     string    `json:"device_id"`
	DeviceName   string    `json:"device_name"`
	ClientIP     string    `json:"client_ip"`
	Method       string    `json:"method"`
	Host         string    `json:"host"`
	Path         string    `json:"path"`
	UserAgent    string    `json:"user_agent"`
	StatusCode   int       `json:"status_code"`
	ResponseSize int64     `json:"response_size"`
	DurationMS   int64     `json:"duration_ms"`
	Action       Action    `json:"action"`
	MatchedRule  string    `json:"matched_rule_id"`
	Reason       string    `json:"reason"`
	Category     string    `json:"category"`
	Encrypted    bool      `json:"encrypted"`
}

// DNSLog represents a DNS query log entry.
type DNSLog struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	ClientIP   string    `json:"client_ip"`
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name"`
	Domain     string    `json:"domain"`
	QueryType  string    `json:"query_type"`
	Action     string    `json:"action"`
	ResponseIP string    `json:"response_ip"`
	Upstream   string    `json:"upstream"`
	LatencyMS  int64     `json:"latency_ms"`
}
